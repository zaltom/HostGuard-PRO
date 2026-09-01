package HGGeo;
###############################################################################
# HostGuard Pro - Country Code Filtering
# /usr/local/hostguard/lib/HGGeo.pm
#
# Allows or denies traffic by the country an address is registered to.
#
# Country ranges are published as plain CIDR zone files, one per ISO 3166-1
# alpha-2 code. HostGuard Pro downloads the codes it has been asked about,
# caches them under the data directory and hands them to the firewall as
# ipsets, exactly as external block lists are handled.
#
# Two modes, and they are mutually exclusive by design:
#
#   GEO_DENY   - traffic from these countries is dropped
#   GEO_ALLOW  - traffic is dropped unless it comes from these countries
#
# GEO_ALLOW is a very sharp instrument. It drops everything the zone files do
# not account for, which includes addresses that have been reassigned since
# the files were published and every address the publisher does not cover. The
# allowlist still wins over both modes, so an administrator's own address
# survives a mistake here, and the firewall refuses to apply an allow mode
# whose zone files came back empty rather than locking the host away.
###############################################################################
use strict;
use warnings;
use HGConfig;
use HGLogger;

# Where zone files are fetched from. The {CC} placeholder is replaced with the
# lower-case country code.
#
# The default publisher serves IPv4 and IPv6 from parallel paths. A site with
# its own mirror can point GEO_SOURCE and GEO_SOURCE6 elsewhere.
our $DEFAULT_SOURCE  = 'https://www.ipdeny.com/ipblocks/data/aggregated/{CC}-aggregated.zone';
our $DEFAULT_SOURCE6 = 'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{CC}-aggregated.zone';

# Refresh no more often than this. Country allocations move slowly, and the
# publishers rebuild once a day at most.
our $MIN_INTERVAL = 86400;

# How far a country's range count may fall against the copy it replaces, as a
# percentage, before the download is treated as truncated rather than smaller.
# Overridden by GEO_MAX_SHRINK_PERCENT.
#
# This check was missing, and its absence was the most serious thing in this
# module. The only acceptance test was "did anything parse", which is the wrong
# question, and HGBlocklist says so at length in the comment on its own
# _reject_reason - a transfer cut short by a proxy or a provider mid-outage
# arrives complete as far as the downloader can tell, and the fragment that did
# arrive parses perfectly well.
#
# What that cost here is worse than it is for a block list, because of what
# allow mode does with the result. GEO_ALLOW builds a chain that RETURNs for an
# address in a permitted country and drops everything else, so a country whose
# ranges fall from forty thousand to two thousand does not stop being
# protected - it stops being reachable. And _apply_geo_rules only refuses when
# nothing at all loaded, while refresh_geo_set only refuses when the fill
# returns zero, so two thousand ranges passed both and was swapped into the
# live set without a reload. A provider having a bad afternoon took the host
# off the air, and the log said "updated: 2000 ranges".
#
# In deny mode the same fragment inverts the failure: the country largely stops
# being blocked, silently.
our $MAX_SHRINK_PERCENT = 60;

# Below this many ranges the percentage says little: a country with a handful
# of allocations can legitimately halve.
our $SHRINK_FLOOR = 100;

sub cache_dir { return "$HGConfig::DATA_DIR/geo"; }

sub cache_file {
    my ($class, $cc, $family) = @_;
    $family //= 'inet';
    my $suffix = $family eq 'inet6' ? '.v6' : '.v4';
    return cache_dir() . '/' . lc($cc) . $suffix . '.zone';
}

###############################################################################
# Configuration
###############################################################################

# The active mode and the country codes it applies to.
#
# Returns (mode, @codes) where mode is 'deny', 'allow' or '' when country
# filtering is off. Configuring both lists is a contradiction rather than a
# combination, so deny wins and the conflict is reported.
sub mode {
    my ($class, $config) = @_;

    return ('') unless ($config->{GEO_ENABLE} // '0') eq '1';

    my @deny  = _codes($config->{GEO_DENY});
    my @allow = _codes($config->{GEO_ALLOW});

    if (@deny && @allow) {
        HGLogger->error("GEO_DENY and GEO_ALLOW are both set; applying GEO_DENY "
                      . "and ignoring GEO_ALLOW");
        return ('deny', @deny);
    }
    return ('deny',  @deny)  if @deny;
    return ('allow', @allow) if @allow;
    return ('');
}

# Parse a comma separated list of country codes.
#
# Anything that is not two letters is refused: a code becomes part of an ipset
# name and a file path, so only the exact shape is accepted.
sub _codes {
    my ($value) = @_;
    return () unless defined $value && length $value;

    my (@codes, %seen);
    for my $cc (split(/[,\s]+/, $value)) {
        next unless length $cc;
        unless ($cc =~ /^[A-Za-z]{2}$/) {
            HGLogger->error("Ignoring invalid country code: $cc");
            next;
        }
        my $up = uc($cc);
        next if $seen{$up}++;
        push @codes, $up;
    }

    return @codes;
}

###############################################################################
# Zone files
###############################################################################

sub age {
    my ($class, $cc, $family) = @_;
    my @st = stat($class->cache_file($cc, $family));
    return undef unless @st;
    return time() - $st[9];
}

sub is_due {
    my ($class, $cc, $config, $family) = @_;

    my $interval = $config->{GEO_INTERVAL} // $MIN_INTERVAL;
    $interval = $MIN_INTERVAL unless $interval =~ /^\d+$/ && $interval >= $MIN_INTERVAL;

    my $age = $class->age($cc, $family);
    return 1 unless defined $age;
    return $age >= $interval ? 1 : 0;
}

# Ranges in the cached copy of a country, or undef if there is no copy.
#
# The cache holds one validated range per line, so counting lines is counting
# ranges.
sub cached_count {
    my ($class, $cc, $family) = @_;

    my $file = $class->cache_file($cc, $family);
    open(my $fh, '<', $file) or return undef;
    my $count = 0;
    while (my $line = <$fh>) {
        $count++ if $line =~ /\S/;
    }
    close($fh);
    return $count;
}

# A percentage setting, bounded to 0-100, falling back to the default when it
# is missing or not a number.
sub _percent {
    my ($config, $key, $default) = @_;
    my $value = $config ? $config->{$key} : undef;
    return $default unless defined $value && $value =~ /^\d+$/ && $value <= 100;
    return $value;
}

# Decide whether a freshly parsed zone file may replace the cached copy.
#
# Returns undef to accept it, or the reason to refuse. The shape follows
# HGBlocklist::_reject_reason deliberately rather than being invented again:
# the structural test has no override, and the heuristic one does.
sub _reject_reason {
    my ($class, $cc, $family, $ranges, $config, $force) = @_;

    return "it contained no usable ranges" unless @$ranges;

    my $shrink = _percent($config, 'GEO_MAX_SHRINK_PERCENT', $MAX_SHRINK_PERCENT);
    return undef if $force || $shrink <= 0 || $shrink >= 100;

    my $previous = $class->cached_count($cc, $family);
    return undef unless defined $previous && $previous >= $SHRINK_FLOOR;

    my $floor = int($previous * (100 - $shrink) / 100);
    my $kept  = scalar(@$ranges);
    return undef if $kept >= $floor;

    return "it fell from $previous ranges to $kept, a drop of more than "
         . "${shrink}% (GEO_MAX_SHRINK_PERCENT), which is what a truncated "
         . "download looks like; run \"hostguard -c force\" to accept it";
}

# Fetch one country's zone file for one family.
#
# The download is parsed before it replaces the cached copy, and then checked
# against the copy it would replace, so neither an error page nor a truncated
# transfer can empty a country. See _reject_reason.
sub refresh {
    my ($class, $cc, $config, %opt) = @_;

    my $family = $opt{family} // 'inet';
    return 0 unless $opt{force} || $class->is_due($cc, $config, $family);

    my $dir = cache_dir();
    unless (-d $dir) {
        mkdir($dir, 0700) or do {
            HGLogger->error("Cannot create $dir: $!");
            return 0;
        };
    }

    my $template = $family eq 'inet6'
                 ? ($config->{GEO_SOURCE6} || $DEFAULT_SOURCE6)
                 : ($config->{GEO_SOURCE}  || $DEFAULT_SOURCE);

    unless ($template =~ m{^https?://[^\s[:cntrl:]]+$}i) {
        HGLogger->error("Country zone source is not a usable URL: $template");
        return 0;
    }

    my $url = $template;
    my $lc  = lc($cc);
    $url =~ s/\{CC\}/$lc/g;

    my $timeout  = $config->{BLOCKLIST_TIMEOUT}  // 60;
    my $max_size = $config->{BLOCKLIST_MAX_SIZE} // 20971520;
    $timeout  = 60       unless $timeout  =~ /^\d+$/ && $timeout > 0;
    $max_size = 20971520 unless $max_size =~ /^\d+$/ && $max_size > 0;

    my $target = $class->cache_file($cc, $family);
    my $tmp    = "$target.tmp.$$";

    my ($rc, $out) = _download($url, $tmp, $timeout, $max_size);
    if ($rc) {
        unlink($tmp);
        # IPv6 zone files are not published for every country. A missing one is
        # normal and should not read as a failure in the log.
        if ($family eq 'inet6') {
            HGLogger->debug("No IPv6 zone file for $cc (rc=$rc)");
        } else {
            HGLogger->error("Country zone $cc download failed (rc=$rc): $out");
        }
        return 0;
    }

    my @ranges = $class->_parse($tmp, $family);
    if (my $why = $class->_reject_reason($cc, $family, \@ranges, $config, $opt{force})) {
        unlink($tmp);
        HGLogger->error("Country zone $cc ($family) was not applied because "
                      . "$why; keeping the previous copy");
        return 0;
    }

    unlink($tmp);
    eval { HGConfig::_write_atomic($target, join("\n", @ranges) . "\n"); 1 } or do {
        HGLogger->error("Cannot write country zone cache for $cc: $@");
        return 0;
    };
    chmod(0600, $target);

    HGLogger->info("Country zone $cc ($family) updated: " . scalar(@ranges) . " ranges");
    return scalar(@ranges);
}

# Refresh every country the configuration names, for both families.
#
# Returns the codes whose IPv4 file changed, which is what the firewall needs
# in order to know which sets to reload.
sub refresh_due {
    my ($class, $config, %opt) = @_;

    my ($mode, @codes) = $class->mode($config);
    return () unless $mode;

    my @updated;
    for my $cc (@codes) {
        my $v4 = $class->refresh($cc, $config, %opt, family => 'inet');
        my $v6 = 0;
        $v6 = $class->refresh($cc, $config, %opt, family => 'inet6')
            if ($config->{IPV6} // '0') eq '1';
        push @updated, $cc if $v4 || $v6;
    }

    return @updated;
}

# Keep only lines that validate as a range of the expected family.
sub _parse {
    my ($class, $file, $family) = @_;

    my @ranges;
    open(my $fh, '<', $file) or return @ranges;

    my %seen;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/[#;].*$//;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        next unless length $line;

        my ($token) = split(/\s+/, $line, 2);
        next unless defined $token && length $token;

        if ($family eq 'inet6') {
            next unless HGConfig->valid_ipv6($token);
        } else {
            next unless HGConfig->valid_ipv4($token);
        }
        next if $seen{$token}++;

        push @ranges, $token;
    }
    close($fh);

    return @ranges;
}

# Read a cached country file.
sub cached_ranges {
    my ($class, $cc, $family) = @_;

    my @ranges;
    my $file = $class->cache_file($cc, $family);
    open(my $fh, '<', $file) or return @ranges;
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;
        push @ranges, $line;
    }
    close($fh);

    return @ranges;
}

# Total ranges held for a country, across both families. Used by the status
# output and the WHM page.
sub count {
    my ($class, $cc) = @_;
    return scalar($class->cached_ranges($cc, 'inet'))
         + scalar($class->cached_ranges($cc, 'inet6'));
}

# Fetch a list to a file, bounded by BLOCKLIST_MAX_SIZE.
#
# The cap is enforced by the shared downloader rather than by curl or
# wget, neither of which can be relied on to bound a single transfer.
sub _download {
    my ($url, $dest, $timeout, $max_size) = @_;
    return HGConfig::download_capped($url, $dest, $timeout, $max_size);
}

1;
