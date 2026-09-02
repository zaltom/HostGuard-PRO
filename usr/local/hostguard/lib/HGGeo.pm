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

# How much of a downloaded file has to parse as ranges before it is believed to
# be a zone file, as a percentage of its content lines. Overridden by
# GEO_MIN_VALID_PERCENT. The same test HGBlocklist applies, for the same reason
# and with the same numbers.
our $MIN_VALID_PERCENT = 50;

# Below this many content lines there is not enough of a file to judge that
# proportion on, and the check is skipped.
our $MIN_SAMPLE_LINES = 20;

# The fewest ranges a country zone file may hold and still be believed.
#
# The proportion test cannot catch a short response that happens to be all
# addresses, and that is the shape of several error pages. Set low enough that
# no real country is refused - the smallest national allocations run to dozens
# of ranges - and overridable with "hostguard -c force".
our $MIN_RANGES = 8;

# The fewest ranges that may be in force before GEO_ALLOW is applied at all.
#
# Separate from MIN_RANGES because it guards a different moment: that one
# decides whether a download is believable, this one decides whether what is on
# disk is enough to build a chain that drops everything it does not match. A
# cache file restored from a backup or left by an older release never went
# through the download check; this is the last point before the rule is
# emitted. See HGFirewall::_apply_geo_rules.
our $ALLOW_MIN_RANGES = 8;

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
    my ($class, $cc, $family, $config) = @_;

    # Counts what would actually load, so the shrink comparison is like with
    # like and the WHM page prints the number the firewall holds rather than
    # the number of lines in the file. Silent: the condition it would report is
    # already reported by cached_ranges, which is what loads the set.
    $config = HGConfig::resolve_config($config);

    my $file = $class->cache_file($cc, $family);
    open(my $fh, '<', $file) or return undef;
    my $count = 0;
    while (my $line = <$fh>) {
        chomp $line;
        next unless $line =~ /\S/;
        next if HGConfig::too_broad($line, $config);
        $count++;
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
#
# It followed only half of it. HGBlocklist asks two independent questions - how
# much of the file parsed as addresses, and how far the count fell against the
# copy being replaced - and this asked only the second. Worse, the second is
# skipped entirely when there is no previous copy, which is exactly the state
# of a first download. So a first "hostguard -c" against a publisher having an
# outage accepted whatever came back, provided one address-shaped token
# appeared anywhere in it.
#
# In GEO_ALLOW mode that is not a country filter that does nothing. The chain
# returns for the ranges it holds and drops everything else, so a zone file of
# one address makes the host reachable from one address. The log said
# "updated: 1 ranges" and the firewall started cleanly.
sub _reject_reason {
    my ($class, $cc, $family, $ranges, $stats, $config, $force) = @_;
    $stats ||= {};

    # A range wider than the floor, before anything else, and with no override.
    #
    # Before the emptiness check, not after it, and the ordering is the whole
    # point. _parse_with_stats drops a too-broad range rather than keeping it,
    # so a zone file in which *every* range trips the floor comes back with an
    # empty list and a positive count - and asking "is it empty" first answered
    # "it contained no usable ranges", which sends the operator looking for a
    # truncated download when what happened is that the prefix floor refused
    # the lot. HGBlocklist::_reject_reason has always asked in this order.
    if ($stats->{too_broad}) {
        return "$stats->{too_broad} of its ranges reach further than "
             . "MIN_PREFIX4/MIN_PREFIX6 allow"
             . (defined $stats->{broad_eg} ? " (for example $stats->{broad_eg})"
                                           : '')
             . ", which is not what a country allocation looks like";
    }

    return "it contained no usable ranges" unless @$ranges;

    # Is this an address list at all?
    #
    # The structural question, asked the way HGBlocklist asks it and for the
    # same reason. An HTML page, a JSON error body or a redirect notice is
    # mostly lines that are not addresses; a zone file is almost entirely
    # lines that are. No override: nothing that fails this is a zone file.
    my $considered = $stats->{considered} || 0;
    my $min = _percent($config, 'GEO_MIN_VALID_PERCENT', $MIN_VALID_PERCENT);
    if ($min > 0 && $considered >= $MIN_SAMPLE_LINES) {
        my $pct = int(100 * ($stats->{valid} || 0) / $considered);
        return "only $pct% of its $considered content lines are ranges, below "
             . "the $min% expected of a country zone file "
             . "(GEO_MIN_VALID_PERCENT)"
            if $pct < $min;
    }

    # An absolute floor, which is what the proportion test cannot supply.
    #
    # A short response that happens to be all addresses passes the percentage
    # and is still not a country. No allocation this software is asked to
    # allow or deny consists of a handful of ranges; the smallest real zone
    # files run to dozens. Deliberately low, so a genuinely tiny country is not
    # refused, and overridable by force for the operator who has one.
    my $min_ranges = $config->{GEO_MIN_RANGES};
    $min_ranges = $MIN_RANGES
        unless defined $min_ranges && $min_ranges =~ /^\d+$/;
    if (!$force && $min_ranges > 0 && scalar(@$ranges) < $min_ranges) {
        return "it holds only " . scalar(@$ranges) . " range(s), below the "
             . "$min_ranges a country zone file is expected to have "
             . "(GEO_MIN_RANGES). A response this short is usually an error "
             . "page rather than a zone file; run \"hostguard -c force\" if "
             . "the country really is this small";
    }

    my $shrink = _percent($config, 'GEO_MAX_SHRINK_PERCENT', $MAX_SHRINK_PERCENT);
    return undef if $force || $shrink <= 0 || $shrink >= 100;

    my $previous = $class->cached_count($cc, $family, $config);
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

    my $allow_http = (defined $config->{BLOCKLIST_ALLOW_HTTP}
                      && $config->{BLOCKLIST_ALLOW_HTTP} =~ /^(1|yes|true|on)$/i)
                   ? 1 : 0;

    my ($rc, $out) = _download($url, $tmp, $timeout, $max_size, $allow_http);
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

    my ($ranges, $stats) = $class->_parse_with_stats($tmp, $family, $config);
    my @ranges = @$ranges;
    if (my $why = $class->_reject_reason($cc, $family, \@ranges, $stats,
                                         $config, $opt{force})) {
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
    my ($class, $file, $family, $config) = @_;
    my ($ranges) = $class->_parse_with_stats($file, $family, $config);
    return @$ranges;
}

# The same parse, with a count of what was rejected along the way.
#
# The counts are the whole of what _reject_reason needs and did not have. This
# module only ever asked "did anything parse", which HGBlocklist's own comment
# explains at length is the wrong question: an error page, a login redirect or
# a parked-domain notice can carry an address in its markup, and the answer is
# yes.
#
#   considered  lines with content once comments and whitespace were removed
#   valid       lines whose first token was a range of the expected family
#   kept        ranges actually stored, so valid minus duplicates
#   too_broad   ranges reaching further than MIN_PREFIX4/MIN_PREFIX6 allow
#   broad_eg    one of those, to name in the message
sub _parse_with_stats {
    my ($class, $file, $family, $config) = @_;

    my @ranges;
    my %stats = (considered => 0, valid => 0, kept => 0,
                 too_broad => 0, broad_eg => undef);

    open(my $fh, '<', $file) or return (\@ranges, \%stats);

    my %seen;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/[#;].*$//;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        next unless length $line;

        $stats{considered}++;

        my ($token) = split(/\s+/, $line, 2);
        next unless defined $token && length $token;

        if ($family eq 'inet6') {
            next unless HGConfig->valid_ipv6($token);
        } else {
            next unless HGConfig->valid_ipv4($token);
        }
        $stats{valid}++;

        # A zone file is a list of allocations, not a statement about the whole
        # address space. In allow mode an over-wide range lets in everything it
        # covers; in deny mode it drops everything it covers. See
        # HGConfig::too_broad.
        if (HGConfig::too_broad($token, $config)) {
            $stats{too_broad}++;
            $stats{broad_eg} //= $token;
            next;
        }

        next if $seen{$token}++;

        push @ranges, $token;
    }
    close($fh);

    $stats{kept} = scalar(@ranges);
    return (\@ranges, \%stats);
}

# Read a cached country file.
#
# The prefix floor is applied here too, not only at download time. The cache is
# written from ranges that already passed it, so on the ordinary path this
# finds nothing - but a cache file restored from a backup, edited by hand, or
# left by a release that had no floor never went through the download path, and
# this is what the firewall loads its sets from.
sub cached_ranges {
    my ($class, $cc, $family, $config) = @_;

    # Resolved once, not once per range, and for the reason cached_entries
    # gives: the floor has to be the one the firewall loads with.
    $config = HGConfig::resolve_config($config);

    my @ranges;
    my $too_broad = 0;
    my $example;

    my $file = $class->cache_file($cc, $family);
    open(my $fh, '<', $file) or return @ranges;
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;

        if (HGConfig::too_broad($line, $config)) {
            $too_broad++;
            $example //= $line;
            next;
        }

        push @ranges, $line;
    }
    close($fh);

    HGLogger->error("Country $cc ($family): $too_broad cached range(s) reach "
                  . "further than MIN_PREFIX4/MIN_PREFIX6 allow"
                  . (defined $example ? " (for example $example)" : '')
                  . " and are NOT being loaded. Re-download with "
                  . "'hostguard -c force'.")
        if $too_broad;

    return @ranges;
}

# Total ranges held for a country, across both families. Used by the status
# output and the WHM page.
sub count {
    my ($class, $cc, $config) = @_;
    # Resolved here so the two reads below share one, rather than loading the
    # file twice.
    $config = HGConfig::resolve_config($config);
    return scalar($class->cached_ranges($cc, 'inet', $config))
         + scalar($class->cached_ranges($cc, 'inet6', $config));
}

# Fetch a list to a file, bounded by BLOCKLIST_MAX_SIZE.
#
# The cap is enforced by the shared downloader rather than by curl or
# wget, neither of which can be relied on to bound a single transfer. So is
# where the request is allowed to go, and whether a plain http:// source is
# acceptable at all: see the Downloading section of HGConfig. GEO_SOURCE is
# judged by the same BLOCKLIST_ALLOW_HTTP setting as a block list, because it
# is the same kind of data, arriving over the same transport, deciding the
# same thing.
sub _download {
    my ($url, $dest, $timeout, $max_size, $allow_http) = @_;
    return HGConfig::download_capped($url, $dest, $timeout, $max_size,
                                     allow_http => $allow_http);
}

1;
