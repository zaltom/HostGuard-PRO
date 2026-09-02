package HGBlocklist;
###############################################################################
# HostGuard Pro - External Block List Module
# /usr/local/hostguard/lib/HGBlocklist.pm
#
# Reads /etc/hostguard/blocklists.conf, downloads the lists it defines, and
# keeps a parsed copy of each on disk for the firewall engine to load into
# ipsets.
#
# Downloaded data is untrusted. It is never executed or interpolated into a
# command; each line is matched against the IP validators and anything that
# does not parse as an address or CIDR range is discarded.
###############################################################################
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
use HGConfig;
use HGLogger;

# A list name becomes part of an ipset name, which the kernel limits to 31
# characters. The longest form is the IPv6 set: "hgb6_" + name + a two
# character slot suffix.
our $MAX_NAME_LEN = 24;

# Refreshing more often than this would hammer the list providers, so a shorter
# interval in the configuration is raised to it.
our $MIN_INTERVAL = 3600;

# How much of a downloaded file has to parse as addresses before it is
# believed to be an address list, as a percentage of its content lines.
# Overridden by BLOCKLIST_MIN_VALID_PERCENT.
our $MIN_VALID_PERCENT = 50;

# Below this many content lines there is not enough of a file to judge that
# proportion on, and the check is skipped.
our $MIN_SAMPLE_LINES = 20;

# How far a list may fall below the copy it replaces, as a percentage, before
# the update is treated as a truncated download. Overridden by
# BLOCKLIST_MAX_SHRINK_PERCENT.
our $MAX_SHRINK_PERCENT = 60;

# Lists smaller than this are exempt from the shrink check: a list of a dozen
# addresses can legitimately halve, and the percentage says little at that
# size.
our $SHRINK_FLOOR = 100;

# Directory holding one cached list per configured entry.
sub cache_dir { return "$HGConfig::DATA_DIR/blocklists"; }

# Cached copy of a list, one validated address or CIDR range per line.
sub cache_file {
    my ($class, $name) = @_;
    return cache_dir() . '/' . lc($name) . '.list';
}

###############################################################################
# Configuration
###############################################################################

# Read blocklists.conf and return one hashref per enabled list.
#
# Each line is "NAME|INTERVAL|MAX|URL". Malformed or unsafe lines are reported
# and skipped so that one bad entry cannot stop the rest from loading.
sub load {
    my ($class, $file) = @_;
    $file //= "$HGConfig::CONFIG_DIR/blocklists.conf";

    my @lists;
    return @lists unless -f $file;

    open(my $fh, '<', $file) or do {
        HGLogger->log_warn("Cannot open $file: $!");
        return @lists;
    };
    flock($fh, LOCK_SH);

    my %seen;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        next if $line eq '' || $line =~ /^#/;

        my ($name, $interval, $max, $url) = split(/\|/, $line, 4);

        unless (defined $name && defined $interval && defined $max && defined $url) {
            HGLogger->error("Blocklist entry is not NAME|INTERVAL|MAX|URL: $line");
            next;
        }

        for ($name, $interval, $max, $url) { s/^\s+//; s/\s+$//; }
        $name = uc($name);

        unless ($name =~ /^[A-Z0-9]{1,$MAX_NAME_LEN}$/) {
            HGLogger->error("Blocklist name must be 1-$MAX_NAME_LEN alphanumeric "
                          . "characters: $name");
            next;
        }
        if ($seen{$name}++) {
            HGLogger->error("Duplicate blocklist name, ignoring later entry: $name");
            next;
        }
        unless ($interval =~ /^\d+$/) {
            HGLogger->error("Blocklist $name has a non-numeric interval: $interval");
            next;
        }
        unless ($max =~ /^\d+$/) {
            HGLogger->error("Blocklist $name has a non-numeric maximum: $max");
            next;
        }
        # Only HTTP(S) URLs are fetched. Anything else - a local path, a
        # different scheme, or an address carrying whitespace or control
        # characters - is refused here.
        #
        # Where an accepted URL may actually lead is decided at fetch time,
        # not here: the host is resolved and checked, redirects are followed
        # one hop at a time under the same check, and a plain http:// source
        # needs BLOCKLIST_ALLOW_HTTP. See the Downloading section of HGConfig.
        # That check needs the configuration, which this does not have.
        unless ($url =~ m{^https?://[^\s[:cntrl:]]+$}i) {
            HGLogger->error("Blocklist $name has an unsupported URL: $url");
            next;
        }

        if ($interval < $MIN_INTERVAL) {
            HGLogger->log_warn("Blocklist $name interval raised to $MIN_INTERVAL seconds");
            $interval = $MIN_INTERVAL;
        }

        push @lists, {
            name     => $name,
            interval => $interval,
            max      => $max,
            url      => $url,
        };
    }
    close($fh);

    return @lists;
}

###############################################################################
# Downloading
###############################################################################

# Seconds since a list was last written to the cache, or undef if it has never
# been downloaded.
sub age {
    my ($class, $entry) = @_;
    my $file = $class->cache_file($entry->{name});
    my @st = stat($file);
    return undef unless @st;
    return time() - $st[9];
}

# True when a list has never been fetched or its cached copy has aged past the
# configured refresh interval.
sub is_due {
    my ($class, $entry) = @_;
    my $age = $class->age($entry);
    return 1 unless defined $age;
    return $age >= $entry->{interval} ? 1 : 0;
}

# Whether a plain http:// source may be fetched.
#
# Off unless BLOCKLIST_ALLOW_HTTP says otherwise. Over plain HTTP the reply is
# written by whoever is on the path between here and the provider, and the
# reply is what the firewall drops - so somebody in that position can empty a
# list, or fill one with the addresses of the customers this host serves, and
# every check downstream of the download would find nothing wrong with what
# arrived. Every list this software ships a line for is published over https,
# so the setting is for an operator with an internal mirror that genuinely has
# no certificate, and not for convenience.
sub allow_http {
    my ($config) = @_;
    my $value = $config ? $config->get('BLOCKLIST_ALLOW_HTTP') : undef;
    return (defined $value && $value =~ /^(1|yes|true|on)$/i) ? 1 : 0;
}

# Fetch one list and replace its cached copy.
#
# The download lands in a temporary file and has to be accepted before it is
# promoted, so a truncated transfer or a provider returning an error page
# leaves the previous copy in place rather than emptying the set. What
# "accepted" means, and why it is more than "it parsed", is in _reject_reason.
sub refresh {
    my ($class, $entry, $config, %opt) = @_;

    return 0 unless $opt{force} || $class->is_due($entry);

    my $dir = cache_dir();
    unless (-d $dir) {
        mkdir($dir, 0700) or do {
            HGLogger->error("Cannot create " . $dir . ": $!");
            return 0;
        };
    }

    my $timeout  = $config->get('BLOCKLIST_TIMEOUT')  // 60;
    my $max_size = $config->get('BLOCKLIST_MAX_SIZE') // 20971520;
    $timeout  = 60       unless $timeout  =~ /^\d+$/ && $timeout > 0;
    $max_size = 20971520 unless $max_size =~ /^\d+$/ && $max_size > 0;

    my $target = $class->cache_file($entry->{name});
    my $tmp    = "$target.tmp.$$";

    my ($rc, $out) = _download($entry->{url}, $tmp, $timeout, $max_size,
                               allow_http($config));
    if ($rc) {
        unlink($tmp);
        HGLogger->error("Blocklist $entry->{name} download failed (rc=$rc): $out");
        return 0;
    }

    my ($entries, $stats) = $class->parse_with_stats($tmp, $entry->{max}, $config);
    if (my $why = $class->_reject_reason($entry, $entries, $stats, $config, $opt{force})) {
        unlink($tmp);
        HGLogger->error("Blocklist $entry->{name} was not applied because $why; "
                      . "keeping the previous copy");
        return 0;
    }
    my @entries = @$entries;

    # Store the validated addresses rather than the raw download, so loading a
    # list into ipset never has to re-examine untrusted text.
    my $body = join("\n", @entries) . "\n";
    unlink($tmp);
    eval { HGConfig::_write_atomic($target, $body); 1 } or do {
        HGLogger->error("Cannot write cache for $entry->{name}: $@");
        return 0;
    };
    chmod(0600, $target);

    HGLogger->info("Blocklist $entry->{name} updated: " . scalar(@entries) . " entries");
    return scalar(@entries);
}

# Refresh every list that is due, returning the names of those that changed.
sub refresh_due {
    my ($class, $config, %opt) = @_;
    my @updated;
    for my $entry ($class->load()) {
        push @updated, $entry->{name} if $class->refresh($entry, $config, %opt);
    }
    return @updated;
}

# Fetch a list to a file, bounded by BLOCKLIST_MAX_SIZE.
#
# The cap is enforced by the shared downloader rather than by curl or
# wget, neither of which can be relied on to bound a single transfer. So is
# where the request is allowed to go, and whether a plain http:// source is
# acceptable at all: see the Downloading section of HGConfig.
sub _download {
    my ($url, $dest, $timeout, $max_size, $allow_http) = @_;
    return HGConfig::download_capped($url, $dest, $timeout, $max_size,
                                     allow_http => $allow_http);
}

###############################################################################
# Parsing
###############################################################################

# Extract addresses and CIDR ranges from a downloaded list.
#
# Providers publish in several shapes: a bare address per line, an address
# followed by a "#" or ";" comment, or an address followed by whitespace and
# free text. The first whitespace-separated token of each line is taken and
# kept only if it validates as an address, so anything unexpected - an HTML
# error page, a changed format - simply yields nothing.
sub parse_file {
    my ($class, $file, $max, $config) = @_;
    my ($entries) = $class->parse_with_stats($file, $max, $config);
    return @$entries;
}

# The same parse, with a count of what was rejected along the way.
#
# The counts are what makes the difference between "a list of 40,000 addresses"
# and "an HTML error page with an address in the footer" visible: both yield
# usable entries, and only the proportion of the file they account for tells
# them apart.
#
# Returns (\@entries, \%stats) where the stats are:
#
#   considered  lines with content once comments and whitespace were removed
#   valid       lines whose first token was an address or CIDR range
#   kept        entries actually stored, so valid minus duplicates
#   capped      true when reading stopped at the list's configured maximum
#   too_broad   entries reaching further than MIN_PREFIX4/MIN_PREFIX6 allow
#   broad_eg    one of those, to name in the message
sub parse_with_stats {
    my ($class, $file, $max, $config) = @_;
    $max = 0 unless defined $max && $max =~ /^\d+$/;

    my @entries;
    my %stats = (considered => 0, valid => 0, kept => 0, capped => 0,
                 too_broad => 0, broad_eg => undef);

    open(my $fh, '<', $file) or return (\@entries, \%stats);

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

        next unless HGConfig->valid_ipv4($token) || HGConfig->valid_ipv6($token);
        $stats{valid}++;

        # An entry reaching further than the floor is counted and dropped, and
        # _reject_reason refuses the whole download over it. Dropping it
        # quietly and keeping the rest would be worse than either extreme: the
        # list would apply, minus the one entry that says the provider is not
        # serving what it used to. See HGConfig::too_broad.
        if (HGConfig::too_broad($token, $config)) {
            $stats{too_broad}++;
            $stats{broad_eg} //= $token;
            next;
        }

        # Counted as valid before the duplicate check, so a provider that
        # repeats itself is not mistaken for one publishing junk.
        next if $seen{$token}++;

        push @entries, $token;
        if ($max && @entries >= $max) {
            $stats{capped} = 1;
            last;
        }
    }
    close($fh);

    $stats{kept} = scalar(@entries);
    return (\@entries, \%stats);
}

# Entries in the cached copy of a list, or undef if there is no cached copy.
#
# The cache holds one validated address per line, so counting lines is
# counting entries.
sub cached_count {
    my ($class, $name, $config) = @_;

    # Counts what would actually load, so the shrink comparison is like with
    # like: the new count is taken after the prefix floor has been applied, and
    # comparing it against a previous count taken before one would read a
    # tightened floor as a provider truncating its list.
    #
    # Silent, unlike the readers. This is a counter, and the condition it would
    # report is already reported by whichever reader loads the file.
    $config = HGConfig::resolve_config($config);

    my $file = $class->cache_file($name);
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

# A percentage setting, bounded to 0-100 and falling back to the default when
# it is missing or not a number.
sub _percent {
    my ($config, $key, $default) = @_;
    my $value = $config ? $config->get($key) : undef;
    return $default unless defined $value && $value =~ /^\d+$/ && $value <= 100;
    return $value;
}

# Decide whether a freshly parsed download may replace the cached copy.
#
# Returns undef to accept it, or the reason to refuse.
#
# "At least one usable entry" is the wrong question to ask. It asks whether the
# download contains an address, when what matters is whether the download is the
# list it claims to be. Both of the ways this goes wrong in practice would pass
# that test:
#
#   a provider serving an error page, a login redirect or a parked-domain
#   notice, any of which can carry an address somewhere in the markup, would
#   replace tens of thousands of entries with the one it happened to contain
#
#   a transfer cut short by a proxy or a provider mid-outage arrives complete
#   as far as the downloader can tell, and the fragment that did arrive parses
#   perfectly well
#
# In both, the firewall would silently stop blocking almost everything the list
# covers, and nothing about the failure would be visible: the update reports as
# a success, only smaller. So two further things are asked. How
# much of the file parsed as addresses, which separates a list from a document
# that mentions one; and how far the count fell against the copy being
# replaced, which separates a list that shrank from one that was truncated.
#
# The shrink check is a heuristic about the provider, not about safety, so an
# administrator can overrule it: "hostguard -b force" re-runs the
# fetch with force set and takes whatever the provider is serving. There is
# no override for the parse ratio, because nothing that fails it is a block
# list.
sub _reject_reason {
    my ($class, $entry, $entries, $stats, $config, $force) = @_;

    # An entry reaching further than the floor allows, before anything else.
    #
    # There is no override for this and there is deliberately no force flag
    # either, unlike the shrink check below. The shrink check is a heuristic
    # about a provider having a bad day; this one is a list that would take the
    # host off the network, and "run it again with force" is not a thing to
    # offer for that. Raise MIN_PREFIX4 or MIN_PREFIX6 if the range is really
    # meant to be blocked.
    if ($stats->{too_broad}) {
        return "$stats->{too_broad} of its entries reach further than "
             . "MIN_PREFIX4/MIN_PREFIX6 allow"
             . (defined $stats->{broad_eg} ? " (for example $stats->{broad_eg})"
                                           : '')
             . ", and a range that wide in a block list drops traffic from "
             . "everyone who is not allowlisted";
    }

    return "it contained no usable addresses" unless @$entries;

    # More entries than the ipset can hold.
    #
    # The sets are created with maxelem, so a list past that makes ipset
    # restore abort, which makes the slot incomplete, which makes start()
    # refuse to activate it. Failing closed there is right - but the oversized
    # copy is already cached by then, so every later reload fails the same way,
    # including the one an administrator runs to fix a lockout or apply an
    # emergency block. Refusing the download instead keeps the previous copy
    # and keeps the firewall reloadable.
    if (scalar(@$entries) > $HGConfig::SET_MAXELEM) {
        return "it holds " . scalar(@$entries) . " entries, more than the "
             . "$HGConfig::SET_MAXELEM an ipset here can hold. Loading it "
             . "would make every firewall reload fail. Set a MAX for this list "
             . "in blocklists.conf, or lower BLOCKLIST_MAX_SIZE";
    }

    my $considered = $stats->{considered} || 0;
    my $min = _percent($config, 'BLOCKLIST_MIN_VALID_PERCENT', $MIN_VALID_PERCENT);

    # Applied only once there is enough of a file to judge. A handful of lines
    # is as consistent with a small hand-maintained list as with a stray
    # address in a page of prose.
    if ($min > 0 && $considered >= $MIN_SAMPLE_LINES) {
        my $pct = int(100 * ($stats->{valid} || 0) / $considered);
        return "only $pct% of its $considered content lines are addresses, "
             . "below the $min% expected of an address list "
             . "(BLOCKLIST_MIN_VALID_PERCENT)"
            if $pct < $min;
    }

    my $shrink = _percent($config, 'BLOCKLIST_MAX_SHRINK_PERCENT', $MAX_SHRINK_PERCENT);
    return undef if $force || $shrink <= 0 || $shrink >= 100;

    # A list read only as far as its configured maximum is as long as it is
    # allowed to be, so it has not shrunk in any sense worth acting on.
    return undef if $stats->{capped};

    my $previous = $class->cached_count($entry->{name}, $config);
    return undef unless defined $previous && $previous >= $SHRINK_FLOOR;

    my $floor = int($previous * (100 - $shrink) / 100);
    my $kept  = scalar(@$entries);
    return undef if $kept >= $floor;

    return "it fell from $previous entries to $kept, a drop of more than "
         . "$shrink% (BLOCKLIST_MAX_SHRINK_PERCENT), which is what a truncated "
         . "download looks like; run \"hostguard -b force\" to accept it";
}

# How many IPv4 and IPv6 entries the cached copy holds.
#
# Separate from cached_entries because a caller that wants a number should not
# have to build a list to get one. The WHM block list page needs exactly this:
# materialising every address of every configured list to print a count would
# be unbounded work, and the CGI raises its own rlimits to infinity at startup,
# so nothing external would stop it.
#
# Returns (v4, v6). Counted line by line, so a list of any size costs one file
# read and no memory.
sub cached_counts {
    my ($class, $name, $config) = @_;

    # The floor applies here too, so the number the WHM page prints is the
    # number the firewall would load rather than the number of lines in the
    # file. Silent, for the reason cached_count gives.
    $config = HGConfig::resolve_config($config);

    my ($v4, $v6) = (0, 0);
    my $file = $class->cache_file($name);
    open(my $fh, '<', $file) or return ($v4, $v6);
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;
        next if HGConfig::too_broad($line, $config);
        if    (HGConfig->valid_ipv4($line)) { $v4++ }
        elsif (HGConfig->valid_ipv6($line)) { $v6++ }
    }
    close($fh);
    return ($v4, $v6);
}

# Read the cached copy of a list, split into IPv4 and IPv6 entries.
#
# The optional stats hashref comes back with 'missing' set when the list has
# never been downloaded, which is ordinary, and 'unreadable' when there is
# something at the path that cannot be read, which is not. Without the
# distinction both looked the same as a list with no entries, and a caller
# applying the list to the running firewall would do nothing at all and say
# nothing about it.
#
# The prefix floor is applied here as well as at download time. The cache is
# written from entries that already passed it, so on the ordinary path this
# finds nothing - but a cache file restored from a backup, edited by hand, or
# left by a release that had no floor does not go through the download path at
# all, and this is what the firewall actually loads from.
sub cached_entries {
    my ($class, $name, $stats, $config) = @_;
    $stats ||= {};
    $stats->{missing}    = 0;
    $stats->{unreadable} = 0;
    $stats->{too_broad}  = 0;
    $stats->{broad_eg}   = undef;

    # Resolved once, not once per entry: the floor has to be the one the
    # firewall loads with, or this reports on sets it disagrees with.
    $config = HGConfig::resolve_config($config);

    my (@v4, @v6);

    my $file = $class->cache_file($name);
    unless (-e $file) {
        $stats->{missing} = 1;
        return (\@v4, \@v6);
    }
    unless (-f $file) {
        HGLogger->error("$file is not a regular file, so blocklist $name "
                      . "cannot be read");
        $stats->{unreadable} = 1;
        return (\@v4, \@v6);
    }

    open(my $fh, '<', $file) or do {
        HGLogger->error("Cannot read $file: $!");
        $stats->{unreadable} = 1;
        return (\@v4, \@v6);
    };
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;

        if (HGConfig::too_broad($line, $config)) {
            $stats->{too_broad}++;
            $stats->{broad_eg} //= $line;
            next;
        }

        if (HGConfig->valid_ipv4($line)) {
            push @v4, $line;
        } elsif (HGConfig->valid_ipv6($line)) {
            push @v6, $line;
        }
    }
    close($fh);

    if ($stats->{too_broad}) {
        HGLogger->error("Blocklist $name: $stats->{too_broad} cached "
                      . "entry(s) reach further than MIN_PREFIX4/MIN_PREFIX6 "
                      . "allow"
                      . (defined $stats->{broad_eg}
                         ? " (for example $stats->{broad_eg})" : '')
                      . " and are NOT being loaded. A range that wide in a "
                      . "block list drops traffic from everyone who is not "
                      . "allowlisted. Re-download the list with "
                      . "'hostguard -b force'.");
    }

    return (\@v4, \@v6);
}

1;
