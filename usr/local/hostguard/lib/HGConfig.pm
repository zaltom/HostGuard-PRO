package HGConfig;
###############################################################################
# HostGuard Pro - Configuration Parser Module
# /usr/local/hostguard/lib/HGConfig.pm
###############################################################################
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
# WNOHANG and _exit: a download that has to be abandoned is stopped and
# collected without ever blocking, and its child leaves without running
# this process's exit handlers.
use POSIX qw(:sys_wait_h _exit);
# Resolving a download's host before it is fetched, so that where the request
# will actually go is known to this process rather than only to curl. See the
# Downloading section.
use Socket;
# For safe_to_exec's explanation of a refused binary. Loaded lazily rather than
# with "use" because HGLogger has no dependency on this module and a circular
# use would be gratuitous.
BEGIN { require HGLogger }

our $CONFIG_DIR = "/etc/hostguard";
our $DATA_DIR   = "/var/lib/hostguard";
our $LOG_DIR    = "/var/log/hostguard";
our $LIB_DIR    = "/usr/local/hostguard/lib";
our $BIN_DIR    = "/usr/local/hostguard/bin";
our $VERSION    = "1.0.0";

# Load main configuration file
sub loadconfig {
    my ($class, $file) = @_;
    $file //= "$CONFIG_DIR/hostguard.conf";

    my %config;
    my %dup;
    open(my $fh, '<', $file) or die "Cannot open config $file: $!\n";
    flock($fh, LOCK_SH);
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/\s*#.*$// unless $line =~ /^#/;
        next if $line =~ /^\s*#/ || $line =~ /^\s*$/;

        my ($key, $value);
        if ($line =~ /^\s*(\w+)\s*=\s*"([^"]*)"\s*$/) {
            ($key, $value) = ($1, $2);
        } elsif ($line =~ /^\s*(\w+)\s*=\s*'([^']*)'\s*$/) {
            ($key, $value) = ($1, $2);
        } elsif ($line =~ /^\s*(\w+)\s*=\s*(\S+)\s*$/) {
            ($key, $value) = ($1, $2);
        }
        next unless defined $key;

        # A key that appears twice is worth saying out loud.
        #
        # The last one wins here, which is a choice this makes silently, and
        # set() used to rewrite the first - so on a file with a duplicate,
        # "hostguard --preset high" printed a full before-and-after table for
        # every setting it changed and changed none of them. set() now rewrites
        # them all, and this says why there was more than one.
        $dup{$key}++ if exists $config{$key};
        $config{$key} = $value;
    }
    close($fh);

    if (%dup) {
        HGLogger->log_warn("$file sets "
                         . join(', ', map { "$_ " . ($dup{$_} + 1) . " times" }
                                      sort keys %dup)
                         . ". The last value of each is the one in force. "
                         . "Remove the earlier lines: a duplicated setting is "
                         . "one nobody can read the file and be sure of.");
    }

    return bless { config => \%config, file => $file }, $class;
}

# Get a config value
sub get {
    my ($self, $key) = @_;
    return $self->{config}{$key};
}

# Get entire config hash
sub config {
    my ($self) = @_;
    return %{$self->{config}};
}

# Save a config value back to file.
#
# The whole read-modify-write is held under one lock, and the file is read
# again inside it rather than trusting the copy loaded at startup.
#
# Both matter, because setting one key rewrites the entire file. Two of these
# running at once - the preset command and the daemon, two administrators, a
# script setting several keys while WHM saves - would each read the same file
# and each write it back whole. The second rename wins and the first key's
# change is gone, with no error anywhere: the caller is told it was saved, and
# it was, for as long as it took the other process to finish.
#
# A shared lock taken only for the read is no defence, since it is released
# before the write. And the lock has to live in a separate file: rename(2)
# replaces the inode, so a lock taken on the config file itself is a lock on a
# file the next process will not be opening.
sub set {
    my ($self, $key, $value) = @_;

    my $file = $self->{file};
    my $lock = HGConfig->get_lock_wait('config', 30);

    my $ok = eval {
        open(my $fh, '<', $file) or die "Cannot read config: $!\n";
        flock($fh, LOCK_SH);
        my @lines = <$fh>;
        close($fh);

        # Every occurrence, not the first.
        #
        # This rewrote the first matching line and stopped. loadconfig reads
        # the file top to bottom and lets each assignment overwrite the last,
        # so the *last* occurrence is the one in force - and the two disagreed.
        # On a hostguard.conf with a duplicated key, which the WHM
        # whole-file editor and an upgrade merge both produce easily, set()
        # reported success, updated its own in-memory copy so the calling
        # process agreed with it, and changed nothing that any later process
        # would read. "hostguard --preset high" was the caller that mattered:
        # it printed the whole before-and-after table and applied none of it.
        #
        # The first match takes the new value and the rest are dropped, so the
        # file comes out of this with exactly one line for the key however many
        # it went in with.
        my $found = 0;
        my @out;
        for my $line (@lines) {
            unless ($line =~ /^\s*\Q$key\E\s*=/) {
                push @out, $line;
                next;
            }
            next if $found++;          # a duplicate: drop it
            push @out, "$key = \"$value\"\n";
        }
        @lines = @out;
        push @lines, "$key = \"$value\"\n" unless $found;

        _write_atomic($file, join('', @lines));
        1;
    };
    my $err = $@;
    close($lock);
    die $err || "Cannot save $key to config\n" unless $ok;

    # Updated only once the file holds it, so an in-memory copy never reports
    # a setting the next process to read the file will not see.
    $self->{config}{$key} = $value;
    return 1;
}

# Write via a temporary file in the same directory, renamed over the target.
# rename(2) is atomic, so a reader sees either the complete previous file or
# the complete new one, and an interrupted write leaves the target intact.
# Existing permissions are carried over to the replacement.
sub _write_atomic {
    my ($file, $content) = @_;
    my $tmp = "$file.tmp.$$";

    my $mode = (stat($file))[2];
    $mode = defined $mode ? ($mode & 07777) : 0600;

    sysopen(my $fh, $tmp, O_WRONLY | O_CREAT | O_TRUNC, $mode)
        or die "Cannot write $tmp: $!\n";
    flock($fh, LOCK_EX);
    unless (print $fh $content) {
        my $err = $!;
        close($fh);
        unlink($tmp);
        die "Cannot write $tmp: $err\n";
    }
    unless (close($fh)) {
        my $err = $!;
        unlink($tmp);
        die "Cannot close $tmp: $err\n";
    }
    chmod($mode, $tmp);

    unless (rename($tmp, $file)) {
        my $err = $!;
        unlink($tmp);
        die "Cannot replace $file: $err\n";
    }
    return 1;
}

# Load an IP list file (allow, deny, ignore) with Include support
sub load_iplist {
    my ($class, $file, $seen) = @_;
    $seen //= {};

    # Prevent include loops
    return () if $seen->{$file};
    $seen->{$file} = 1;

    my @entries;
    return @entries unless -f $file;

    open(my $fh, '<', $file) or do {
        warn "Cannot open $file: $!\n";
        return @entries;
    };
    flock($fh, LOCK_SH);
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;

        # Skip blanks and pure comments
        next if $line =~ /^\s*$/ || $line =~ /^\s*#/;

        # Handle Include directives
        if ($line =~ /^Include\s+(.+)$/i) {
            my $inc_file = $1;
            $inc_file =~ s/\s+$//;
            push @entries, $class->load_iplist($inc_file, $seen);
            next;
        }

        # Extract IP/CIDR (strip inline comment)
        my ($entry, $comment) = split(/\s*#\s*/, $line, 2);
        $entry =~ s/\s+$//;
        $comment //= "";

        next unless $entry;
        push @entries, { ip => $entry, comment => $comment, raw => $line };
    }
    close($fh);

    return @entries;
}

# Write an IP list file
sub save_iplist {
    my ($class, $file, $header, @entries) = @_;

    my $out = '';
    $out .= $header if $header;
    for my $entry (@entries) {
        if (ref $entry eq 'HASH') {
            if ($entry->{comment}) {
                $out .= "$entry->{ip} # $entry->{comment}\n";
            } else {
                $out .= "$entry->{ip}\n";
            }
        } else {
            $out .= "$entry\n";
        }
    }
    _write_atomic($file, $out);
}

# Validate an IPv4 address
sub valid_ipv4 {
    my ($class, $ip) = @_;
    return 0 unless defined $ip;
    # Strip CIDR
    my ($addr, $cidr) = split(/\//, $ip, 2);
    return 0 unless $addr =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    return 0 if $1 > 255 || $2 > 255 || $3 > 255 || $4 > 255;
    if (defined $cidr) {
        return 0 unless $cidr =~ /^\d{1,2}$/;
        return 0 if $cidr > 32;
    }
    return 1;
}

# Validate an IPv6 address, with an optional prefix length.
#
# The address itself is checked by parsing it to its 16 byte form, so only
# well-formed addresses are accepted.
sub valid_ipv6 {
    my ($class, $ip) = @_;
    return 0 unless defined $ip;
    my ($addr, $cidr) = split(/\//, $ip, 2);
    if (defined $cidr) {
        return 0 unless $cidr =~ /^\d{1,3}$/;
        return 0 if $cidr > 128;
    }
    return defined _ip6_to_bytes($addr) ? 1 : 0;
}

# Validate an IP (v4 or v6)
sub valid_ip {
    my ($class, $ip) = @_;
    return $class->valid_ipv4($ip) || $class->valid_ipv6($ip);
}

###############################################################################
# How wide a downloaded range may be
###############################################################################
#
# The block lists and the country zone files are the two places where data this
# host has not written decides what the firewall drops, and the only test
# applied to an entry was that it parsed. valid_ipv4 accepts a prefix length of
# zero, so "0.0.0.0/0" is a valid block list entry - and one line is the whole
# attack.
#
# What it costs: the live rule is a set match sending the source to the drop
# chain, so a zero-length prefix in that set drops every inbound packet from
# every source that is not allowlisted and not already established. Every site
# on the host goes off the air. The allowlist ordering protects the
# administrator's own access and does nothing at all for the service the host
# exists to run.
#
# What it defeats: nothing. BLOCKLIST_MIN_VALID_PERCENT asks what proportion of
# the file parsed as addresses, and a list with one line added is still
# overwhelmingly addresses. BLOCKLIST_MAX_SHRINK_PERCENT asks whether the count
# fell, and it did not. Both are tests of the file's shape; neither is a test
# of how far an entry reaches. And the apply path does not need a reload: the
# daemon's refresh swaps the new contents into the live set directly.
#
# So a floor, applied where the data is parsed. A provider with a legitimate
# reason to block a /8 is asking for a decision a person should make.
our $MIN_PREFIX4 = 8;
our $MIN_PREFIX6 = 32;

# How many entries one ipset is created to hold.
#
# Stated once, because two places have to agree about it: HGFirewall creates
# the sets with this as maxelem, and HGBlocklist refuses a download that would
# not fit. They disagreed by being written twice - the number was a literal in
# the set creation and nowhere else - and the consequence was that an oversized
# list was accepted, cached, and then failed to load on every reload from then
# on, because ipset restore aborts at maxelem and start() will not activate an
# incomplete slot. Correct, and permanent: the bad copy was already on disk.
our $SET_MAXELEM = 1000000;

# The floor in force, from configuration, bounded to something meaningful.
#
# 0 switches the check off, which is an administrator's call to make and is
# recorded here rather than hidden: a floor of 0 accepts 0.0.0.0/0.
sub min_prefix {
    my ($config, $family) = @_;

    my $v6  = (defined $family && $family eq 'inet6');
    my $key = $v6 ? 'MIN_PREFIX6' : 'MIN_PREFIX4';
    my $max = $v6 ? 128 : 32;
    my $def = $v6 ? $MIN_PREFIX6 : $MIN_PREFIX4;

    # Deliberately no fallback to loading the file here. This is called once
    # per entry, and a list runs to hundreds of thousands of them; a read per
    # entry would cost more than the check saves. Callers that may not have a
    # configuration resolve one first - see HGConfig::resolve_config, which the
    # cache readers call once on the way in.
    my $value;
    if (ref $config eq 'HASH')      { $value = $config->{$key} }
    elsif (ref $config)             { $value = eval { $config->get($key) } }

    return $def unless defined $value && $value =~ /^\d+$/ && $value <= $max;
    return $value;
}

# A configuration to judge entries against, loading one if the caller had none.
#
# Called once by each cache reader, not once per entry.
#
# Falling back to the built-in floor instead looks harmless and is not: the
# firewall loads its sets using the configured floor, so a reader using a
# different one disagrees with the kernel about what those sets contain. On a
# host that has lowered MIN_PREFIX4 - which the setting documents as supported,
# including 0 to switch the check off - "hostguard -s" and the WHM page counted
# fewer entries than the firewall was matching on, and logged an ERROR for each
# range telling the operator to re-download data their own configuration had
# already accepted.
#
# Every caller inside the firewall threads its configuration through, and
# should. This is so that one which does not is wrong about nothing.
sub resolve_config {
    my ($config) = @_;
    return $config if defined $config;
    return eval { HGConfig->loadconfig() };
}

# The prefix length an entry carries. A bare address is a full-length prefix.
sub prefix_len {
    my ($entry) = @_;
    return undef unless defined $entry;

    my ($addr, $bits) = split(m{/}, $entry, 2);
    return undef unless defined $addr && length $addr;

    my $v6 = ($addr =~ /:/) ? 1 : 0;
    return $v6 ? 128 : 32 unless defined $bits && length $bits;
    return undef unless $bits =~ /^\d{1,3}$/;
    return undef if $bits > ($v6 ? 128 : 32);
    return $bits;
}

# True when an entry reaches further than the configured floor permits.
sub too_broad {
    my ($entry, $config) = @_;

    my $bits = prefix_len($entry);
    return 0 unless defined $bits;

    my $v6    = (defined $entry && $entry =~ /:/) ? 'inet6' : 'inet';
    my $floor = min_prefix($config, $v6);
    return 0 unless $floor > 0;

    return $bits < $floor ? 1 : 0;
}

# Validate port list string
sub valid_ports {
    my ($class, $ports) = @_;
    return 1 if !defined $ports || $ports eq '';
    for my $p (split(/,/, $ports)) {
        $p =~ s/\s//g;
        if ($p =~ /^(\d+):(\d+)$/) {
            return 0 if $1 > 65535 || $2 > 65535 || $1 > $2;
        } elsif ($p =~ /^\d+$/) {
            return 0 if $p > 65535;
        } else {
            return 0;
        }
    }
    return 1;
}

# Check if an IP is in a list (supports CIDR matching)
sub ip_in_list {
    my ($class, $ip, @list) = @_;
    return 0 unless defined $ip;

    # An IPv6 address has many spellings and they are all the same address.
    # 2001:db8::1, 2001:0db8:0000:0000:0000:0000:0000:0001 and 2001:DB8::1
    # differ as strings and not at all as addresses, so comparing the text is
    # comparing the wrong thing: an allowlisted address written one way did
    # not match the same address written another, and the entry that exists to
    # stop a block being placed silently failed to stop it. The CIDR branch
    # never had the problem because it reduces both sides to bytes first;
    # HGCluster reduces member addresses the same way and for the same reason.
    my $want = _norm_ip($ip);

    for my $entry (@list) {
        my $check = ref $entry eq 'HASH' ? $entry->{ip} : $entry;
        next unless defined $check && length $check;
        # Handle advanced filter format
        next if $check =~ /\|/;
        if ($check =~ /\//) {
            return 1 if $class->ip_in_cidr($ip, $check);
        } else {
            return 1 if $ip eq $check;
            return 1 if defined $want && ($want eq (_norm_ip($check) // ''));
        }
    }
    return 0;
}

# One address in one canonical form, for comparison. IPv4 is already canonical
# as text; IPv6 becomes its 16 byte form. Returns undef for anything that is
# not a bare address.
sub _norm_ip {
    my ($ip) = @_;
    return undef unless defined $ip && length $ip && $ip !~ m{/};
    return $ip if $ip !~ /:/;
    my $bytes = _ip6_to_bytes($ip);
    return defined $bytes ? unpack('H*', $bytes) : undef;
}

# Check whether an address falls inside a CIDR range.
#
# Dispatches on the family of the range, so an IPv6 range is matched against
# IPv6 addresses and an IPv4 range against IPv4 addresses. An address of one
# family is never inside a range of the other.
sub ip_in_cidr {
    my ($class, $ip, $cidr) = @_;
    return 0 unless defined $ip && defined $cidr;

    my ($net, $bits) = split(/\//, $cidr, 2);
    return 0 unless defined $net && length $net;

    if ($net =~ /:/) {
        return $class->ip_in_cidr6($ip, $cidr);
    }

    return 0 unless $class->valid_ipv4($ip) && $class->valid_ipv4($net);
    $bits = 32 unless defined $bits;
    return 0 unless $bits =~ /^\d{1,2}$/ && $bits <= 32;

    my $ip_n   = _ip4_to_int($ip);
    my $net_n  = _ip4_to_int($net);
    my $mask_n = $bits == 0 ? 0 : (~0 << (32 - $bits)) & 0xFFFFFFFF;

    return ($ip_n & $mask_n) == ($net_n & $mask_n) ? 1 : 0;
}

# Check whether an IPv6 address falls inside an IPv6 CIDR range.
#
# Both sides are reduced to their 16 byte form and compared over the leading
# prefix: whole bytes first, then the remaining bits under a partial mask.
sub ip_in_cidr6 {
    my ($class, $ip, $cidr) = @_;

    my ($net, $bits) = split(/\//, $cidr, 2);
    $bits = 128 unless defined $bits;
    return 0 unless $bits =~ /^\d{1,3}$/ && $bits <= 128;

    my $addr_bytes = _ip6_to_bytes($ip);
    my $net_bytes  = _ip6_to_bytes($net);
    return 0 unless defined $addr_bytes && defined $net_bytes;

    my $whole = int($bits / 8);
    my $rest  = $bits % 8;

    return 0 if $whole && substr($addr_bytes, 0, $whole) ne substr($net_bytes, 0, $whole);

    if ($rest) {
        my $mask = (0xFF << (8 - $rest)) & 0xFF;
        return 0 if (ord(substr($addr_bytes, $whole, 1)) & $mask)
                 != (ord(substr($net_bytes,  $whole, 1)) & $mask);
    }

    return 1;
}

# Convert an IPv6 address to its 16 byte form, or undef if it is malformed.
#
# Handles the "::" run-length compression and the trailing dotted-quad form
# used by IPv4-mapped addresses such as ::ffff:192.0.2.1.
sub _ip6_to_bytes {
    my ($addr) = @_;
    return undef unless defined $addr && length $addr;

    $addr = lc($addr);
    return undef if $addr =~ /[^0-9a-f:.]/;
    return undef unless $addr =~ /:/;

    # A trailing dotted quad occupies the final two groups.
    if ($addr =~ s/:((?:\d{1,3}\.){3}\d{1,3})\z/:/) {
        my @octets = split(/\./, $1);
        return undef if grep { $_ > 255 } @octets;
        $addr .= sprintf('%x:%x',
                         ($octets[0] << 8) | $octets[1],
                         ($octets[2] << 8) | $octets[3]);
    }
    return undef if $addr =~ /\./;

    my (@head, @tail);
    if ($addr =~ /::/) {
        # Only one compressed run is permitted.
        return undef if $addr =~ /::.*::/;
        my ($h, $t) = split(/::/, $addr, 2);
        $h = '' unless defined $h;
        $t = '' unless defined $t;
        @head = length($h) ? split(/:/, $h, -1) : ();
        @tail = length($t) ? split(/:/, $t, -1) : ();
        return undef if @head + @tail > 7;
    } else {
        @head = split(/:/, $addr, -1);
        return undef unless @head == 8;
    }

    my @groups = (@head, ('0') x (8 - @head - @tail), @tail);
    return undef unless @groups == 8;

    my $bytes = '';
    for my $group (@groups) {
        return undef unless $group =~ /^[0-9a-f]{1,4}\z/;
        $bytes .= pack('n', hex($group));
    }
    return $bytes;
}

sub _ip4_to_int {
    my ($ip) = @_;
    my @octets = split(/\./, $ip);
    return ($octets[0] << 24) + ($octets[1] << 16) + ($octets[2] << 8) + $octets[3];
}

# Execute a command as an argument list, returning its exit code and combined
# stdout/stderr.
#
# The command is exec'd directly, with no shell involved, so values drawn from
# configuration files, IP lists or downloaded data cannot be interpreted as
# shell syntax. Callers pass a list of arguments, never a joined string.
sub run_command {
    my (@args) = @_;
    return (-1, "empty command") unless @args && defined $args[0] && length $args[0];

    # SIGCHLD restored for the length of this call.
    #
    # close() on a '-|' handle reaps the child and puts its status in $?. A
    # caller that has set SIGCHLD to IGNORE - the daemon does, so its own
    # short-lived children are not left as zombies - has asked the kernel to
    # discard exactly that status, so the waitpid inside close() fails with
    # ECHILD and $? comes back as -1. Shifted, that is a large positive number,
    # which every caller here reads as "the command failed". Every firewall
    # decision the daemon makes would then be made on a fabricated failure.
    local $SIG{CHLD} = 'DEFAULT';

    my $pid = open(my $fh, '-|');
    unless (defined $pid) {
        return (-1, "fork failed: $!");
    }
    if ($pid == 0) {
        # Child: fold stderr into stdout so the parent captures both streams.
        open(STDERR, '>&', \*STDOUT);
        exec { $args[0] } @args;
        exit(127);    # reached only if exec itself fails
    }

    my $out = do { local $/; <$fh> };
    close($fh);

    # -1 means the status could not be collected at all, which is not an exit
    # code and must not be shifted into one.
    my $rc = ($? == -1) ? -1 : ($? >> 8);
    return ($rc, defined $out ? $out : '');
}

###############################################################################
# Downloading
###############################################################################
#
# The block lists and the country zone files are the only data this host asks
# a stranger for, and it asks as root. Three things are decided here rather
# than left to curl, because curl cannot express any of them.
#
#   Where the request may go. A provider that has been taken over, a DNS
#   answer that has been tampered with, or a redirect from either points a
#   root process at whatever the attacker names, and the interesting targets
#   are all inside the host: cloud instance metadata on 169.254.169.254, an
#   unauthenticated admin service on loopback, a database on the private
#   network. Nothing of the response comes back to the attacker - it is
#   validated address by address and discarded - but the request is made, and
#   a request is enough for anything that acts on being asked. curl can be
#   told which schemes it may use; it cannot be told that those addresses are
#   not places a public block list lives. So every hop is resolved here, every
#   resolved address is checked against @FORBIDDEN_RANGES, and the connection
#   is pinned with --resolve to the addresses that passed, so the name cannot
#   answer differently the second time it is asked.
#
#   How many hops, and past whose gate. Redirects are followed by this code,
#   one at a time, each new URL going through the same check as the first.
#   curl's own --location follows them inside a single process, where the
#   destination is never visible to anything that could refuse it - which is
#   why --proto-redir, which was all this had, is not enough: it confines the
#   scheme and says nothing about the address.
#
#   Whether the transport is authenticated at all. Over plain http:// the
#   answer comes from whoever is on the path, and the answer decides what the
#   firewall drops: an attacker who can rewrite one response can empty a block
#   list, or fill one with the addresses of a customer's users. It is refused
#   unless the caller passes allow_http, which the callers take from
#   BLOCKLIST_ALLOW_HTTP.
#
# None of this replaces the checks on the content. A list fetched from an
# address that passed here is still parsed, still measured against the copy it
# replaces, and still refused if it does not look like a block list.

# Address ranges a download may never be directed at, whether by the
# configured URL, by DNS, or by a redirect.
#
# Everything that is not a place on the public internet: this host, this
# host's networks, link-local (which is where instance metadata lives on every
# major cloud), carrier-grade NAT, benchmarking, multicast and reserved space.
# A block list served from any of them is not a block list.
our @FORBIDDEN_RANGES = (
    '0.0.0.0/8',            # this network
    '10.0.0.0/8',           # private
    '100.64.0.0/10',        # carrier-grade NAT
    '127.0.0.0/8',          # loopback
    '169.254.0.0/16',       # link-local, and cloud instance metadata
    '172.16.0.0/12',        # private
    '192.0.0.0/24',         # IETF protocol assignments
    '192.0.2.0/24',         # documentation
    '192.88.99.0/24',       # 6to4 relay anycast
    '192.168.0.0/16',       # private
    '198.18.0.0/15',        # benchmarking
    '198.51.100.0/24',      # documentation
    '203.0.113.0/24',       # documentation
    '224.0.0.0/4',          # multicast
    '240.0.0.0/4',          # reserved, and 255.255.255.255 with it
    '::/128',               # unspecified
    '::1/128',              # loopback
    '100::/64',             # discard-only
    '2001:db8::/32',        # documentation
    'fc00::/7',             # unique local
    'fe80::/10',            # link-local
    'ff00::/8',             # multicast
);

# How many redirects a source may answer with before the fetch is abandoned.
our $MAX_REDIRECTS = 4;

# Split an http(s) URL into its parts, or undef if it is not one this fetches.
#
# Credentials in the authority are refused rather than honoured: nothing here
# has a reason to send them, and "http://safe.example@10.0.0.1/" reads to a
# person as a request to safe.example and to a client as a request to
# 10.0.0.1. The address check below would catch that one, but a URL nobody can
# read correctly has no business being fetched in the first place.
sub split_url {
    my ($url) = @_;
    return undef unless defined $url && length $url;
    return undef if $url =~ /[\s[:cntrl:]]/;
    return undef unless $url =~ m{^([A-Za-z][A-Za-z0-9+.\-]*)://([^/?\#]+)(.*)$};

    my ($scheme, $authority, $rest) = (lc($1), $2, $3);
    return undef if $authority =~ /\@/;

    my ($host, $port);
    if ($authority =~ /^\[([0-9A-Fa-f:.]+)\](?::(\d+))?$/) {
        ($host, $port) = ($1, $2);
    } elsif ($authority =~ /^([A-Za-z0-9._\-]+)(?::(\d+))?$/) {
        ($host, $port) = ($1, $2);
    } else {
        return undef;
    }

    return undef if defined $port && ($port < 1 || $port > 65535);
    $port = ($scheme eq 'https' ? 443 : 80) unless defined $port;
    $rest = '/' unless length $rest;

    return {
        scheme => $scheme,
        host   => $host,
        port   => $port,
        path   => $rest,
        url    => $url,
    };
}

# Why an address may not be fetched from, or undef when it may be.
sub address_is_forbidden {
    my ($ip) = @_;
    return 'it is not an address' unless defined $ip && length $ip;

    # An IPv4-mapped address is an IPv4 address wearing a hat, and
    # ::ffff:127.0.0.1 reaches loopback exactly as 127.0.0.1 does. Checking it
    # against the IPv6 ranges alone would let it through.
    $ip = $1 if $ip =~ /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

    return "\"$ip\" is not an address" unless HGConfig->valid_ip($ip);

    my $v6 = ($ip =~ /:/) ? 1 : 0;
    for my $range (@FORBIDDEN_RANGES) {
        next if (($range =~ /:/) ? 1 : 0) != $v6;
        return "$ip is inside $range, which is not on the public internet"
            if HGConfig->ip_in_cidr($ip, $range);
    }
    return undef;
}

# Every address a host name answers with, as text.
#
# All of them, not the first: a name that answers with one public address and
# one private one is exactly the shape of a rebinding attack, and taking the
# first would let it through half the time. The caller refuses the fetch if
# any single answer is forbidden.
#
# Returns (\@addresses, undef) or (undef, reason).
sub resolve_host {
    my ($host) = @_;
    return (undef, 'no host to resolve') unless defined $host && length $host;

    # A literal address is its own answer, and asking the resolver about it
    # would only invite one.
    return ([$host], undef) if HGConfig->valid_ip($host) && $host !~ m{/};

    my @addrs;

    if (defined &Socket::getaddrinfo) {
        my ($err, @res) = Socket::getaddrinfo($host, '',
                                              { socktype => Socket::SOCK_STREAM() });
        return (undef, "cannot resolve $host: $err") if $err;
        for my $ai (@res) {
            my $text = _sockaddr_text($ai->{family}, $ai->{addr});
            next unless defined $text;
            push @addrs, $text unless grep { $_ eq $text } @addrs;
        }
    } else {
        # A perl too old for Socket::getaddrinfo. IPv4 only, which is all
        # gethostbyname can say - and a name that has to be reached over IPv6
        # simply will not resolve here rather than being reached unchecked.
        my @packed = (gethostbyname($host))[4 .. 8];
        for my $p (@packed) {
            next unless defined $p && length($p) == 4;
            my $text = Socket::inet_ntoa($p);
            push @addrs, $text unless grep { $_ eq $text } @addrs;
        }
    }

    return (undef, "$host did not resolve to any address") unless @addrs;
    return (\@addrs, undef);
}

# One resolved socket address as text, or undef for a family we do not fetch
# over.
sub _sockaddr_text {
    my ($family, $addr) = @_;
    return undef unless defined $family && defined $addr;

    return eval {
        if ($family == Socket::AF_INET()) {
            my (undef, $packed) = Socket::unpack_sockaddr_in($addr);
            return Socket::inet_ntoa($packed);
        }
        if (defined &Socket::AF_INET6 && $family == Socket::AF_INET6()) {
            my (undef, $packed) = Socket::unpack_sockaddr_in6($addr);
            return Socket::inet_ntop(Socket::AF_INET6(), $packed);
        }
        return undef;
    };
}

# Decide whether one URL may be fetched, and where it resolves to.
#
# Returns (\%target, undef) with the resolved addresses filled in, or
# (undef, reason). Called once per hop, so a redirect is judged by the same
# rules as the URL an administrator configured.
sub check_download_target {
    my ($url, $allow_http) = @_;

    my $target = split_url($url);
    return (undef, "\"$url\" is not a usable http:// or https:// address")
        unless $target;

    unless ($target->{scheme} eq 'http' || $target->{scheme} eq 'https') {
        return (undef, "$target->{scheme}:// is not a scheme this fetches over");
    }

    if ($target->{scheme} eq 'http' && !$allow_http) {
        return (undef, "it is a plain http:// address, so anyone on the path "
                     . "between here and the provider decides what the "
                     . "firewall blocks. Use the https:// address the provider "
                     . "publishes, or set BLOCKLIST_ALLOW_HTTP to 1 to accept "
                     . "that risk deliberately");
    }

    my ($addrs, $err) = resolve_host($target->{host});
    return (undef, $err) unless $addrs;

    for my $addr (@$addrs) {
        if (my $why = address_is_forbidden($addr)) {
            return (undef, "$target->{host} resolves to $addr, which is not "
                         . "somewhere a block list can be fetched from: $why");
        }
    }

    $target->{addrs} = $addrs;
    return ($target, undef);
}

# Fetch a URL to a file, refusing to write more than max_size bytes.
#
# The size cap is applied here rather than left to the downloader, because
# neither downloader can be relied on for it:
#
#   wget  has no option that bounds a single file at all. --quota applies to
#         recursive retrievals and is documented as never affecting a single
#         file, so the fallback path had no limit whatsoever.
#   curl  has --max-filesize, but it only acts on a size declared up front. A
#         server using chunked encoding, or simply omitting Content-Length,
#         defeats it, so the primary path had no limit either in that case.
#
# The download is therefore streamed through a pipe and counted as it is
# written. Passing the cap aborts the transfer and removes the partial file,
# which is what stops a hostile or broken URL from filling the disk that the
# firewall's own state lives on.
#
# Options: allow_http accepts a plain http:// source, and defaults off.
#
# Returns (rc, message) as run_command does: rc 0 on success.
sub download_capped {
    my ($url, $dest, $timeout, $max_size, %opt) = @_;

    $timeout  = 60       unless defined $timeout  && $timeout  =~ /^\d+$/ && $timeout > 0;
    $max_size = 20971520 unless defined $max_size && $max_size =~ /^\d+$/ && $max_size > 0;

    my $current = $url;
    my $hops    = 0;

    while (1) {
        my ($target, $why) = check_download_target($current, $opt{allow_http});
        unless ($target) {
            unlink($dest);
            return (-1, ($hops ? "refused to follow a redirect to $current: "
                               : "refused to fetch $current: ") . $why);
        }

        my ($rc, $msg, $location) = _fetch_once($target, $dest, $timeout, $max_size);
        return ($rc, $msg) if $rc;
        return (0, '') unless defined $location;

        # The body of a redirect is not the list, whatever it contains.
        unlink($dest);

        if (++$hops > $MAX_REDIRECTS) {
            return (-1, "the source redirected more than $MAX_REDIRECTS times");
        }

        my $next = _absolute_url($target, $location);
        unless (defined $next) {
            return (-1, "the source redirected to something that is not a "
                      . "usable address: $location");
        }
        $current = $next;
    }
}

# Resolve a Location header against the URL it came from.
#
# Returns undef for anything that cannot be made into an absolute URL, which
# the caller reports rather than guessing at.
sub _absolute_url {
    my ($target, $location) = @_;
    return undef unless defined $location && length $location;
    return undef if $location =~ /[\s[:cntrl:]]/;

    return $location if $location =~ m{^[A-Za-z][A-Za-z0-9+.\-]*://};

    my $authority = ($target->{host} =~ /:/) ? "[$target->{host}]"
                                             : $target->{host};
    my $default = $target->{scheme} eq 'https' ? 443 : 80;
    $authority .= ":$target->{port}" if $target->{port} != $default;

    # Scheme-relative, before the path-absolute test below: "//host/x" starts
    # with a slash and is not a path.
    return "$target->{scheme}:$location" if $location =~ m{^//};
    return "$target->{scheme}://$authority$location" if $location =~ m{^/};

    my $dir = $target->{path};
    $dir =~ s/[?\#].*$//;
    $dir =~ s{[^/]*$}{};
    $dir = '/' unless length $dir;
    return "$target->{scheme}://$authority$dir$location";
}

# One hop: fetch a checked target, streaming it to $dest under the size cap.
#
# Returns (rc, message, location). A defined location means the server
# answered with a redirect and the caller decides whether to follow it; $dest
# then holds whatever body came with the redirect and is the caller's to
# discard.
sub _fetch_once {
    my ($target, $dest, $timeout, $max_size) = @_;

    my $url = $target->{url};

    # Both downloaders are asked to write to stdout so the bytes pass through
    # this process on their way to disk.
    my (@cmd, $hdrfile);
    if (my $curl = find_bin('curl')) {
        $hdrfile = "$dest.hdr.$$";

        # Pinned to the addresses check_download_target accepted. Without this
        # the name is resolved a second time inside curl, and the answer to
        # that lookup is not the answer that was checked - which is the whole
        # of a rebinding attack. Skipped when the host is already a literal
        # address, where there is no lookup to pin.
        my @pin;
        unless (HGConfig->valid_ip($target->{host})) {
            for my $addr (@{ $target->{addrs} || [] }) {
                my $text = ($addr =~ /:/) ? "[$addr]" : $addr;
                push @pin, '--resolve', "$target->{host}:$target->{port}:$text";
            }
        }

        @cmd = ($curl,
                '--fail',            # an HTTP error is a failure, not a body
                '--silent', '--show-error',
                # An https source is fetched over https or not at all. An
                # http one has already been accepted deliberately by the
                # caller, and may still be answered by an https address.
                '--proto', ($target->{scheme} eq 'https' ? '=https' : '=http,https'),
                # Redirects are followed by download_capped, one hop at a
                # time, so that each destination goes through the address
                # check. curl following them itself would skip every check
                # after the first.
                '--max-redirs', '0',
                @pin,
                '--dump-header', $hdrfile,
                '--max-time', $timeout,
                '--max-filesize', $max_size,   # early abort when it can be known
                '--output', '-',
                $url);
    } elsif (my $wget = find_bin('wget')) {
        # wget is the fallback, and a weaker one than it looks. It has no
        # --resolve, so a checked address cannot be pinned and the name is
        # looked up again inside it; no --proto; and no option that bounds a
        # transfer in total, which is why the size cap is enforced in this
        # process. Redirects are refused outright rather than followed,
        # because without pinning there is nothing to stop the second lookup
        # answering with an address the first did not.
        my @https = ($target->{scheme} eq 'https') ? ('--https-only') : ();

        @cmd = ($wget,
                '--quiet',
                '--timeout=' . $timeout,
                '--max-redirect=0',
                '--tries=2',
                @https,
                '--output-document=-',
                $url);

        HGLogger->log_warn("Downloading with wget; curl was not found. wget "
                         . "cannot be pinned to the address this checked, and "
                         . "cannot be told which protocols to use, so a "
                         . "compromised or hijacked provider has more room "
                         . "here than it would with curl, and a source that "
                         . "answers with a redirect will simply fail. "
                         . "Installing curl is worth doing on a host that "
                         . "fetches block lists.");
    } else {
        return (-1, 'neither curl nor wget is installed');
    }

    my $errfile = "$dest.err.$$";

    # An explicit pipe and fork, rather than open($fh, '-|').
    #
    # Closing a handle opened that way also waits for the child, and that wait
    # has no bound. Every path that abandons a transfer closes the pipe while
    # the downloader is still running, so abandoning it became a wait for the
    # process being abandoned - and the kill that was meant to settle a stuck
    # child was issued after the close, where it could never run.
    #
    # Usually the child dies of SIGPIPE the next time it writes and the wait is
    # brief. The case that hangs is a child that is not writing: wget has no
    # option that bounds a transfer in total (--timeout bounds a single stall,
    # and --tries starts over after one), so a server that trickles, or stalls
    # and resumes, keeps it alive indefinitely while it waits on the network
    # rather than on us. The size cap is what makes this reachable in normal
    # operation: it is the one abandon that happens while the server is still
    # healthy and sending.
    #
    # That wait ran on the daemon's main loop, so nothing else ran either: no
    # log reading, no block expiry, no cluster listening. With the pipe held
    # separately from the child, closing and reaping are two acts, and the reap
    # can escalate.
    my ($rd, $wr);
    unless (pipe($rd, $wr)) {
        unlink($hdrfile) if defined $hdrfile;
        return (-1, "pipe failed: $!");
    }

    # Reaping needs a status to collect, and a caller that has set SIGCHLD to
    # IGNORE - the daemon does, so that its own short-lived children are not
    # left as zombies - has asked the kernel to discard exactly that. Restored
    # for the length of this call, and only this call.
    local $SIG{CHLD} = 'DEFAULT';

    my $pid = fork();
    unless (defined $pid) {
        close($rd);
        close($wr);
        unlink($hdrfile) if defined $hdrfile;
        return (-1, "fork failed: $!");
    }
    if ($pid == 0) {
        # Child: stdout down the pipe, stderr to a file so a failure can still
        # be explained.
        close($rd);
        open(STDOUT, '>&', $wr);
        open(STDERR, '>', $errfile);
        close($wr);
        # _exit rather than exit: this process shares the parent's buffers, and
        # its stdout is the pipe the download arrives on. Running the parent's
        # exit handlers here would empty those buffers into the data.
        exec { $cmd[0] } @cmd or POSIX::_exit(127);
    }

    # The parent's copy of the write end has to go, or the read below never
    # sees end of file: the pipe stays open as long as any process holds it.
    close($wr);

    binmode($rd);
    my $written = 0;
    my $over    = 0;
    my $error   = '';

    my $out;
    unless (open($out, '>', $dest)) {
        $error = "cannot write $dest: $!";
        close($rd);
        _reap_child($pid, 0);
        unlink($errfile);
        unlink($hdrfile) if defined $hdrfile;
        return (-1, $error);
    }
    binmode($out);

    eval {
        # A backstop for a server that trickles bytes slowly enough to stay
        # inside the downloader's own timeout indefinitely.
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($timeout + 30);

        my $buf;
        while (1) {
            my $n = read($rd, $buf, 65536);
            last unless defined $n && $n > 0;

            if ($written + $n > $max_size) {
                # Write the part that fits so the byte count is exact, then
                # stop: the caller discards the file either way.
                my $room = $max_size - $written;
                print $out substr($buf, 0, $room) if $room > 0;
                $written += $room if $room > 0;
                $over = 1;
                last;
            }

            print $out $buf;
            $written += $n;
        }
        alarm(0);
        1;
    } or do {
        $error = $@ || 'read failed';
        chomp $error;
    };
    alarm(0);

    close($out);

    # The read end is closed first, so a downloader blocked writing into a full
    # pipe is released and can find out that nobody is listening. Closing it no
    # longer waits for anything.
    close($rd);

    # An abandoned transfer gets no grace period. The child is being stopped
    # because we have already decided not to use what it produces, so there is
    # nothing to wait for it to finish.
    my ($reaped, $status) = _reap_child($pid, ($over || $error) ? 0 : 5);

    my $rc = 0;
    if (!$reaped) {
        $rc = -1;
        $error ||= 'the downloader could not be stopped';
    } elsif (defined $status && $status >= 0) {
        $rc = $status >> 8;
    }

    my $stderr = '';
    if (open(my $ef, '<', $errfile)) {
        local $/;
        $stderr = <$ef> // '';
        close($ef);
    }
    unlink($errfile);
    $stderr =~ s/\s+$//;

    my ($http_status, $location);
    if (defined $hdrfile) {
        ($http_status, $location) = _read_headers($hdrfile);
        unlink($hdrfile);
    }

    if ($over) {
        unlink($dest);
        return (-1, "download exceeded BLOCKLIST_MAX_SIZE ($max_size bytes) "
                  . "and was abandoned");
    }
    if ($error) {
        unlink($dest);
        return (-1, $error eq 'timeout' ? "download timed out after ${timeout}s"
                                        : $error);
    }
    if ($rc) {
        unlink($dest);
        return ($rc, length $stderr ? $stderr : "downloader exited with $rc");
    }

    # A redirect is not a failure and not content. Reported up, where the
    # destination can be checked before it is followed. Tested before the
    # empty-body check below, because a redirect usually carries no body.
    if (defined $http_status && $http_status >= 300 && $http_status < 400) {
        return (0, '', $location) if defined $location;
        unlink($dest);
        return (-1, "the source answered with HTTP $http_status and no "
                  . "destination to follow");
    }

    unless ($written) {
        unlink($dest);
        return (-1, 'download was empty');
    }

    return (0, '');
}

# The final status and Location from a dumped header file.
#
# curl appends the headers of every response it saw, so the file can hold more
# than one; the status resets the location so that a Location left behind by an
# earlier response is never read as belonging to the last one.
sub _read_headers {
    my ($file) = @_;
    my ($status, $location);

    open(my $fh, '<', $file) or return (undef, undef);
    while (my $line = <$fh>) {
        $line =~ s/\r?\n\z//;
        if ($line =~ m{^HTTP/\S+\s+(\d{3})}) {
            $status   = $1;
            $location = undef;
            next;
        }
        $location = $1 if $line =~ /^Location:\s*(\S+)\s*$/i;
    }
    close($fh);

    return ($status, $location);
}

# Collect a child process, escalating rather than waiting indefinitely.
#
# Returns (1, status) once it has been collected, or (0, undef) if it could not
# be. $grace is how long it is given to leave on its own before it is
# signalled; a child being abandoned is given none.
#
# Every step here is bounded, which is the whole point: this is called from
# paths that have already given up on the child, and a cleanup that can block
# forever turns giving up into hanging.
sub _reap_child {
    my ($pid, $grace) = @_;
    $grace = 5 unless defined $grace;

    my ($got, $status) = _wait_child($pid, $grace);
    return ($got, $status) if $got;

    kill('TERM', $pid);
    ($got, $status) = _wait_child($pid, 2);
    return ($got, $status) if $got;

    # A downloader that ignores TERM, or that is stuck in a read the kernel
    # will not interrupt, is not going to be talked round.
    kill('KILL', $pid);
    return _wait_child($pid, 2);
}

# Poll for a child's exit until the deadline.
#
# Returns (1, status) if it has been collected, (1, -1) if it is gone but its
# status went to someone else, and (0, undef) if it is still running.
sub _wait_child {
    my ($pid, $seconds) = @_;

    my $deadline = time() + $seconds;
    while (1) {
        my $got = waitpid($pid, WNOHANG);
        return (1, $?) if $got == $pid;
        # Already collected - by a SIGCHLD disposition, or by a handler that
        # got there first. There is no status to be had, and nothing left to
        # wait for either.
        return (1, -1) if $got < 0;
        return (0, undef) if time() >= $deadline;

        # A twentieth of a second: short enough that a child which has already
        # exited is noticed at once, long enough not to spin.
        select(undef, undef, undef, 0.05);
    }
}

# Where an executable this software runs as root may live.
our @BIN_DIRS = ('/usr/sbin', '/sbin', '/usr/bin', '/bin',
                 '/usr/local/sbin', '/usr/local/bin');

# Locate an executable by name in the usual system directories. Accepts either
# a plain call or a class-method call; the name is always the final argument.
#
# Every candidate is checked before it is returned: it must be a regular,
# executable, root-owned file that no other account can rewrite, including
# through a directory above it. curl, wget, sendmail, systemctl and ip are all
# found through here and all run as root, so this is the single place that
# decides what this software is willing to execute with those privileges -
# HGFirewall's own lookup delegates to it rather than keeping a second
# standard.
sub find_bin {
    my $name = $_[-1];
    return "" unless defined $name && length $name;
    for my $dir (@BIN_DIRS) {
        my $path = "$dir/$name";
        next unless -x $path;
        next unless safe_to_exec($path, $name);
        return $path;
    }
    return "";
}

# True when a path is a regular, executable, root-owned file that only root can
# replace - directly or by writing the directory it sits in.
#
# Quiet by default: find_bin walks candidates and a rejection there is a reason
# to try the next directory, not an error. Pass a label to have the reason
# logged, which is what a configured path wants.
sub safe_to_exec {
    my ($path, $label) = @_;
    return 0 unless defined $path && length $path;

    my $complain = sub {
        HGLogger->error("Refusing to run $label at $path: $_[0]") if defined $label;
        return 0;
    };

    my @st = stat($path);
    return $complain->("cannot stat it: $!")           unless @st;
    return $complain->('not an executable regular file') unless -f _ && -x _;
    return $complain->('it is not owned by root')      if $st[4] != 0;
    return $complain->(sprintf('mode %04o is writable by group or other',
                               $st[2] & 07777))        if $st[2] & 022;

    my $dir = $path;
    while ($dir =~ s{/[^/]+$}{}) {
        $dir = '/' unless length $dir;
        my @d = stat($dir);
        return $complain->("cannot stat the directory $dir: $!") unless @d;
        return $complain->(sprintf('the directory %s is owned by uid %d with '
                                 . 'mode %04o, so it is not only root who '
                                 . 'decides what is there',
                                   $dir, $d[4], $d[2] & 07777))
            if $d[4] != 0 || ($d[2] & 022);
        last if $dir eq '/';
    }

    return 1;
}

# Get lock for exclusive operations
sub get_lock {
    my ($class, $name) = @_;
    my $lockfile = "$DATA_DIR/$name.lock";
    open(my $fh, '>', $lockfile) or die "Cannot create lock $lockfile: $!\n";
    flock($fh, LOCK_EX | LOCK_NB) or die "Cannot acquire lock $lockfile (another instance running?)\n";
    return $fh;
}

# The same lock, but waiting for it rather than giving up.
#
# Failing immediately is right for a second copy of a long operation starting
# up, and wrong for a short one that merely arrived while a long one was
# running. A block that gives up because a reload happened to be in progress is
# a block that never happens.
#
# Returns the handle, which holds the lock until it is closed, or dies if the
# wait runs out.
sub get_lock_wait {
    my ($class, $name, $timeout) = @_;
    $timeout = 30 unless defined $timeout && $timeout =~ /^\d+$/ && $timeout > 0;

    my $lockfile = "$DATA_DIR/$name.lock";
    sysopen(my $fh, $lockfile, O_WRONLY | O_CREAT, 0600)
        or die "Cannot create lock $lockfile: $!\n";

    my $got = eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($timeout);
        my $r = flock($fh, LOCK_EX);
        alarm(0);
        $r;
    };
    alarm(0);

    unless ($got) {
        close($fh);
        die "Timed out after ${timeout}s waiting for $lockfile. Another "
          . "operation is holding it.\n";
    }

    return $fh;
}

1;
