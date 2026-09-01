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
    open(my $fh, '<', $file) or die "Cannot open config $file: $!\n";
    flock($fh, LOCK_SH);
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/\s*#.*$// unless $line =~ /^#/;
        next if $line =~ /^\s*#/ || $line =~ /^\s*$/;
        if ($line =~ /^\s*(\w+)\s*=\s*"([^"]*)"\s*$/) {
            $config{$1} = $2;
        } elsif ($line =~ /^\s*(\w+)\s*=\s*'([^']*)'\s*$/) {
            $config{$1} = $2;
        } elsif ($line =~ /^\s*(\w+)\s*=\s*(\S+)\s*$/) {
            $config{$1} = $2;
        }
    }
    close($fh);

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

        my $found = 0;
        for my $line (@lines) {
            if ($line =~ /^\s*\Q$key\E\s*=/) {
                $line = "$key = \"$value\"\n";
                $found = 1;
                last;
            }
        }
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
# Returns (rc, message) as run_command does: rc 0 on success.
sub download_capped {
    my ($url, $dest, $timeout, $max_size) = @_;

    $timeout  = 60       unless defined $timeout  && $timeout  =~ /^\d+$/ && $timeout > 0;
    $max_size = 20971520 unless defined $max_size && $max_size =~ /^\d+$/ && $max_size > 0;

    # Both downloaders are asked to write to stdout so the bytes pass through
    # this process on their way to disk.
    my @cmd;
    if (my $curl = find_bin('curl')) {
        @cmd = ($curl,
                '--fail',            # an HTTP error is a failure, not a body
                '--silent', '--show-error',
                '--location',        # follow provider redirects
                # ...but only to where a block list can legitimately live. A
                # provider that has been compromised, or simply taken over,
                # can answer with a redirect, and an unrestricted --location
                # follows it anywhere: cloud metadata on 169.254.169.254, a
                # service listening on loopback, or file:// on a curl built
                # with it. Nothing of the response comes back to the attacker
                # - it is validated address by address and discarded - but the
                # request is still made, as root, from inside the host.
                '--proto', '=http,https',
                '--proto-redir', '=http,https',
                '--max-redirs', '3',
                '--max-time', $timeout,
                '--max-filesize', $max_size,   # early abort when it can be known
                '--output', '-',
                $url);
    } elsif (my $wget = find_bin('wget')) {
        @cmd = ($wget,
                '--quiet',
                '--timeout=' . $timeout,
                '--max-redirect=3',
                '--tries=2',
                '--output-document=-',
                $url);
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
    unless ($written) {
        unlink($dest);
        return (-1, 'download was empty');
    }

    return (0, '');
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
