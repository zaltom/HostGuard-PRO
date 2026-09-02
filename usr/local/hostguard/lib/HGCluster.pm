package HGCluster;
###############################################################################
# HostGuard Pro - Server Cluster
# /usr/local/hostguard/lib/HGCluster.pm
#
# Propagates blocks between HostGuard Pro servers, so an address that attacks
# one member is refused by all of them.
#
# A member holds two things: the list of its peers, in cluster.conf, and a
# shared secret. A message is a single line sent over TCP and authenticated
# with an HMAC over its contents, so a peer that cannot produce the secret
# cannot inject a block. The secret is never sent.
#
#   HG2|<timestamp>|<nonce>|<action>|<address>|<reason>|<hmac>
#
# Four things have to hold before a message is acted on: the sender's address
# is a configured member, the HMAC verifies, the timestamp is inside
# CLUSTER_WINDOW seconds of now, and the nonce has not been seen before.
#
# The timestamp alone was the whole of the replay defence, and it is not
# enough. It stops a message captured today from being used next week; it does
# nothing about the next five minutes. Anyone able to see cluster traffic - a
# member that has been compromised, a shared network segment, a provider-side
# man in the middle - could resend a captured ALLOW or UNBLOCK as many times as
# they liked for CLUSTER_WINDOW seconds, and each resend was applied again. An
# administrator blocking that address on a member watched the block come
# straight back off, without the attacker ever holding the key.
#
# The nonce is inside the HMAC, so it cannot be changed to make a captured
# message look new, and every accepted one is remembered for the length of the
# window. Protocol version raised to HG2 rather than accepting both: leaving
# HG1 acceptable would leave the hole open, and nothing has shipped that speaks
# it.
#
# Only the actions below are accepted. A member cannot ask another to run a
# command, change its configuration or read a file - the protocol has no way
# to express any of those.
###############################################################################
use strict;
use warnings;
use Socket;
use Errno qw(EINPROGRESS EWOULDBLOCK EAGAIN EINTR);
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use HGConfig;
use HGLogger;

our $PROTOCOL = 'HG2';

# Nonces accepted within the current window, so none is accepted twice.
#
# In memory rather than on disk: the only process that listens is the daemon,
# and it is long lived. What a restart costs is one replay per captured
# message, and only for a message still inside CLUSTER_WINDOW at the moment the
# daemon comes back - so the exposure is a single reapplication of an
# already-authenticated action, within five minutes of it being sent, by
# someone who has to have been watching the wire. Persisting the cache would
# close that and would put a file write on the path of every accepted message;
# the trade is recorded here rather than made silently.
my %SEEN_NONCE;

# A ceiling, for the same reason every other table keyed on remote input has
# one. Only a holder of the key can add to this, so it is a backstop rather
# than a defence, and it is sized well above any real cluster's traffic.
our $MAX_SEEN_NONCE = 20000;

# Connections a broadcast will have open at once. A cluster is a handful of
# hosts; the limit is here so that a member list which is not cannot open a
# descriptor per entry.
our $MAX_IN_FLIGHT = 32;

# Sub-second timing where it is available, so a one second CLUSTER_TIMEOUT is
# a timeout rather than a rounding error. Time::HiRes ships with Perl, but the
# module works without it.
my $HAVE_HIRES = eval { require Time::HiRes; 1 } ? 1 : 0;
sub _now { return $HAVE_HIRES ? Time::HiRes::time() : time(); }

# Largest message read from a peer, and how long one peer may take to send it.
# A message is a single short line; anything that cannot manage one inside a
# second is not a member with something to say.
our $MAX_MESSAGE  = 1024;
our $READ_TIMEOUT = 1;

sub _set_nonblocking {
    my ($fh) = @_;
    my $flags = fcntl($fh, F_GETFL, 0);
    return 0 unless defined $flags;
    return fcntl($fh, F_SETFL, $flags | O_NONBLOCK) ? 1 : 0;
}

sub _wait_readable {
    my ($fh, $deadline) = @_;
    my $left = $deadline - _now();
    return 0 if $left <= 0;
    my $vec = '';
    vec($vec, fileno($fh), 1) = 1;
    my $n = select(my $r = $vec, undef, undef, $left);
    return (defined $n && $n > 0) ? 1 : 0;
}

# Whether this Perl's Socket can do IPv6.
#
# Socket has carried inet_pton, inet_ntop and the sockaddr_in6 pair since 2.000,
# which is every Perl a supported release ships. The check is here so that a
# host without them loses IPv6 members with an explanation rather than dying
# inside a socket call.
my $HAVE_INET6 = do {
    my $ok = eval {
        Socket->can('inet_pton') && Socket->can('inet_ntop')
            && Socket->can('pack_sockaddr_in6') && Socket->can('unpack_sockaddr_in6')
            && Socket->can('AF_INET6') && Socket->can('sockaddr_family');
    };
    $ok ? 1 : 0;
};

sub have_inet6 { return $HAVE_INET6 }

# An address in its packed form, for comparison.
#
# Two spellings of one IPv6 address are the same address: 2001:db8::1 and
# 2001:0db8:0000:0000:0000:0000:0000:0001 differ as strings and not at all as
# addresses. Comparing member addresses as text would let a member connect and
# be treated as a stranger, so everything that compares them compares these.
sub _packed {
    my ($ip) = @_;
    return undef unless defined $ip && length $ip;

    if (HGConfig->valid_ipv4($ip) && $ip !~ /:/) {
        return Socket::inet_aton($ip);
    }
    return undef unless $HAVE_INET6;
    return undef unless HGConfig->valid_ipv6($ip);
    my $packed = eval { Socket::inet_pton(Socket::AF_INET6(), $ip) };
    return $packed;
}

# The address family a member address belongs to, or undef if unusable.
sub _family {
    my ($ip) = @_;
    return undef unless defined $ip;
    return Socket::AF_INET()  if HGConfig->valid_ipv4($ip) && $ip !~ /:/;
    return Socket::AF_INET6() if $HAVE_INET6 && HGConfig->valid_ipv6($ip);
    return undef;
}

# What one member may ask of another.
our %ACTIONS = (
    DENY      => 'add a permanent block',
    TEMPDENY  => 'add a temporary block',
    ALLOW     => 'add to the allowlist',
    UNBLOCK   => 'remove a temporary block',
    PING      => 'confirm the member is reachable',
);

###############################################################################
# Membership
###############################################################################

# Read cluster.conf: one member address per line, optionally with a comment.
#
# The local host's own addresses are not filtered out here. Sending to
# ourselves is harmless - the message is authenticated and idempotent - and
# filtering would need an address list this module has no reason to hold.
sub members {
    my ($class, $file) = @_;
    $file //= "$HGConfig::CONFIG_DIR/cluster.conf";

    my @members;
    return @members unless -f $file;

    open(my $fh, '<', $file) or do {
        HGLogger->log_warn("Cannot open $file: $!");
        return @members;
    };

    my %seen;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        $line =~ s/\s*#.*$//;
        next unless length $line;

        unless (HGConfig->valid_ip($line)) {
            HGLogger->error("Ignoring cluster member that is not an address: $line");
            next;
        }
        # A CIDR range names many hosts and cannot be connected to.
        if ($line =~ m{/}) {
            HGLogger->error("Cluster members must be single addresses, not ranges: $line");
            next;
        }
        # Refused here rather than at send time. An address accepted into the
        # list and then skipped on every broadcast is a member that appears
        # configured and silently never receives anything.
        unless (defined _family($line)) {
            HGLogger->error("Ignoring cluster member $line: this Perl's Socket "
                          . "cannot do IPv6, so an IPv6 member cannot be reached");
            next;
        }
        next if $seen{$line}++;
        push @members, $line;
    }
    close($fh);

    return @members;
}

# True when the given address is a configured member.
sub is_member {
    my ($class, $ip, @members) = @_;
    return 0 unless defined $ip;

    my $want = _packed($ip);
    return 0 unless defined $want;

    @members = $class->members() unless @members;
    for my $m (@members) {
        my $have = _packed($m);
        next unless defined $have;
        return 1 if $have eq $want;
    }
    return 0;
}

# Examine the key file and say whether it is fit to use.
#
# The secret lives in its own file rather than in hostguard.conf so that it can
# carry tighter permissions than the configuration does.
#
# Returns (status, message, key). The key is only ever returned with a status
# of 'ok'; every other status returns the empty string, and the callers treat
# an empty key as "the cluster is not configured" and refuse to send or accept
# anything.
#
# Refusing rather than warning is the point of this sub. This key is the only
# thing standing between a cluster member and a forged instruction: anyone
# holding it can tell every member in the group to block or allow any address.
# On a shared host, a key that other local users can read means every hosting
# customer on the machine can do that. Continuing to use it because a warning
# was printed somewhere would make the warning the only protection, and nobody
# reads a log that says the same thing every minute.
#
# This is how ssh treats a private key with loose permissions, and for the same
# reason.
sub key_status {
    my ($class, $config) = @_;

    my $file = $config->{CLUSTER_KEY_FILE} || "$HGConfig::CONFIG_DIR/cluster.key";

    return ('missing', "no key file at $file", '') unless -f $file;

    my @st = stat($file);
    return ('missing', "cannot stat $file", '') unless @st;

    open(my $fh, '<', $file) or return ('missing', "cannot read $file: $!", '');
    my $key = do { local $/; <$fh> };
    close($fh);

    $key = '' unless defined $key;
    $key =~ s/^\s+//;
    $key =~ s/\s+$//;

    return classify_key($file, $st[2] & 07777, $st[4], $key);
}

# Decide whether a key is usable, given what was found on disk.
#
# Separated from reading the file so the decision can be exercised directly.
# The states it distinguishes are the whole of the policy, and a policy that
# cannot be tested is one that quietly stops being enforced.
sub classify_key {
    my ($file, $mode, $uid, $key) = @_;

    # Readable or writable by group or other.
    if ($mode & 0077) {
        return ('insecure_mode',
                sprintf('%s is mode %04o; anyone who can read it can forge '
                      . 'cluster messages. Run: chmod 600 %s', $file, $mode, $file),
                '');
    }

    # Owned by someone who is not root, and therefore rewritable by them.
    if (defined $uid && $uid != 0) {
        my $owner = getpwuid($uid);
        $owner = defined $owner ? $owner : $uid;
        return ('insecure_owner',
                "$file is owned by $owner rather than root, so that account "
              . "can replace the key. Run: chown root:root $file",
                '');
    }

    return ('missing', "$file is empty", '') unless defined $key && length $key;

    # Short enough to be worth guessing. The generator in cluster.conf produces
    # 64 hex characters.
    if (length($key) < 16) {
        return ('short',
                "the key in $file is only " . length($key) . " characters; a "
              . "key that short can be searched. Generate one with: "
              . "openssl rand -hex 32 > $file",
                '');
    }

    return ('ok', 'configured', $key);
}

# The shared secret, or the empty string when it cannot safely be used.
sub secret {
    my ($class, $config) = @_;

    my ($status, $message, $key) = $class->key_status($config);
    return $key if $status eq 'ok';

    # A missing key is the ordinary state on a host that is not clustered, so
    # it is not worth an error every time something asks.
    HGLogger->error("Cluster key refused: $message") unless $status eq 'missing';

    return '';
}

###############################################################################
# Message construction
###############################################################################

# Build one authenticated line, without its trailing newline.
sub _build {
    my ($class, $action, $ip, $reason, $key) = @_;

    my $ts = time();
    $reason = '' unless defined $reason;
    # The field separator and newlines cannot appear inside a field, or the
    # receiver would parse a different message than the one that was signed.
    $reason =~ s/[|\r\n]/ /g;
    $reason = substr($reason, 0, 200);

    my $payload = join('|', $PROTOCOL, $ts, _nonce(), $action, $ip, $reason);
    my $mac     = _hmac($payload, $key);

    return "$payload|$mac";
}

# A value that will not be produced twice.
#
# From the kernel where it can be, because the nonce is the only thing keeping
# a captured message from being reusable and a predictable one would let a
# receiver's cache be primed. The fallback is only reached on a host with no
# /dev/urandom, and mixes in enough that a collision inside one window is not a
# practical concern.
sub _nonce {
    if (open(my $fh, '<', '/dev/urandom')) {
        binmode($fh);
        my $buf;
        my $got = read($fh, $buf, 12);
        close($fh);
        return unpack('H*', $buf) if $got && $got == 12;
    }
    return sprintf('%08x%08x%08x', $$, time(), int(rand(0xFFFFFFFF)));
}

# Whether this nonce is new, recording it if so.
#
# Pruned on every call, so the table holds at most one window's traffic.
# When the cache was last swept.
#
# Sweeping on every message walked the whole table each time, so sustained
# traffic from a member holding the key cost O(n) per message against a 20,000
# ceiling. Nothing expires faster for being checked more often: an entry older
# than the window is refused on its timestamp regardless.
my $NONCE_PRUNED = 0;
our $NONCE_PRUNE_INTERVAL = 60;

sub _nonce_is_new {
    my ($nonce, $window) = @_;

    my $now = time();
    if ($now - $NONCE_PRUNED >= $NONCE_PRUNE_INTERVAL) {
        for my $seen (keys %SEEN_NONCE) {
            delete $SEEN_NONCE{$seen} if $SEEN_NONCE{$seen} < $now - $window;
        }
        $NONCE_PRUNED = $now;
    }

    if (scalar(keys %SEEN_NONCE) >= $MAX_SEEN_NONCE) {
        # Refusing is the only safe direction. Forgetting a nonce to make room
        # would make the message it belonged to replayable again, which is the
        # thing this exists to prevent.
        HGLogger->error("Cluster: $MAX_SEEN_NONCE messages accepted inside the "
                      . "replay window; refusing further messages until it "
                      . "clears. Something is sending far more than a cluster "
                      . "should.");
        return 0;
    }

    return 0 if exists $SEEN_NONCE{$nonce};
    $SEEN_NONCE{$nonce} = $now;
    return 1;
}

# Parse and authenticate one received line.
#
# Returns a hashref on success, or undef with the reason logged. Nothing about
# the message is trusted until the HMAC has verified.
sub parse {
    my ($class, $line, $key, $config) = @_;

    return undef unless defined $line && length $line;

    # No key, no authentication - and therefore nothing to parse.
    #
    # secret() returns the empty string for every key it refuses: missing,
    # readable by group or other, owned by someone other than root, or short
    # enough to search. This did not check, and hmac_sha256_hex($payload, '')
    # is a perfectly good digest under a perfectly guessable key. Anyone who
    # could reach the port from a configured member address, and who knew or
    # guessed that the key had been refused, could sign whatever they liked -
    # including an ALLOW that appends an address to allow.conf on every member,
    # above every block, permanently.
    #
    # listeners() already refuses to open a socket without a usable key, so
    # this was reachable only when a key degraded while the daemon was running:
    # a restored backup, a configuration-management run, a key copied between
    # members under a permissive umask. That is not a rare way for a file mode
    # to change, and the daemon holds its sockets for weeks.
    #
    # broadcast() has always made this check. The header of this module says
    # callers "refuse to send or accept anything"; this is the accept half.
    unless (defined $key && length $key) {
        HGLogger->error("Cluster message refused: no usable shared key, so "
                      . "nothing can be authenticated. Check the key with "
                      . "'hostguard --cluster list'.");
        return undef;
    }

    chomp $line;
    $line =~ s/\r$//;

    my @f = split(/\|/, $line, 7);
    unless (@f == 7) {
        HGLogger->log_warn("Cluster message has the wrong number of fields");
        return undef;
    }
    my ($proto, $ts, $nonce, $action, $ip, $reason, $mac) = @f;

    unless ($proto eq $PROTOCOL) {
        HGLogger->log_warn("Cluster message has an unknown protocol: $proto"
                         . ($proto eq 'HG1'
                            ? ". HG1 had no replay protection inside its"
                              . " timestamp window and is no longer accepted;"
                              . " upgrade the sending member."
                            : ''));
        return undef;
    }

    my $payload = join('|', $proto, $ts, $nonce, $action, $ip, $reason);
    unless (_secure_eq(_hmac($payload, $key), $mac)) {
        HGLogger->log_warn("Cluster message failed authentication");
        return undef;
    }

    # Only past authentication is any field worth checking, so that a forged
    # message cannot be told apart from a malformed one by how it is rejected.
    unless ($ts =~ /^\d+$/) {
        HGLogger->log_warn("Cluster message has a malformed timestamp");
        return undef;
    }
    unless ($nonce =~ /^[0-9a-f]{16,64}$/) {
        HGLogger->log_warn("Cluster message has a malformed nonce");
        return undef;
    }

    my $window = $config->{CLUSTER_WINDOW} // 300;
    $window = 300 unless $window =~ /^\d+$/ && $window > 0;

    # Asymmetric on purpose. A message from the past is a message that took a
    # while to arrive, and the window has to allow for that; a message from the
    # future is a clock that disagrees, and allowing the full window in that
    # direction only widens the span over which a capture stays useful.
    my $ahead = $ts - time();
    my $drift = abs(time() - $ts);
    if ($ahead > 30) {
        HGLogger->log_warn("Cluster message is timestamped ${ahead}s in the "
                         . "future; check that member clocks agree");
        return undef;
    }
    if ($drift > $window) {
        HGLogger->log_warn("Cluster message is outside the ${window}s window "
                         . "(${drift}s adrift); check that member clocks agree");
        return undef;
    }

    # Last, so that a replay is not distinguishable from a stale message by how
    # long the rejection takes.
    unless (_nonce_is_new($nonce, $window)) {
        HGLogger->log_warn("Cluster message has already been seen; refusing it "
                         . "as a replay");
        return undef;
    }

    unless (exists $ACTIONS{$action}) {
        HGLogger->log_warn("Cluster message has an unsupported action: $action");
        return undef;
    }

    unless ($action eq 'PING' || HGConfig->valid_ip($ip)) {
        HGLogger->log_warn("Cluster message carries an invalid address");
        return undef;
    }

    return {
        action => $action,
        ip     => $ip,
        reason => $reason,
        ts     => $ts,
        nonce  => $nonce,
    };
}

###############################################################################
# Sending
###############################################################################

# Send one action to every member.
#
# Delivery is best effort: a member that is down or unreachable is logged and
# skipped, because a cluster that stops blocking locally when a peer is
# offline would be worse than one that falls briefly out of step.
#
# Every member is contacted at once rather than one after another. The
# difference is what the caller pays for an unreachable member: sending in
# turn cost CLUSTER_TIMEOUT per member, so a six-member cluster with three
# hosts down stalled the caller for fifteen seconds. That caller is
# block_ip(), on the daemon's main loop, during the flood that produced the
# block - the loop that is meanwhile not reading the logs the next block would
# come from. The bound is now CLUSTER_TIMEOUT for the whole broadcast, whatever
# the size of the cluster.
sub broadcast {
    my ($class, $action, $ip, $reason, $config) = @_;

    return 0 unless ($config->{CLUSTER_ENABLE} // '0') eq '1';
    return 0 unless exists $ACTIONS{$action};

    my $key = $class->secret($config);
    unless (length $key) {
        HGLogger->error("Cluster is enabled but no key is configured; "
                      . "not sending $action");
        return 0;
    }

    my @members = $class->members();
    return 0 unless @members;

    my $port = _port($config);
    my $line = $class->_build($action, $ip, $reason, $key);
    my $sent = _send_all(\@members, $port, $line, $config);

    HGLogger->info("Cluster: sent $action for $ip to $sent of "
                 . scalar(@members) . " member(s)");
    return $sent;
}

# Deliver one line to several members concurrently, returning how many took it.
#
# Each connection is non-blocking and all of them are watched by a single
# select, so the cost of the slowest member is paid once by the broadcast
# rather than once per member ahead of it in the list.
#
# select rather than alarm. alarm is a single per-process timer, so setting one
# inside a broadcast would silently discard whatever the caller had running, and
# a SIGALRM arriving from elsewhere would land in the middle of a socket call
# here. A deadline compared against the clock belongs to this function alone.
sub _send_all {
    my ($members, $port, $line, $config) = @_;

    my $timeout = $config->{CLUSTER_TIMEOUT} // 5;
    $timeout = 5 unless defined $timeout && $timeout =~ /^\d+$/ && $timeout > 0;

    # Concurrent, but not unboundedly so: a member list is normally a handful
    # of hosts, and one that is not should not open a file descriptor per
    # entry. Members past the limit start as earlier ones finish, and all of
    # them share the one deadline.
    my $limit = $config->{CLUSTER_MAX_PARALLEL} // $MAX_IN_FLIGHT;
    $limit = $MAX_IN_FLIGHT unless defined $limit && $limit =~ /^\d+$/ && $limit > 0;
    $limit = 256 if $limit > 256;

    # A member that closes the connection as we write would otherwise deliver
    # SIGPIPE, whose default action is to kill the daemon. A failed write is a
    # member that did not receive the message, nothing more.
    local $SIG{PIPE} = 'IGNORE';

    my $deadline = _now() + $timeout;
    my @queue    = @$members;
    my %live;                       # fileno => connection state
    my $sent     = 0;

    while (@queue || %live) {
        while (@queue && scalar(keys %live) < $limit) {
            my $member = shift @queue;
            my $conn   = _start_connect($member, $port, $line) or next;
            $live{ fileno($conn->{sock}) } = $conn;
        }
        last unless %live;

        my $remaining = $deadline - _now();
        if ($remaining <= 0) {
            _abandon(\%live, \@queue, 'timed out');
            last;
        }

        my $bits = '';
        vec($bits, $_, 1) = 1 for keys %live;
        my $wout = $bits;
        my $eout = $bits;
        my $n    = select(undef, $wout, $eout, $remaining);

        # A signal - the daemon's own SIGCHLD, a HUP asking for a reload -
        # interrupts select and is not a failure of any member.
        if (!defined $n || $n < 0) {
            next if $! == Errno::EINTR();
            _abandon(\%live, \@queue, "select failed: $!");
            last;
        }
        next unless $n;

        for my $fd (sort { $a <=> $b } keys %live) {
            next unless vec($wout, $fd, 1) || vec($eout, $fd, 1);

            my $conn = $live{$fd};
            my $done = _advance($conn);
            next unless defined $done;

            $sent++ if $done;
            close($conn->{sock});
            delete $live{$fd};
        }
    }

    return $sent;
}

# Open a non-blocking connection and return its state, or undef if it could
# not be started. A connection that completes immediately - a member on this
# host, or one already in the kernel's path - is returned ready to write.
sub _start_connect {
    my ($member, $port, $line) = @_;

    my $family = _family($member);
    unless (defined $family) {
        HGLogger->log_warn("Cannot reach cluster member $member: unusable address");
        return undef;
    }

    my $addr = _packed($member);
    unless (defined $addr) {
        HGLogger->log_warn("Cannot resolve cluster member $member");
        return undef;
    }

    my $sockaddr = ($family == Socket::AF_INET())
                 ? sockaddr_in($port, $addr)
                 : Socket::pack_sockaddr_in6($port, $addr);

    my $sock;
    unless (socket($sock, $family, SOCK_STREAM, getprotobyname('tcp'))) {
        HGLogger->error("Cluster socket for $member failed: $!");
        return undef;
    }

    my $flags = fcntl($sock, F_GETFL, 0);
    unless (defined $flags && fcntl($sock, F_SETFL, $flags | O_NONBLOCK)) {
        HGLogger->error("Cannot set cluster socket for $member non-blocking: $!");
        close($sock);
        return undef;
    }

    my $ok = connect($sock, $sockaddr);
    unless ($ok || $! == Errno::EINPROGRESS() || $! == Errno::EWOULDBLOCK()) {
        HGLogger->log_warn("Cluster send to $member failed: connect: $!");
        close($sock);
        return undef;
    }

    return {
        member    => $member,
        sock      => $sock,
        buf       => "$line\n",
        connected => $ok ? 1 : 0,
    };
}

# Move one connection along now that it is writable.
#
# Returns 1 when the line has been written, 0 when the member has failed, and
# undef when the connection is still in progress and should stay in the set.
sub _advance {
    my ($conn) = @_;

    unless ($conn->{connected}) {
        # Writable says the connect finished, not that it succeeded: a refused
        # connection reports itself the same way, and the reason is waiting in
        # SO_ERROR.
        my $packed = getsockopt($conn->{sock}, Socket::SOL_SOCKET(), Socket::SO_ERROR());
        my $err    = defined $packed ? unpack('i', $packed) : -1;
        if ($err) {
            local $! = $err > 0 ? $err : 0;
            my $why = $err > 0 ? "$!" : 'connect failed';
            HGLogger->log_warn("Cluster send to $conn->{member} failed: connect: $why");
            return 0;
        }
        $conn->{connected} = 1;
    }

    while (length $conn->{buf}) {
        my $n = syswrite($conn->{sock}, $conn->{buf});
        unless (defined $n) {
            # The socket buffer is full: wait to be told it is writable again.
            return undef if $! == Errno::EWOULDBLOCK() || $! == Errno::EAGAIN();
            return undef if $! == Errno::EINTR();
            HGLogger->log_warn("Cluster send to $conn->{member} failed: write: $!");
            return 0;
        }
        substr($conn->{buf}, 0, $n) = '';
    }

    return 1;
}

# Give up on everything still outstanding, so a member is never left counted
# as sent because the broadcast ran out of time before it was decided.
sub _abandon {
    my ($live, $queue, $why) = @_;

    for my $fd (keys %$live) {
        HGLogger->log_warn("Cluster send to $live->{$fd}{member} failed: $why");
        close($live->{$fd}{sock});
        delete $live->{$fd};
    }
    for my $member (@$queue) {
        HGLogger->log_warn("Cluster send to $member was not attempted: $why");
    }
    @$queue = ();
}

# Kept for callers that want to reach a single member. The concurrent path
# handles one member as readily as many, so there is no second implementation
# of the socket handling to keep in step.
sub _send_to {
    my ($member, $port, $line, $config) = @_;
    return _send_all([$member], $port, $line, $config);
}

###############################################################################
# Listening
###############################################################################

# Open the listening socket.
#
# Bound to CLUSTER_BIND, which defaults to the loopback address rather than
# every interface. A cluster that listens on 0.0.0.0 by accident is exposed to
# whoever can reach the port, and defaulting to loopback means the port has to
# be opened deliberately.
# Open the listening sockets.
#
# Returns a list, because a dual-stack host needs one socket per family: a
# single IPv6 socket accepting IPv4 depends on IPV6_V6ONLY defaulting off,
# which differs between kernels and is exactly the kind of thing that works on
# the test box and not on the customer's.
#
# CLUSTER_BIND takes a comma-separated list, so a host can listen on the one
# interface its members reach it on, or on both families. It defaults to
# loopback: the cluster port has to be opened deliberately, never by accident.
sub listeners {
    my ($class, $config) = @_;

    return () unless ($config->{CLUSTER_ENABLE} // '0') eq '1';

    my $key = $class->secret($config);
    unless (length $key) {
        HGLogger->error("Cluster is enabled but no key is configured; "
                      . "not listening");
        return ();
    }

    my $port = _port($config);
    my $spec = $config->{CLUSTER_BIND};
    $spec = '127.0.0.1' unless defined $spec && length $spec;

    my @socks;
    for my $bind (split(/[,\s]+/, $spec)) {
        next unless length $bind;

        my $family = _family($bind);
        unless (defined $family) {
            if (HGConfig->valid_ipv6($bind) && !$HAVE_INET6) {
                HGLogger->error("CLUSTER_BIND $bind needs IPv6, which this "
                              . "Perl's Socket cannot do");
            } else {
                HGLogger->error("CLUSTER_BIND is not an address: $bind");
            }
            next;
        }

        my $sock;
        unless (socket($sock, $family, SOCK_STREAM, getprotobyname('tcp'))) {
            HGLogger->error("Cannot create cluster listener for $bind: $!");
            next;
        }
        setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, pack('l', 1));

        # An IPv6 socket handles IPv6 only, and the IPv4 socket beside it
        # handles IPv4. Without this a v6 socket may also claim v4, and the
        # two would then race for the same port.
        if ($family == Socket::AF_INET6() && Socket->can('IPV6_V6ONLY')) {
            setsockopt($sock, Socket::IPPROTO_IPV6(), Socket::IPV6_V6ONLY(),
                       pack('l', 1));
        }

        my $addr = _packed($bind);
        my $sa   = ($family == Socket::AF_INET())
                 ? sockaddr_in($port, $addr)
                 : Socket::pack_sockaddr_in6($port, $addr);

        unless (bind($sock, $sa)) {
            HGLogger->error("Cannot bind cluster listener to [$bind]:$port: $!");
            close($sock);
            next;
        }
        unless (listen($sock, 10)) {
            HGLogger->error("Cannot listen on [$bind]:$port: $!");
            close($sock);
            next;
        }

        HGLogger->info("Cluster listener started on [$bind]:$port");
        push @socks, $sock;
    }

    HGLogger->error("Cluster is enabled but no listener could be opened")
        unless @socks;

    return @socks;
}

# Kept for callers that want a single socket. Returns the first listener.
sub listener {
    my ($class, $config) = @_;
    my @socks = $class->listeners($config);
    return $socks[0];
}

# Accept one pending connection and return the authenticated message.
#
# Returns (message, peer) on success, or an empty list. The caller is expected
# to have established that the socket is readable, so this never blocks for
# long: the read is bounded by both a timeout and a length cap, so a peer that
# connects and says nothing cannot hold the daemon.
sub accept_message {
    my ($class, $listen, $config) = @_;

    my $peer_addr = accept(my $conn, $listen);
    return () unless $peer_addr;

    # The peer's family comes from the sockaddr itself rather than from the
    # socket, so one accept path serves both listeners.
    my $peer = _peer_address($peer_addr);
    unless (defined $peer) {
        HGLogger->log_warn("Cluster connection from an address that could not "
                         . "be read; refused");
        close($conn);
        return ();
    }

    # Membership is checked before anything is read, so an unknown host cannot
    # even spend our time.
    unless ($class->is_member($peer)) {
        HGLogger->log_warn("Cluster connection from non-member $peer refused");
        close($conn);
        return ();
    }

    # Bounded by the clock, on a non-blocking socket.
    #
    # This ran as a blocking sysread under alarm(5), on the daemon's main loop,
    # and service_sockets calls it up to fifty times a pass. A member that
    # connected and sent 1023 bytes with no newline cost five seconds, and
    # fifty such connections cost four minutes with no log reading, no block
    # expiry and no scheduled task running. A member is more trusted than a
    # stranger, but "more trusted" is not "may stop the firewall thinking", and
    # a member host is exactly what gets compromised first in a cluster.
    #
    # select against a deadline rather than alarm, for the reason _send_all
    # gives below: alarm is one timer per process, and taking it here discards
    # whatever the caller was running.
    my $line = '';
    if (_set_nonblocking($conn)) {
        my $deadline = _now() + $READ_TIMEOUT;
        while (length($line) < $MAX_MESSAGE) {
            last unless _wait_readable($conn, $deadline);
            my $chunk;
            my $n = sysread($conn, $chunk, $MAX_MESSAGE - length($line));
            if (!defined $n) {
                last unless $! == EWOULDBLOCK || $! == EAGAIN || $! == EINTR;
                next;
            }
            last if $n == 0;
            $line .= $chunk;
            last if $line =~ /\n/;
        }
    } else {
        HGLogger->log_warn("Cannot set the cluster connection from $peer "
                         . "non-blocking; refusing it rather than risking a "
                         . "blocking read on the main loop");
    }
    close($conn);

    unless (defined $line && length $line) {
        HGLogger->log_warn("Cluster connection from $peer sent nothing");
        return ();
    }

    ($line) = split(/\n/, $line, 2);

    my $key = $class->secret($config);
    my $msg = $class->parse($line, $key, $config);
    return () unless $msg;

    HGLogger->info("Cluster: $msg->{action} for $msg->{ip} from $peer");
    return ($msg, $peer);
}

###############################################################################
# Helpers
###############################################################################

# Turn an accepted sockaddr into a printable address.
sub _peer_address {
    my ($sockaddr) = @_;
    return undef unless defined $sockaddr;

    my $family = eval { Socket::sockaddr_family($sockaddr) };
    return undef unless defined $family;

    if ($family == Socket::AF_INET()) {
        my (undef, $addr) = sockaddr_in($sockaddr);
        return inet_ntoa($addr);
    }

    if ($HAVE_INET6 && $family == Socket::AF_INET6()) {
        my (undef, $addr) = Socket::unpack_sockaddr_in6($sockaddr);
        my $text = eval { Socket::inet_ntop(Socket::AF_INET6(), $addr) };
        return undef unless defined $text;

        # A v4 address arriving on a v6 socket is written ::ffff:203.0.113.1.
        # Members are configured in their own notation, so it is reduced to
        # the form the member list uses before anything is compared.
        $text =~ s/^::ffff://i if $text =~ /^::ffff:\d+\.\d+\.\d+\.\d+$/i;
        return $text;
    }

    return undef;
}

sub _port {
    my ($config) = @_;
    my $port = $config->{CLUSTER_PORT} // 7654;
    $port = 7654 unless $port =~ /^\d+$/ && $port > 0 && $port <= 65535;
    return $port;
}

# HMAC-SHA256 of the payload under the shared key.
#
# Digest::SHA provides hmac_sha256_hex on every Perl that ships with a
# supported release. Without it the cluster refuses to authenticate rather
# than falling back to something weaker: a downgrade here would be silent, and
# a weak authenticator on a block-propagation channel is worse than no
# cluster at all.
sub _hmac {
    my ($payload, $key) = @_;

    my $hex = eval {
        require Digest::SHA;
        Digest::SHA::hmac_sha256_hex($payload, $key);
    };
    return $hex if defined $hex && length $hex;

    HGLogger->error("Digest::SHA is unavailable; cluster messages cannot be "
                  . "authenticated");
    return '';
}

# Compare two digests without leaking where they first differ.
sub _secure_eq {
    my ($a, $b) = @_;
    return 0 unless defined $a && defined $b;
    return 0 unless length $a && length $a == length $b;

    my $diff = 0;
    for my $i (0 .. length($a) - 1) {
        $diff |= ord(substr($a, $i, 1)) ^ ord(substr($b, $i, 1));
    }
    return $diff == 0 ? 1 : 0;
}

1;
