package HGDetect;
###############################################################################
# HostGuard Pro - Log Detection Registry
# /usr/local/hostguard/lib/HGDetect.pm
#
# Owns every log line pattern HostGuard Pro recognises, and the mapping from a
# pattern to the configuration key that sets its threshold.
#
# The daemon asks this module two questions: which files to watch, and what a
# given line means. Keeping both here means a new service is added by editing
# one table rather than by touching the daemon's main loop.
#
# Three kinds of pattern are held:
#
#   failure  - an authentication failure, counted towards a block threshold
#   success  - a successful login, counted for rate tracking and notices
#   notice   - an event that is only ever reported, never counted
#
# Administrator-supplied patterns are read from patterns.conf and carry their
# own log file and threshold, so a service HostGuard Pro does not know about
# can be watched without changing any code.
###############################################################################
use strict;
use warnings;
use HGConfig;
use HGLogger;

# Locates a candidate address in a log line.
#
# Deliberately permissive: its only job is to find something address-shaped.
# Every capture is validated with HGConfig->valid_ip before it is acted on, so
# a false positive here costs nothing.
our $IP = qr/((?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})/;

# The same shape, captured under a name.
#
# Which address a pattern picks out of a line is a security decision, and it
# not made by position. Taking whichever capture group comes first and parses
# is only safe when nothing to the left of the real address is under anyone
# else's control, and on an authentication log almost everything to the left of
# it is. A user name is chosen by whoever is trying to log in, sshd logs it as
# it was given, and it may contain spaces - so a client offering the user name
#
#     root from 8.8.8.8
#
# produced the line
#
#     sshd[1]: Invalid user root from 8.8.8.8 from 203.0.113.9 port 51234
#
# and the old pattern, "Invalid user \S+ from $IP", matched 8.8.8.8. Anyone who
# could reach the SSH port could therefore choose which address this host
# blocked: the administrator's, a DNS resolver's, the cPanel licence server's,
# a payment gateway's - and after LF_PERM_BLOCK_AFTER repeats, permanently, in
# deny.conf, propagated to every member of the cluster.
#
# Every pattern below now names its address group with $IPN, and the group is
# placed against text the logging daemon writes rather than against text a
# client supplies. Where the daemon writes something after the address - sshd's
# "port N", Dovecot's field separators, Apache's brackets - the pattern
# requires it, so the greedy run in front can only settle on the daemon's own
# copy, which is always the rightmost. Where the daemon writes the address
# first, as PAM's rhost= does, leftmost matching already picks the right one
# and the pattern is anchored there instead.
#
# _first_ip treats a named group as authoritative and never falls back to
# position when one is present.
our $IPN = qr/(?<ip>(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})/;

# The same for a user name, so a caller can tell the two apart without
# inferring it from the order the groups happen to appear in.
our $USER = qr/(?<user>\S+)/;

# Authentication failure patterns, keyed by service.
#
# Each service name maps to the configuration key holding its threshold via
# %THRESHOLD below. A service whose threshold is 0 is skipped entirely, so an
# unused pattern set costs nothing at runtime.
our %FAILURE = (
    # sshd puts the client's own user name in most of these lines, so each one
    # takes its address from the "from ADDR port N" tail sshd appends. The run
    # in front of the address is greedy on purpose: an injected copy is always
    # to the left of the real one, so the rightmost match is the daemon's.
    sshd => [
        qr/sshd\[\d+\]:\s+Failed (?:password|publickey|keyboard-interactive\/pam) for .*from $IPN port \d+/,
        qr/sshd\[\d+\]:\s+Invalid user .*from $IPN port \d+/,
        qr/sshd\[\d+\]:\s+Connection closed by (?:authenticating|invalid) user .*\s$IPN port \d+/,
        # PAM writes rhost= before user=, so leftmost matching already lands on
        # the real one and a "rhost=" inside a user name cannot displace it.
        qr/sshd\[\d+\]:\s+pam_unix\(sshd:auth\):\s+authentication failure;.*?\brhost=$IPN/,
        # No user name precedes the address in these two.
        qr/sshd\[\d+\]:\s+Received disconnect from $IPN port \d+.*\[preauth\]/,
        qr/sshd\[\d+\]:\s+error: maximum authentication attempts exceeded for .*from $IPN port \d+/,
        qr/sshd\[\d+\]:\s+User .*from $IPN not allowed because/,
    ],

    # Each of these brackets or quotes the address, and the pattern requires
    # that delimiter plus the end of the line where the daemon puts it there.
    # The runs are greedy for a reason: a non-greedy one would take the first
    # address-shaped token on the line, which a user name can supply.
    ftpd => [
        # pure-ftpd
        qr/pure-ftpd.*\[WARNING\] Authentication failed for user .*\[$IPN\]\s*$/,
        # proftpd
        qr/proftpd\[\d+\].*no such user.*\[$IPN\]/i,
        qr/proftpd\[\d+\].*Login failed.*\[$IPN\]/i,
        # vsftpd writes both to its own log and to syslog; both shapes appear.
        qr/vsftpd.*\[pid \d+\].*FAIL LOGIN: Client "$IPN"\s*$/,
        qr/FAIL LOGIN: Client "$IPN"\s*$/,
    ],

    # Dovecot's rip= is a field it writes itself and always follows with either
    # another field or the end of the line, so requiring that boundary bounds
    # the address on both sides by the daemon's own syntax. Courier, uw-imap
    # and Kerio put it last.
    pop3d => [
        # Dovecot
        qr/dovecot.*pop3-login.*Authentication failure.*\brip=$IPN(?:[,\s]|$)/,
        qr/dovecot.*pop3-login.*Aborted login.*\brip=$IPN(?:[,\s]|$)/,
        qr/dovecot.*pop3-login.*Disconnected.*auth failed.*\brip=$IPN(?:[,\s]|$)/i,
        # Courier
        qr/pop3d.*LOGIN FAILED.*\bip=\[(?:::ffff:)?$IPN\]/,
        qr/authdaemond.*failed.*\bip=\[(?:::ffff:)?$IPN\]/,
        # uw-imap / ipop3d
        qr/ipop3d\[\d+\]:\s+Login failed user=.*\bhost=\S+ \[$IPN\]\s*$/,
        # Kerio Connect
        qr/kerio.*POP3.*[Ll]ogin failure.*from $IPN\s*$/,
    ],

    imapd => [
        # Dovecot
        qr/dovecot.*imap-login.*Authentication failure.*\brip=$IPN(?:[,\s]|$)/,
        qr/dovecot.*imap-login.*Aborted login.*\brip=$IPN(?:[,\s]|$)/,
        qr/dovecot.*imap-login.*Disconnected.*auth failed.*\brip=$IPN(?:[,\s]|$)/i,
        # Courier
        qr/imapd.*LOGIN FAILED.*\bip=\[(?:::ffff:)?$IPN\]/,
        # uw-imap
        qr/imapd\[\d+\]:\s+Login (?:failed|excessive failures) user=.*\bhost=\S+ \[$IPN\]\s*$/,
        # Kerio Connect
        qr/kerio.*IMAP.*[Ll]ogin failure.*from $IPN\s*$/,
    ],

    smtpauth => [
        # Only genuine authenticator failures count. A rejected recipient is
        # routine mail traffic - unknown local part, greylisting, relay denied
        # - rather than an authentication failure, and counting it would block
        # legitimate sending mail servers.
        qr/exim.*authenticator failed.*H=.*\[$IPN\](?::\d+)?/,
        qr/exim.*login authenticator failed for.*\[$IPN\](?::\d+)?/,
        qr/dovecot.*submission-login.*Authentication failure.*\brip=$IPN(?:[,\s]|$)/,
    ],

    # cPanel writes one line per failed login to login_log, covering cPanel,
    # WHM and Webmail alike. The address leads the line in the common format,
    # so it is matched before the marker as well as after it.
    # cPanel writes the address at the head of the line in the common format,
    # which is the one shape here that nothing can get in front of. The other
    # forms take the rightmost occurrence, for the same reason as sshd's.
    cpanel => [
        qr/^$IPN\b.*FAILED LOGIN/,
        qr/FAILED LOGIN.*\bip=$IPN(?:[\s,]|$)/,
        qr/FAILED LOGIN.*from $IPN(?:[\s,]|$)/i,
        qr/Login attempt failed.*from $IPN(?:[\s,]|$)/i,
        qr/brute force.*from $IPN(?:[\s,]|$)/i,
    ],

    # Password protected pages served by Apache. Both the classic and the 2.4
    # wordings are recognised.
    # Apache writes the address inside its own [client ...] field, ahead of any
    # request data, so these were never reachable by an injected user name.
    # Named all the same, so no pattern in this table depends on positional
    # capture any more.
    htpasswd => [
        qr/\[client (?:::ffff:)?$IPN(?::\d+)?\].*user \S+ not found/,
        qr/\[client (?:::ffff:)?$IPN(?::\d+)?\].*user \S+: authentication failure/,
        qr/\[client (?:::ffff:)?$IPN(?::\d+)?\].*password mismatch/i,
        qr/\[client (?:::ffff:)?$IPN(?::\d+)?\].*Invalid (?:password|credentials)/i,
    ],

    # ModSecurity. Version 1 logs "mod_security: Access denied"; version 2
    # logs "ModSecurity: Access denied" with a rule id. Both are treated as one
    # service because an administrator tunes them with a single threshold.
    modsec => [
        qr/\[client (?:::ffff:)?$IPN(?::\d+)?\].*ModSecurity: (?:Access denied|Warning)/i,
        qr/mod_security(?:-message)?: Access denied.*\[client (?:::ffff:)?$IPN/i,
        # There is deliberately no pattern reading the [uri] field. That is the
        # request path and is chosen by the client, so a request for /8.8.8.8
        # would name the address to block. The two forms above read Apache's own
        # [client] field and cover the same events.
    ],

    suhosin => [
        qr/suhosin\[\d+\].*ALERT.*\(attacker '(?:::ffff:)?$IPN'/i,
        qr/suhosin.*ALERT-\d+.*attacker '(?:::ffff:)?$IPN'/i,
    ],
);

# Successful authentications.
#
# These are never blocked on. They feed the per-hour login rate limit and the
# login notices, so an administrator sees who got in as well as who did not.
our %SUCCESS = (
    sshd => [
        qr/sshd\[\d+\]:\s+Accepted (?:password|publickey|keyboard-interactive\/pam) for $USER from $IPN port \d+/,
    ],
    pop3d => [
        qr/dovecot.*pop3-login.*Login: user=<(?<user>[^>]*)>.*\brip=$IPN(?:[,\s]|$)/,
        qr/pop3d.*LOGIN, user=$USER, ip=\[(?:::ffff:)?$IPN\]/,
    ],
    imapd => [
        qr/dovecot.*imap-login.*Login: user=<(?<user>[^>]*)>.*\brip=$IPN(?:[,\s]|$)/,
        qr/imapd.*LOGIN, user=$USER, ip=\[(?:::ffff:)?$IPN\]/,
    ],
);

# Events that are reported but never counted towards a block.
our %NOTICE = (
    # su(1) both ways round: the refusal and the successful switch.
    su_fail => [
        qr/su(?:\[\d+\])?:\s+FAILED SU \(to (\S+)\) (\S+)/,
        qr/su(?:\[\d+\])?:\s+pam_unix\(su(?:-l)?:auth\):\s+authentication failure.*user=(\S+)/,
    ],
    su_ok => [
        qr/su(?:\[\d+\])?:\s+\(to (\S+)\) (\S+) on/,
        qr/su(?:\[\d+\])?:\s+Successful su for (\S+) by (\S+)/,
    ],
    # A source the kernel blocked for sweeping closed ports.
    #
    # The block itself is applied in the kernel, by the rule the firewall
    # builds, so the daemon never sees it happen. What it can see is the log
    # line that rule emits, which is what makes the report possible at all.
    # This needs DROP_LOGGING=1 and the kernel log among the watched files.
    port_scan => [
        qr/HG_SCAN:.* SRC=$IPN/,
    ],

    # Root access to WHM. cPanel logs a successful login to login_log.
    whm_root => [
        qr/^$IP\b.*(?:whostmgrd|whm).*successful login.*root/i,
        qr/system\s+root.*successful login.*$IP/i,
    ],
);

# Configuration key holding each failure service's threshold.
our %THRESHOLD = (
    sshd     => 'LF_SSHD',
    ftpd     => 'LF_FTPD',
    pop3d    => 'LF_POP3D',
    imapd    => 'LF_IMAPD',
    smtpauth => 'LF_SMTPAUTH',
    cpanel   => 'LF_CPANEL',
    htpasswd => 'LF_HTPASSWD',
    modsec   => 'LF_MODSEC',
    suhosin  => 'LF_SUHOSIN',
);

# Configuration keys naming the files to watch, in the order they are opened.
#
# A key that is empty or names a file that does not exist is skipped silently,
# so one configuration serves hosts with and without cPanel, Apache or
# ModSecurity installed.
our @LOG_KEYS = qw(
    LOG_SSHD
    LOG_SSHD_ALT
    LOG_FTPD
    LOG_FTPD_ALT
    LOG_MAIL
    LOG_MAIL_ALT
    LOG_CPANEL
    LOG_CPANEL_ERROR
    LOG_APACHE_ERROR
    LOG_MODSEC
    LOG_SUHOSIN
);

###############################################################################
# Custom patterns
###############################################################################

# Read patterns.conf and return one hashref per administrator-defined pattern.
#
# Format: NAME|LOGFILE|THRESHOLD|REGEX
#
# The regex is compiled inside an eval, so a malformed expression is reported
# and skipped rather than killing the daemon at startup. It must contain a
# capture group naming the offender, which should be written (?<ip>...) - see
# the warning below for what happens when it is not.
sub load_custom {
    my ($class, $file) = @_;
    $file //= "$HGConfig::CONFIG_DIR/patterns.conf";

    my @patterns;
    return @patterns unless -f $file;

    open(my $fh, '<', $file) or do {
        HGLogger->log_warn("Cannot open $file: $!");
        return @patterns;
    };

    my %seen;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        next if $line eq '' || $line =~ /^#/;

        my ($name, $logfile, $threshold, $regex) = split(/\|/, $line, 4);
        unless (defined $name && defined $logfile && defined $threshold && defined $regex) {
            HGLogger->error("Custom pattern is not NAME|LOGFILE|THRESHOLD|REGEX: $line");
            next;
        }
        for ($name, $logfile, $threshold) { s/^\s+//; s/\s+$//; }

        unless ($name =~ /^[A-Za-z0-9_]{1,24}$/) {
            HGLogger->error("Custom pattern name must be 1-24 word characters: $name");
            next;
        }
        if ($seen{lc $name}++) {
            HGLogger->error("Duplicate custom pattern name, ignoring later entry: $name");
            next;
        }
        unless ($threshold =~ /^\d+$/) {
            HGLogger->error("Custom pattern $name has a non-numeric threshold: $threshold");
            next;
        }
        unless ($logfile =~ m{^/\S*$}) {
            HGLogger->error("Custom pattern $name has an unusable log file: $logfile");
            next;
        }

        # A pattern with no capture group can never yield an address and would
        # silently never fire. Rejecting it here makes the mistake visible.
        unless ($regex =~ /\(/) {
            HGLogger->error("Custom pattern $name has no capture group for the address");
            next;
        }

        my $compiled = eval { qr/$regex/ };
        if ($@ || !defined $compiled) {
            my $err = $@ || 'unknown error';
            $err =~ s/\s+at\s+\S+\s+line\s+\d+\.?\s*$//;
            HGLogger->error("Custom pattern $name does not compile: $err");
            next;
        }

        # A pattern that does not name its address group falls back to
        # positional matching, and position is only safe when nothing to the
        # left of the address is attacker-supplied. On an authentication log
        # it usually is - a user name, a request path, a mail subject - so a
        # pattern like "Login failed for (\S+) from ([0-9.]+)" lets the client
        # decide which address gets blocked. Said once at load, naming the
        # pattern, rather than left to be discovered.
        unless ($regex =~ /\(\?<ip>/) {
            HGLogger->log_warn("Custom pattern $name does not name its address "
                             . "group. Whichever capture parses as an address "
                             . "first will be used, so anything the client "
                             . "controls earlier in the line can choose the "
                             . "address this host blocks. Write the address "
                             . "group as (?<ip>...) instead.");
        }

        push @patterns, {
            name      => $name,
            file      => $logfile,
            threshold => $threshold,
            regex     => $compiled,
            source    => $regex,
        };
    }
    close($fh);

    HGLogger->info("Loaded " . scalar(@patterns) . " custom log pattern(s)") if @patterns;
    return @patterns;
}

###############################################################################
# Matching
###############################################################################

# Test one line against the failure patterns of the services whose threshold
# is above zero.
#
# Returns (service, ip) for the first match, or an empty list. Each line is
# attributed to a single service: the first pattern set to claim it wins,
# which keeps one event from being counted twice.
sub match_failure {
    my ($class, $line, $config) = @_;

    for my $service (sort keys %FAILURE) {
        my $key = $THRESHOLD{$service} or next;
        my $threshold = $config->{$key} // 0;
        next unless $threshold =~ /^\d+$/ && $threshold > 0;

        for my $re (@{$FAILURE{$service}}) {
            next unless $line =~ $re;
            my $ip = _first_ip($line, $re);
            next unless defined $ip;
            return ($service, $ip);
        }
    }

    return ();
}

# Test one line against the successful-login patterns.
#
# Returns (service, ip, user) so the caller can both rate-limit the address and
# name the account in a notice.
sub match_success {
    my ($class, $line) = @_;

    for my $service (sort keys %SUCCESS) {
        for my $re (@{$SUCCESS{$service}}) {
            next unless $line =~ $re;

            # Named groups, for the same reason the failure patterns use them:
            # the address and the account are told apart by which group the
            # pattern says they are, not by which parsed as an address first.
            my ($ip, $user) = ($+{ip}, $+{user});
            next unless defined $ip;
            $ip =~ s/^::ffff://i;
            next unless HGConfig->valid_ip($ip);

            return ($service, $ip, defined $user && length $user ? $user : 'unknown');
        }
    }

    return ();
}

# Test one line against the notice patterns. Returns (event, detail) where
# detail is whatever the pattern captured, joined for reporting.
sub match_notice {
    my ($class, $line) = @_;

    for my $event (sort keys %NOTICE) {
        for my $re (@{$NOTICE{$event}}) {
            next unless $line =~ $re;
            my @caps = grep { defined } ($1, $2);
            return ($event, join(' ', @caps));
        }
    }

    return ();
}

# Test one line against the administrator's own patterns.
#
# Returns (name, ip, threshold) for the first match. A custom pattern is only
# applied to lines read from the file it names, which the daemon enforces by
# passing the originating file.
sub match_custom {
    my ($class, $line, $file, $patterns) = @_;

    for my $p (@$patterns) {
        next if defined $file && $p->{file} ne $file;
        next unless $line =~ $p->{regex};
        my $ip = _first_ip($line, $p->{regex});
        next unless defined $ip;
        return ($p->{name}, $ip, $p->{threshold});
    }

    return ();
}

# Pull the address a pattern identified.
#
# A pattern that names its address group is believed and nothing else is
# considered: the group was placed against text the logging daemon writes, and
# falling back to position when it does not match would restore exactly the
# behaviour the naming exists to remove.
#
# The positional fallback exists only for patterns with no named group, which
# in practice means administrator-supplied ones from patterns.conf. Those carry
# the same hazard - a pattern whose capture sits after a user name lets the
# client choose the address - so load_custom warns about it once per pattern and
# the documentation says to use (?<ip>...).
sub _first_ip {
    my ($line, $re) = @_;

    # One match, and only one. A second "$line =~ $re" here was unreachable -
    # a successful match in list context always yields at least (1) - and if it
    # had ever run it would have re-matched and reset %+, which is the state
    # everything below depends on.
    my @caps = ($line =~ $re);
    return undef unless @caps;

    if (defined $+{ip}) {
        my $candidate = $+{ip};
        # Trim the IPv4-mapped IPv6 prefix that Apache and Courier emit, so
        # the address matches what the firewall holds.
        $candidate =~ s/^::ffff://i;
        return HGConfig->valid_ip($candidate) ? $candidate : undef;
    }

    for my $cap (@caps) {
        next unless defined $cap && length $cap;
        my $candidate = $cap;
        $candidate =~ s/^::ffff://i;
        return $candidate if HGConfig->valid_ip($candidate);
    }
    return undef;
}

1;
