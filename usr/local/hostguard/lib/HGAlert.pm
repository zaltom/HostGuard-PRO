package HGAlert;
###############################################################################
# HostGuard Pro - Notification Engine
# /usr/local/hostguard/lib/HGAlert.pm
#
# Single path out of HostGuard Pro for every message sent to an administrator:
# blocks, login notices, process and file reports, load warnings and relay
# alerts all arrive here.
#
# Three guards stand between an event and the mailbox, because the events that
# most need reporting are exactly the ones that arrive in floods:
#
#   enabled   - each kind of notice has its own on/off switch, so a site can
#               take the reports it wants and nothing else
#   throttle  - an hourly ceiling per kind, counted in whole clock hours
#   repeat    - an identical notice inside REPEAT_INTERVAL is dropped, so one
#               noisy process or one persistent attacker yields one message
#
# State lives in a single file under the data directory and survives a daemon
# restart, so restarting is not a way to get around the ceilings.
###############################################################################
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock F_GETFL F_SETFL O_NONBLOCK);
use Errno qw(EWOULDBLOCK EAGAIN EINTR);
use POSIX ();
use HGConfig;
use HGLogger;

# Longest one delivery may take, in seconds, from fork to the mailer being
# collected. See _deliver.
our $DELIVER_TIMEOUT = 5;
our $DELIVER_GRACE   = 3;

# Every notice kind: the configuration key that enables it, the subject line
# used when no explicit subject is given, and the template that renders it.
#
# A kind absent from this table is refused, so a typo in a caller cannot
# quietly send unthrottled mail.
#
# Every template is optional. A caller always supplies a plain-text body as
# well, and that body is used when the template is missing or unreadable, so
# an edited, deleted or half-installed template degrades to readable mail
# rather than to an empty message.
our %KINDS = (
    block         => { key => 'LF_EMAIL_ALERT',      label => 'IP Blocked',
                       template => 'block_alert.txt' },
    permblock     => { key => 'LF_EMAIL_ALERT',      label => 'IP Permanently Blocked',
                       template => 'perm_block_alert.txt' },
    ssh_login     => { key => 'NOTIFY_SSH_LOGIN',    label => 'SSH Login',
                       template => 'ssh_login.txt' },
    su_login      => { key => 'NOTIFY_SU_LOGIN',     label => 'su Activity',
                       template => 'su_login.txt' },
    whm_root      => { key => 'NOTIFY_WHM_ROOT',     label => 'WHM Root Access',
                       template => 'whm_root.txt' },
    account_mod   => { key => 'NOTIFY_ACCOUNT_MOD',  label => 'Account Modified',
                       template => 'account_change.txt' },
    load_average  => { key => 'LOAD_ALERT',          label => 'High Load Average',
                       template => 'load_average.txt' },
    relay         => { key => 'RELAY_ALERT',         label => 'Excessive Email',
                       template => 'relay_alert.txt' },
    process       => { key => 'PROC_ALERT',          label => 'Suspicious Process',
                       template => 'suspicious_process.txt' },
    proc_usage    => { key => 'PROC_USAGE_ALERT',    label => 'Excessive Process Usage',
                       template => 'process_usage.txt' },
    proc_count    => { key => 'PROC_COUNT_ALERT',    label => 'Excessive User Processes',
                       template => 'process_count.txt' },
    susp_file     => { key => 'FILE_ALERT',          label => 'Suspicious File',
                       template => 'suspicious_file.txt' },
    watch_change  => { key => 'WATCH_ALERT',         label => 'Watched Path Changed',
                       template => 'watch_change.txt' },
    integrity     => { key => 'INTEGRITY_ALERT',     label => 'System Binary Changed',
                       template => 'integrity_change.txt' },
    login_rate    => { key => 'LOGIN_RATE_ALERT',    label => 'Excessive Logins',
                       template => 'login_rate.txt' },
    port_scan     => { key => 'SCAN_ALERT',          label => 'Port Scan Detected',
                       template => 'port_scan.txt' },
    cluster       => { key => 'CLUSTER_ALERT',       label => 'Cluster Event',
                       template => 'cluster_event.txt' },
    security      => { key => 'SECURITY_ALERT',      label => 'Security Check',
                       template => 'security_check.txt' },
);

# Where the templates live. A directory rather than a fixed path per file, so
# an administrator can point the whole set elsewhere if they keep their
# customisations outside the installation.
our $TEMPLATE_DIR = '/usr/local/hostguard/tpl';

# Resolved per call rather than captured at load time, so the module reads
# the data directory that is in force now.
sub _state_file { return "$HGConfig::DATA_DIR/alerts.state" }

# What this process last saw, used only to reject a notice without touching the
# disk. It is not the state: the state lives in the file, and every decision
# that could result in a message being sent is taken against that, under a
# lock. See _definitely_suppressed.
my %SEEN;


###############################################################################
# Public entry point
###############################################################################

# Send one notice.
#
#   kind    - key into %KINDS (required)
#   config  - hashref of the loaded configuration (required)
#   subject - subject line, without the host prefix (optional)
#   body    - plain-text message body (required). Used as written when the
#             kind has no template, and as the fallback when it has one that
#             cannot be read.
#   vars    - hashref of [NAME] substitutions for the template (optional).
#             HOSTNAME and TIME are always available without being passed.
#   ident   - what makes this notice distinct from another of the same kind,
#             usually an address, path or user. Repeat suppression is keyed on
#             it. Defaults to the subject.
#
# Returns 1 when a message was handed to the mailer, 0 when it was suppressed.
sub send {
    my ($class, %args) = @_;

    my $kind   = $args{kind}   or return 0;
    my $config = $args{config} or return 0;
    my $body   = $args{body};
    return 0 unless defined $body && length $body;

    my $spec = $KINDS{$kind};
    unless ($spec) {
        HGLogger->error("Refusing to send unknown notice kind: $kind");
        return 0;
    }

    # Master switch. With notices off nothing leaves the host, whatever the
    # individual settings say.
    return 0 unless ($config->{NOTIFY_ENABLE} // '1') eq '1';

    # Per-kind switch.
    my $enabled = $config->{ $spec->{key} } // '0';
    return 0 unless $enabled eq '1';

    my $ident = defined $args{ident} && length $args{ident}
              ? _bound_ident($args{ident})
              : ($args{subject} // $spec->{label});

    # Cheap rejection first, so a flood of notices this process has already
    # suppressed does not take the lock once per attempt.
    return 0 if _definitely_suppressed($kind, $ident, $config);

    # Everything that might actually be sent is decided against what is on
    # disk, with the lock held for the whole read-decide-write.
    # Checked in this order, and only recorded once both have passed.
    #
    # Testing the ident and recording it are separate steps on purpose. If the
    # repeat table were written before the hourly ceiling had been consulted, a
    # notice the ceiling was about to refuse would still cost a key in the state
    # file. Block notices are on by default (LF_EMAIL_ALERT=1) and their ident
    # is the blocked address, so an attack from many sources would write one key
    # per source - none of them pruneable inside NOTIFY_REPEAT_INTERVAL, with
    # the whole file rewritten under an exclusive lock for each. The cost of
    # reporting one block would grow with the number of blocks before it, during
    # exactly the flood that produces them, in the small directory
    # tempblock.dat also lives in.
    my $allowed = _with_locked_state(sub {
        my ($state) = @_;

        return (0, 0) if _repeat_suppressed($state, $kind, $ident, $config);
        return (0, 1) unless _throttle_allowed($state, $kind, $config);
        _repeat_record($state, $kind, $ident, $config);
        return (1, 1);
    });

    return 0 unless $allowed;
    $SEEN{"$kind\0$ident"} = time();

    my $subject = $args{subject} // $spec->{label};

    # Rendering happens after the suppression checks, so a notice that is
    # going to be dropped never costs a template read.
    if ($spec->{template}) {
        my %vars = (
            HOSTNAME => hostname(),
            TIME     => scalar(localtime()),
            SUBJECT  => $subject,
            %{ $args{vars} || {} },
        );
        $body = $class->render($spec->{template}, \%vars, $body);
    }

    return _deliver($config, $subject, $body, $kind);
}

# Render one of the templates in tpl/, substituting [NAME] placeholders.
#
# A missing template is not an error: the caller supplies a plain-text
# fallback, so a partial installation still sends readable mail.
sub render {
    my ($class, $template, $vars, $fallback) = @_;

    # A template name comes from %KINDS, never from configuration or a log
    # line, but the check costs nothing and keeps it that way.
    return $fallback unless defined $template && $template =~ /^[\w.-]+$/;

    my $path = "$TEMPLATE_DIR/$template";
    unless (-f $path) {
        return $fallback;
    }

    open(my $fh, '<', $path) or return $fallback;
    my $body = do { local $/; <$fh> };
    close($fh);
    return $fallback unless defined $body && length $body;

    # One pass over the template rather than one pass per variable.
    #
    # Substituting variable by variable meant a placeholder appearing inside a
    # substituted value was expanded by a later iteration, in hash order - so a
    # log line containing "[HOSTNAME]" had it replaced. Harmless in a
    # plain-text body to the administrator, and still the wrong shape.
    #
    # An unknown placeholder is left as written rather than blanked, so a
    # template referring to a variable a caller did not pass is visible instead
    # of silently empty.
    $body =~ s/\[(\w+)\]/
        exists $vars->{$1} && defined $vars->{$1} ? $vars->{$1} : "[$1]"
    /ge;

    return $body;
}

# Hostname for subject lines, resolved once per process.
{
    my $cached;
    sub hostname {
        return $cached if defined $cached;
        $cached = eval { require Sys::Hostname; Sys::Hostname::hostname() } || 'server';
        chomp $cached;
        return $cached;
    }
}

###############################################################################
# Suppression
###############################################################################

# True when this exact notice has not been sent inside the repeat window.
#
# The window is measured from the last time the same kind and ident were sent,
# so a condition that persists - a process that will not die, an attacker that
# keeps coming back - is reported once per window rather than once per check.
# Longest ident kept verbatim before the remainder is digested.
#
# The ident goes into the persisted state file, and several callers build it
# from something the other side chooses: HGProcess uses "$user\0$cmd", and a
# command line can be megabytes. A local user on a shared host could therefore
# write an arbitrary amount into /var/lib/hostguard - the small directory
# tempblock.dat lives in, where a full filesystem makes the firewall roll a
# block back rather than record it.
#
# Truncating alone would collapse distinct notices into one, so the tail is
# replaced by a digest of itself: the key stays as distinct as it was and its
# length is bounded.
our $MAX_IDENT_LEN = 180;

sub _bound_ident {
    my ($ident) = @_;
    return $ident unless length($ident) > $MAX_IDENT_LEN;

    my $head = substr($ident, 0, $MAX_IDENT_LEN - 17);
    my $tail = substr($ident, $MAX_IDENT_LEN - 17);
    my $digest = eval { require Digest::SHA; Digest::SHA::sha256_hex($tail) };

    # A fallback that depends on the tail's contents, not only its length.
    #
    # It was sprintf('%08x', length($tail)), which is a function of length
    # alone - so any two idents sharing a head and having equal-length tails
    # collapsed to one suppression key and one notice silenced the other. The
    # branch is unreachable on a supported host, since Digest::SHA has been core
    # Perl since 5.10, but a fallback that quietly merges distinct keys is the
    # wrong thing to have written down.
    unless (defined $digest) {
        my ($h1, $h2) = (0x1505, 0x7fed);
        for my $c (unpack('C*', $tail)) {
            $h1 = (($h1 * 33) ^ $c) & 0xFFFFFFFF;
            $h2 = (($h2 * 31) + $c) & 0xFFFFFFFF;
        }
        $digest = sprintf('%08x%08x', $h1, $h2);
    }

    return $head . '~' . substr($digest, 0, 16);
}

# Largest number of idents remembered for repeat suppression.
#
# There was a prune already, but it only dropped entries older than the window,
# which bounds nothing inside it - and the window is an hour by default. The
# table is keyed on something an attacker chooses, so it needs a ceiling on
# count as well as on age, for the same reason the daemon's own tracking tables
# do. Eviction is least-recently-touched: an ident that keeps recurring keeps
# its entry and keeps being suppressed, while the one-shot addresses that would
# flood the table are what gets dropped.
our $MAX_REPEAT_KEYS = 5000;

# Whether this exact notice was sent recently enough to skip. Read-only.
sub _repeat_suppressed {
    my ($state, $kind, $ident, $config) = @_;

    my $window = _repeat_window($config);
    return 0 if $window == 0;

    my $slot = $state->{repeat}{"$kind\0$ident"};
    return 0 unless defined $slot;

    if ((time() - $slot) < $window) {
        HGLogger->debug("Suppressing repeat $kind notice for $ident");
        return 1;
    }
    return 0;
}

# Remember that this notice has been sent. Called only once it is going out.
sub _repeat_record {
    my ($state, $kind, $ident, $config) = @_;

    my $window = _repeat_window($config);
    return if $window == 0;

    my $now = time();
    $state->{repeat}{"$kind\0$ident"} = $now;

    my $table = $state->{repeat};
    return if keys %$table <= $MAX_REPEAT_KEYS;

    # Anything past the window can never suppress again, so it goes first.
    for my $k (keys %$table) {
        delete $table->{$k} if ($now - $table->{$k}) > $window;
    }
    return if keys %$table <= $MAX_REPEAT_KEYS;

    # Still over: drop the least recently touched, keeping the entry just
    # recorded. Trimmed to three quarters rather than exactly to the ceiling so
    # a table sitting at the limit is not sorted on every single insert.
    my $keep   = "$kind\0$ident";
    my $target = int($MAX_REPEAT_KEYS * 0.75);
    my @oldest = sort { $table->{$a} <=> $table->{$b} or $a cmp $b }
                 grep { $_ ne $keep } keys %$table;
    my $drop = scalar(keys %$table) - $target;
    $drop = scalar(@oldest) if $drop > scalar(@oldest);
    return if $drop <= 0;

    delete $table->{$_} for @oldest[0 .. $drop - 1];

    HGLogger->log_warn("Notice repeat table reached $MAX_REPEAT_KEYS entries; "
                     . "dropped $drop least recently seen. Some repeated "
                     . "notices may be sent again sooner than "
                     . "NOTIFY_REPEAT_INTERVAL. This is normally a sign of an "
                     . "attack from a large number of addresses.");
    return;
}

sub _repeat_window {
    my ($config) = @_;
    my $window = $config->{NOTIFY_REPEAT_INTERVAL};
    return 3600 unless defined $window && $window =~ /^\d+$/;
    return $window;
}

# True while this kind is under its ceiling for the current clock hour.
#
# A distributed attack produces one event per source address; without a
# ceiling that is one message per address. The log records the moment
# suppression starts so the gap in the mailbox is explainable.
sub _throttle_allowed {
    my ($state, $kind, $config) = @_;

    my $max = $config->{NOTIFY_MAX_PER_HOUR};
    $max = 20 unless defined $max && $max =~ /^\d+$/;
    return 1 if $max == 0;

    my $hour = int(time() / 3600);
    my $slot = $state->{hourly}{$kind};

    if (!$slot || ($slot->{hour} // -1) != $hour) {
        $state->{hourly}{$kind} = { hour => $hour, count => 0 };
        $slot = $state->{hourly}{$kind};
    }

    $slot->{count}++;

    return 1 if $slot->{count} <= $max;

    HGLogger->info("Notice limit of $max per hour reached for $kind; "
                 . "further $kind notices this hour are suppressed")
        if $slot->{count} == $max + 1;

    return 0;
}

###############################################################################
# State persistence
###############################################################################
#
# The counters decide whether a notice is sent, so they have to be right across
# every process that might send one, not merely within each.
#
# A process that read the file once, kept the table for its own lifetime and
# wrote the whole thing back would get two things wrong. The daemon runs for
# weeks and would never see anything another process wrote. And each write
# would replace the file wholesale, discarding whatever another process had
# recorded in between - so a ceiling meant to hold across the host would only
# hold within one process.
#
# Every decision now happens inside an exclusive lock: take the lock, read what
# is on disk, decide, write, release. The lock is a separate file from the
# state, because the state is replaced by rename and a lock on a file that is
# about to be replaced belongs to the old inode.

sub _lock_file { return _state_file() . '.lock' }

# Run a block with the state loaded and the lock held.
#
# The block receives the state read from disk and returns whether the notice
# may be sent. Anything it changes is written back before the lock is dropped.
# Counters used only when the lock cannot be taken. See below.
my %FALLBACK = (repeat => {}, hourly => {});
my $FALLBACK_REPORTED = 0;

sub _with_locked_state {
    my ($code) = @_;

    my $lock;
    if (sysopen($lock, _lock_file(), O_WRONLY | O_CREAT, 0600)
        && flock($lock, LOCK_EX)) {

        my $state = _read_state();
        my ($allowed, $changed) = $code->($state);
        _write_state($state) if $changed;

        close($lock);      # releases the lock
        return $allowed;
    }
    close($lock) if $lock;

    # The lock could not be taken: the data directory is missing, read-only or
    # full. Fall back to counting within this process.
    #
    # Not refusing to send. The ceiling exists to keep a flood out of a
    # mailbox, and this fallback still provides one; stopping notices outright
    # would mean a host that has just developed a disk problem also stops
    # reporting the attack that is under way. Degraded and noisy beats silent.
    unless ($FALLBACK_REPORTED++) {
        HGLogger->error("Cannot lock " . _lock_file() . ": $!. Notice limits "
                      . "are being applied per process instead of per host, so "
                      . "more mail than NOTIFY_MAX_PER_HOUR may be sent. Check "
                      . "that $HGConfig::DATA_DIR exists and is writable.");
    }

    my ($allowed) = $code->(\%FALLBACK);
    return $allowed;
}

# Read the counters from disk. A missing or unreadable file means no history,
# which is the correct starting point.
sub _read_state {
    my %state = (repeat => {}, hourly => {});

    return \%state unless -f _state_file();
    open(my $fh, '<', _state_file()) or return \%state;
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;
        my ($type, $a, $b) = split(/\t/, $line, 3);
        next unless defined $type && defined $a && defined $b;
        if ($type eq 'R') {
            next unless $b =~ /^\d+$/;
            $state{repeat}{$a} = $b;
        } elsif ($type eq 'H') {
            my ($hour, $count) = split(/:/, $b, 2);
            next unless defined $hour && defined $count;
            next unless $hour =~ /^\d+$/ && $count =~ /^\d+$/;
            $state{hourly}{$a} = { hour => $hour, count => $count };
        }
    }
    close($fh);

    return \%state;
}

# Written through a temporary file and renamed, so a process killed mid-write
# cannot leave counters that parse as garbage. Called only with the lock held.
sub _write_state {
    my ($state) = @_;

    my $out = '';
    for my $k (keys %{ $state->{repeat} }) {
        # The ident may contain anything; tabs and newlines would corrupt the
        # record, so they are folded to spaces on the way out.
        my $safe = $k;
        $safe =~ s/[\t\n]/ /g;
        $out .= "R\t$safe\t$state->{repeat}{$k}\n";
    }
    for my $k (keys %{ $state->{hourly} }) {
        my $h = $state->{hourly}{$k};
        $out .= "H\t$k\t$h->{hour}:$h->{count}\n";
    }

    eval { HGConfig::_write_atomic(_state_file(), $out); 1 }
        or HGLogger->debug("Cannot save alert state: $@");
    chmod(0600, _state_file());
}

# A cheap rejection that never touches the disk.
#
# Only ever used to suppress. Being out of date here can mean suppressing a
# notice that was in fact allowed, which is harmless; it can never mean sending
# one that should have been held, because anything that might be sent goes on
# to the locked check.
sub _definitely_suppressed {
    my ($kind, $ident, $config) = @_;

    my $window = $config->{NOTIFY_REPEAT_INTERVAL};
    $window = 3600 unless defined $window && $window =~ /^\d+$/;
    return 0 if $window == 0;

    my $seen = $SEEN{"$kind\0$ident"};
    return 0 unless defined $seen;
    return (time() - $seen) < $window ? 1 : 0;
}

# Drop what this process remembers, so the next send reads the file again.
# Used by the daemon on reload.
sub reset_state {
    %SEEN     = ();
    %FALLBACK = (repeat => {}, hourly => {});
    $FALLBACK_REPORTED = 0;
    return 1;
}

###############################################################################
# Delivery
###############################################################################

# Sub-second timing where it is available, so a five second deadline is a
# deadline rather than a rounding error.
sub _now {
    return eval { require Time::HiRes; Time::HiRes::time() } || time();
}

sub _set_nonblocking {
    my ($fh) = @_;
    my $flags = fcntl($fh, F_GETFL, 0);
    return 0 unless defined $flags;
    return fcntl($fh, F_SETFL, $flags | O_NONBLOCK) ? 1 : 0;
}

# Hand a finished message to sendmail.
#
# The message is piped rather than passed on a command line, so a subject
# built from a log line cannot become an argument. Only the recipient and
# sender come from configuration, and both are checked for the header
# injection that a newline would allow.
#
# Every step is bounded by a wall-clock deadline, which is the part that was
# missing. This was "open(my $mail, '|-')" followed by a bare close(), and
# close() on a piped handle waits for the child with no bound at all. A mailer
# that hangs - a full spool, an NFS queue that has gone away, a sendmail
# blocked on DNS - stopped the daemon indefinitely: no log read, so no new
# attack from any source noticed; no block expiry; no slot verification; no
# scheduled task. systemd went on reporting the unit active, because it was.
#
# LF_EMAIL_ALERT defaults to 1 and block_ip calls this on every new block, so
# one hang was enough. The hourly ceiling does not help with that.
#
# Setting SIGCHLD to IGNORE, as the daemon does, does not shorten the wait
# either: waitpid then blocks until every child has gone and returns -1.
#
# An explicit pipe and fork rather than open('|-'), for the reason
# HGConfig::download_capped gives: closing a handle opened that way also waits
# for the child, so the close and the reap have to be separate acts before the
# reap can escalate. _reap_child is that escalation, and it is the same one
# the downloader uses.
sub _deliver {
    my ($config, $subject, $body, $kind) = @_;

    my $to   = $config->{LF_ALERT_TO}   // 'root';
    my $from = $config->{LF_ALERT_FROM} // 'hostguard@localhost';

    for my $field ($to, $from) {
        if ($field =~ /[\r\n]/) {
            HGLogger->error("Refusing to send $kind notice: address contains a newline");
            return 0;
        }
    }

    my $host = hostname();
    $subject =~ s/[\r\n]+/ /g;

    my $sendmail = HGConfig::find_bin('sendmail');
    unless ($sendmail && -x $sendmail) {
        HGLogger->log_warn("Cannot send $kind notice: no sendmail binary found");
        return 0;
    }

    my $message = "From: $from\n"
                . "To: $to\n"
                . "Subject: HostGuard Pro [$host] $subject\n"
                . "Content-Type: text/plain; charset=UTF-8\n"
                . "Auto-Submitted: auto-generated\n"
                . "\n"
                . $body;
    $message .= "\n" unless $message =~ /\n\z/;

    my ($rd, $wr);
    unless (pipe($rd, $wr)) {
        HGLogger->log_warn("Cannot create a pipe to send $kind notice: $!");
        return 0;
    }

    # A mailer that exits early would otherwise deliver SIGPIPE, whose default
    # action is to kill the daemon. A failed write is an undelivered notice.
    local $SIG{PIPE} = 'IGNORE';

    # Reaping needs a status to collect, and the daemon has asked the kernel to
    # discard exactly that by setting SIGCHLD to IGNORE. Restored for the
    # length of this call, and only this call.
    local $SIG{CHLD} = 'DEFAULT';

    my $pid = fork();
    unless (defined $pid) {
        close($rd);
        close($wr);
        HGLogger->log_warn("Cannot fork to send $kind notice: $!");
        return 0;
    }
    if ($pid == 0) {
        close($wr);
        open(STDIN, '<&', $rd);
        close($rd);
        open(STDOUT, '>', '/dev/null');
        open(STDERR, '>', '/dev/null');
        # _exit rather than exit: this process shares the parent's buffers,
        # and running the parent's exit handlers here would flush them.
        exec { $sendmail } $sendmail, '-t', '-oi' or POSIX::_exit(127);
    }

    # The parent's copy of the read end has to go, or a mailer that exits never
    # sees end of file on its stdin.
    close($rd);

    my $sent     = 0;
    my $deadline = _now() + $DELIVER_TIMEOUT;
    my $stalled  = 0;

    if (_set_nonblocking($wr)) {
        while ($sent < length($message)) {
            my $left = $deadline - _now();
            if ($left <= 0) { $stalled = 1; last }

            my $vec = '';
            vec($vec, fileno($wr), 1) = 1;
            my $ready = select(undef, my $w = $vec, undef, $left);
            unless (defined $ready && $ready > 0) {
                next if !defined $ready && $! == EINTR;
                $stalled = 1;
                last;
            }

            my $n = syswrite($wr, $message, length($message) - $sent, $sent);
            unless (defined $n) {
                next if $! == EWOULDBLOCK || $! == EAGAIN || $! == EINTR;
                HGLogger->log_warn("Cannot write the $kind notice to "
                                 . "$sendmail: $!");
                last;
            }
            last if $n == 0;
            $sent += $n;
        }
    } else {
        # Without a non-blocking descriptor there is no way to bound the write,
        # and an unbounded one is what this exists to remove. A blocking write
        # of a message this size will almost always complete inside the pipe
        # buffer, so it is attempted once and the deadline is enforced by the
        # reap below rather than abandoned altogether.
        HGLogger->debug("Cannot set the pipe to $sendmail non-blocking; "
                      . "writing the $kind notice without a write deadline");
        $sent = (print $wr $message) ? length($message) : 0;
    }

    # Closing the write end is what tells sendmail the message is complete, so
    # it happens before the wait rather than after it.
    close($wr);

    # A message we could not finish writing is a truncated mail, so the mailer
    # is stopped rather than waited for.
    my ($reaped, $status) =
        HGConfig::_reap_child($pid, $stalled ? 0 : $DELIVER_GRACE);

    if ($stalled) {
        HGLogger->log_warn("The $kind notice was abandoned after "
                         . "${DELIVER_TIMEOUT}s: $sendmail accepted $sent of "
                         . length($message) . " bytes and then stopped reading. "
                         . "The mail was not sent. Check the mail queue - a "
                         . "mailer that blocks here would otherwise stop this "
                         . "daemon reading logs.");
        return 0;
    }
    unless ($reaped) {
        HGLogger->log_warn("The $kind notice was handed to $sendmail, but it "
                         . "could not be stopped or collected. The mail may or "
                         . "may not have been sent.");
        return 0;
    }
    # A wait status carries two different things and they need asking about
    # separately.
    #
    # The exit code is in bits 8-15 and the signal that killed the child, if
    # one did, is in the low seven. Testing only ">> 8" therefore reads a child
    # killed by a signal as a clean exit: SIGTERM leaves $? as 15, and 15 >> 8
    # is 0. That is exactly the child _reap_child produces when it escalates,
    # which is the case this whole rework exists to handle - so the one path
    # where the mailer had to be killed was the one reported as "Notice sent".
    if (defined $status && $status > 0) {
        if (my $signal = $status & 0x7f) {
            HGLogger->log_warn("$sendmail did not finish within "
                             . "${DELIVER_GRACE}s and was stopped (signal "
                             . "$signal); the $kind notice was probably not "
                             . "delivered.");
            return 0;
        }
        if (my $exit = $status >> 8) {
            HGLogger->log_warn("$sendmail exited with $exit; the $kind notice "
                             . "was probably not delivered.");
            return 0;
        }
    }

    # -1 means the child was collected by something else and no status was
    # available. The message was written and the pipe closed, so this is not a
    # failure - but it is not a confirmed delivery either, and saying so in the
    # log costs nothing.
    if (defined $status && $status < 0) {
        HGLogger->debug("No exit status was available for $sendmail; the $kind "
                      . "notice was written but delivery is unconfirmed.");
    }

    HGLogger->info("Notice sent to $to: $subject");
    return 1;
}

1;
