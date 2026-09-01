package HGSystem;
###############################################################################
# HostGuard Pro - Host Condition
# /usr/local/hostguard/lib/HGSystem.pm
#
# Everything HostGuard Pro reports about the state of the host itself, rather
# than about traffic reaching it:
#
#   check_load      - sustained load average, reported once it has stayed high
#                     rather than the moment it spikes
#   security_check  - a review of the settings that decide how exposed the
#                     host is, run on demand
#   statistics      - the sampled series behind the graphs in the WHM
#                     interface
#
# The security check reports; it never changes anything. Every finding names
# the file that holds the setting, so an administrator can weigh it against
# how the host is actually used. A finding is a question worth answering, not
# a fault.
###############################################################################
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
use HGConfig;
use HGLogger;
use HGAlert;
use HGProcess;

sub _load_state_file { return "$HGConfig::DATA_DIR/load.state" }
sub _stats_file      { return "$HGConfig::DATA_DIR/stats.rrd" }

# How many samples the statistics file keeps. At one sample a minute this is
# roughly a day, which is the span the graphs cover.
our $STATS_SAMPLES = 1440;

###############################################################################
# Load average
###############################################################################

# Report a load average that has stayed above LOAD_LIMIT for LOAD_INTERVAL
# seconds.
#
# The duration is the whole point. Load spikes constantly on a busy host - a
# backup, a mail queue run, a package update - and alerting on the spike
# trains an administrator to ignore the alert. What matters is load that does
# not come back down.
sub check_load {
    my ($class, $config, %opt) = @_;

    return 0 unless ($config->{LOAD_ALERT} // '0') eq '1';

    my $limit = $config->{LOAD_LIMIT} // 0;
    return 0 unless $limit =~ /^\d+(?:\.\d+)?$/ && $limit > 0;

    my $required = $config->{LOAD_INTERVAL} // 300;
    $required = 300 unless $required =~ /^\d+$/ && $required > 0;

    my ($one, $five, $fifteen) = HGProcess::loadavg();
    my $now = time();

    # The moment the load first went over, or 0 while it is under.
    my $since = 0;
    if (open(my $fh, '<', _load_state_file())) {
        my $v = <$fh>;
        close($fh);
        chomp $v if defined $v;
        $since = $v if defined $v && $v =~ /^\d+$/;
    }

    if ($one <= $limit) {
        # Back under: forget the episode so the next one is timed afresh.
        unlink(_load_state_file()) if $since;
        return 0;
    }

    unless ($since) {
        # Checked, because the whole alert depends on it.
        #
        # The result was discarded. On a read-only or full filesystem the start
        # time was never recorded, so $since was 0 on every pass, the elapsed
        # time never reached LOAD_INTERVAL, and the load alert silently never
        # fired - during exactly the incident it exists to report.
        unless (eval { HGConfig::_write_atomic(_load_state_file(), "$now\n"); 1 }) {
            my $err = $@ || 'unknown error';
            chomp $err;
            HGLogger->error("Load average $one is above $limit, but the start "
                          . "of the episode could not be recorded ($err), so "
                          . "no load alert can be raised for it. Check that "
                          . "$HGConfig::DATA_DIR is writable.");
            return 0;
        }
        chmod(0600, _load_state_file());
        HGLogger->debug("Load average $one is above $limit; timing the episode");
        return 0;
    }

    my $elapsed = $now - $since;
    return 0 if $elapsed < $required;

    HGLogger->log_warn("Load average has been above $limit for ${elapsed}s "
                     . "(currently $one)");

    my @top = sort { $b->{pcpu} <=> $a->{pcpu} } HGProcess->snapshot();
    @top = @top[0 .. 9] if @top > 10;

    # Built once and used by both the template and the plain-text fallback.
    my $top_list = sprintf("  %-8s %-12s %6s %10s  %s\n",
                           'PID', 'USER', 'CPU%', 'RSS(KB)', 'COMMAND');
    for my $p (@top) {
        my $cmd = length($p->{cmd}) > 60 ? substr($p->{cmd}, 0, 57) . '...' : $p->{cmd};
        $top_list .= sprintf("  %-8s %-12s %6s %10s  %s\n",
                             $p->{pid}, $p->{user}, $p->{pcpu}, $p->{rss}, $cmd);
    }

    my $body = "Load average:  $one (1m), $five (5m), $fifteen (15m)\n"
             . "Limit:         $limit\n"
             . "Above limit:   ${elapsed}s (reporting after ${required}s)\n\n"
             . "Highest CPU processes\n\n"
             . $top_list;

    HGAlert->send(
        kind    => 'load_average',
        config  => $config,
        subject => "Load average has been above $limit for ${elapsed}s",
        # Keyed on the episode, so one sustained period of high load produces
        # one message however long it lasts.
        ident   => "load\0$since",
        vars    => {
            LOAD1     => $one,
            LOAD5     => $five,
            LOAD15    => $fifteen,
            LIMIT     => $limit,
            ELAPSED   => $elapsed,
            REQUIRED  => $required,
            PROCESSES => $top_list,
        },
        body    => $body,
    ) unless $opt{quiet};

    return 1;
}

###############################################################################
# Security check
###############################################################################

# Review the host's exposed settings.
#
# Returns a list of findings, each with a level, a heading, what was found and
# where to change it. Nothing is modified.
sub security_check {
    my ($class, $config) = @_;

    my @findings;

    my $add = sub {
        my ($level, $title, $detail, $where) = @_;
        push @findings, {
            level  => $level,
            title  => $title,
            detail => $detail,
            where  => $where // '',
        };
    };

    # --- HostGuard Pro's own configuration ---------------------------------

    if (($config->{TESTING} // '0') eq '1') {
        $add->('high', 'Firewall is in testing mode',
               'TESTING is set to 1, so the firewall clears itself every '
             . ($config->{TESTING_INTERVAL} // 5) . ' minutes and the daemon '
             . 'will not start. The host is unprotected between clears.',
               '/etc/hostguard/hostguard.conf');
    }

    if (($config->{LF_DAEMON} // '1') ne '1') {
        $add->('high', 'Login failure daemon is disabled',
               'LF_DAEMON is 0, so no authentication log is being watched and '
             . 'no address will be blocked automatically.',
               '/etc/hostguard/hostguard.conf');
    }

    if (($config->{IPV6} // '0') ne '1') {
        my $has_v6 = 0;
        if (open(my $fh, '<', '/proc/net/if_inet6')) {
            while (my $line = <$fh>) {
                # Ignore the loopback address, which every host has.
                next if $line =~ /^0{31}1\s/;
                $has_v6 = 1;
                last;
            }
            close($fh);
        }
        $add->('high', 'IPv6 is configured but not filtered',
               'The host has a global IPv6 address and IPV6 is 0, so ip6tables '
             . 'rules are not built. Every service reachable over IPv6 is '
             . 'unfiltered.',
               '/etc/hostguard/hostguard.conf')
            if $has_v6;
    }

    if (($config->{RESTRICT_UI} // '1') eq '0') {
        $add->('medium', 'WHM interface can write the configuration',
               'RESTRICT_UI is 0, so the firewall configuration can be edited '
             . 'from the browser. Anyone who reaches an authenticated WHM '
             . 'session can change the firewall.',
               '/etc/hostguard/hostguard.conf');
    }

    my $temp = $config->{LF_TEMP_BLOCK_DURATION} // 3600;
    $add->('low', 'Temporary blocks are very short',
           "LF_TEMP_BLOCK_DURATION is ${temp}s. An attacker who waits that long "
         . 'between attempts is never held for meaningfully long.',
           '/etc/hostguard/hostguard.conf')
        if $temp =~ /^\d+$/ && $temp < 300;

    # --- Exposed ports -----------------------------------------------------

    my @tcp_in = split(/,/, $config->{TCP_IN} // '');
    my %risky = (
        23    => 'telnet, which carries credentials in clear text',
        512   => 'rexec',
        513   => 'rlogin',
        514   => 'rsh',
        3306  => 'MySQL, which is rarely meant to be reachable from outside',
        5432  => 'PostgreSQL, which is rarely meant to be reachable from outside',
        6379  => 'Redis, which has no authentication by default',
        11211 => 'memcached, which has no authentication',
        27017 => 'MongoDB',
    );
    for my $port (@tcp_in) {
        $port =~ s/\s//g;
        next unless exists $risky{$port};
        $add->('high', "Port $port is open to the internet",
               "TCP_IN includes $port: $risky{$port}.",
               '/etc/hostguard/hostguard.conf');
    }

    # --- SSH ---------------------------------------------------------------

    my %sshd = _sshd_config();
    if (-d '/etc/ssh/sshd_config.d' && !%sshd) {
        $add->('medium', 'SSH configuration could not be read',
               'This host has /etc/ssh/sshd_config.d, but no setting could be '
             . 'read from sshd_config or its includes, so none of the SSH '
             . 'findings below can be trusted.',
               '/etc/ssh/sshd_config');
    }
    if (($sshd{permitrootlogin} // '') =~ /^yes$/i) {
        $add->('high', 'Root may log in over SSH with a password',
               'PermitRootLogin is yes. Every brute-force attempt against this '
             . 'host has a known account name to aim at.',
               '/etc/ssh/sshd_config');
    }
    if (($sshd{passwordauthentication} // '') =~ /^yes$/i) {
        $add->('low', 'SSH accepts password authentication',
               'PasswordAuthentication is yes. Key-only authentication removes '
             . 'brute forcing as a category of risk, at the cost of key '
             . 'management.',
               '/etc/ssh/sshd_config');
    }
    if (($sshd{permitemptypasswords} // '') =~ /^yes$/i) {
        $add->('high', 'SSH accepts empty passwords',
               'PermitEmptyPasswords is yes.',
               '/etc/ssh/sshd_config');
    }
    my $ssh_port = $sshd{port} // '22';
    if ($ssh_port eq '22' && ($config->{SSH_PORT} // '22') eq '22') {
        $add->('low', 'SSH is on the default port',
               'Moving SSH off port 22 does not make it more secure, but it '
             . 'does remove most of the automated noise from the logs.',
               '/etc/ssh/sshd_config');
    }

    # --- File permissions --------------------------------------------------

    for my $path ('/etc/hostguard/hostguard.conf', '/etc/hostguard/cluster.key') {
        next unless -f $path;
        my @st = stat($path);
        next unless @st;
        my $mode = $st[2] & 07777;
        $add->('high', "$path is readable by other users",
               sprintf('Mode is %04o; it should be 0600.', $mode),
               $path)
            if $mode & 0077;
    }

    for my $dir (@HGProcess::TEMP_DIRS) {
        next unless -d $dir;
        my @st = stat($dir);
        next unless @st;
        # A world-writable scratch directory is correct; a missing sticky bit
        # on one is not, because it lets any user remove another's files.
        $add->('high', "$dir is world-writable without the sticky bit",
               'Any user can delete or replace another user\'s files there.',
               $dir)
            if ($st[2] & 0002) && !($st[2] & 01000);
    }

    # --- Subsystems that are switched off ----------------------------------

    my %off = (
        PROC_SCAN        => 'Suspicious process reporting',
        FILE_SCAN        => 'Suspicious file reporting',
        INTEGRITY_ENABLE => 'System binary integrity monitoring',
        SCAN_ENABLE      => 'Port scan detection',
        RELAY_TRACK      => 'Outbound mail tracking',
    );
    for my $key (sort keys %off) {
        next if ($config->{$key} // '0') eq '1';
        $add->('low', "$off{$key} is off",
               "$key is 0. It is off by default; turn it on once the host's "
             . 'normal behaviour is known.',
               '/etc/hostguard/hostguard.conf');
    }

    return @findings;
}

# Read the settings the security check cares about from sshd_config.
#
# Two things about this had to change, and both made the check report a host as
# clean when it was not.
#
# Include is followed. AlmaLinux 9, Rocky 9 and RHEL 9 all ship an sshd_config
# whose first directive is "Include /etc/ssh/sshd_config.d/*.conf", and that is
# where a modern host actually sets PermitRootLogin and
# PasswordAuthentication. Reading only the top-level file meant the check
# looked at a file that no longer holds the answers and reported nothing wrong.
#
# And the first occurrence wins, not the last. That is sshd's own rule for
# these keywords, and getting it backwards produced the opposite error on a
# file with a repeated setting: reporting "PermitRootLogin yes" on a host where
# sshd was using the "no" that came first.
sub _sshd_config {
    my %conf;
    _sshd_read('/etc/ssh/sshd_config', \%conf, 0);
    return %conf;
}

sub _sshd_read {
    my ($file, $conf, $depth) = @_;

    # Include can nest. sshd itself allows it; a bound here stops a loop
    # created by a mistake from becoming an unbounded recursion.
    return if $depth > 8;
    return unless -f $file;

    open(my $fh, '<', $file) or do {
        HGLogger->debug("Security check cannot read $file: $!");
        return;
    };
    my @lines = <$fh>;
    close($fh);

    for my $line (@lines) {
        chomp $line;
        $line =~ s/^\s+//;
        next if $line =~ /^#/ || $line !~ /\S/;
        next unless $line =~ /^(\w+)\s+(.+?)\s*$/;
        my ($key, $value) = (lc $1, $2);

        # Processed where it appears, so the ordering sshd sees is the ordering
        # this sees.
        if ($key eq 'include') {
            for my $pattern (split(/\s+/, $value)) {
                $pattern =~ s/^["']//;
                $pattern =~ s/["']$//;
                next unless length $pattern;
                # A relative pattern is resolved against /etc/ssh, as sshd
                # resolves it.
                $pattern = "/etc/ssh/$pattern" unless $pattern =~ m{^/};
                for my $inc (sort glob($pattern)) {
                    _sshd_read($inc, $conf, $depth + 1);
                }
            }
            next;
        }

        # First occurrence wins.
        $conf->{$key} = $value unless exists $conf->{$key};
    }
    return;
}

# Run the check and send its findings, for the scheduled run.
sub report_security {
    my ($class, $config, %opt) = @_;
    return 0 unless ($config->{SECURITY_ALERT} // '0') eq '1';

    my @findings = $class->security_check($config);
    my @serious  = grep { $_->{level} ne 'low' } @findings;
    return 0 unless @serious;

    my $body = "Security check findings\n\n";
    for my $f (@serious) {
        $body .= uc($f->{level}) . ": $f->{title}\n"
               . "  $f->{detail}\n"
               . ($f->{where} ? "  Setting: $f->{where}\n" : '')
               . "\n";
    }
    $body .= scalar(@findings) - scalar(@serious)
           . " further low-severity finding(s) are shown in WHM.\n"
        if @findings > @serious;

    HGAlert->send(
        kind    => 'security',
        config  => $config,
        subject => scalar(@serious) . " security check finding(s)",
        ident   => join(',', map { $_->{title} } @serious),
        vars    => {
            COUNT    => scalar(@serious),
            FINDINGS => join('', map {
                            uc($_->{level}) . ": $_->{title}\n"
                          . "  $_->{detail}\n"
                          . ($_->{where} ? "  Setting: $_->{where}\n" : '')
                          . "\n"
                        } @serious),
        },
        body    => $body,
    ) unless $opt{quiet};

    return scalar(@serious);
}

###############################################################################
# Statistics
###############################################################################

# Append one sample of the host's condition.
#
# Kept as a plain fixed-length ring of text lines rather than in a database:
# the series is small, the graphs are simple, and a text file can be read by
# anything without a library.
sub record_sample {
    my ($class, $config, %opt) = @_;
    return 0 unless ($config->{STATS_ENABLE} // '1') eq '1';

    my ($one, $five, $fifteen) = HGProcess::loadavg();
    my ($mem_total, $mem_free)  = _meminfo();
    my ($cpu_used)              = _cpu_percent();
    my $procs                   = _process_count();

    my $sample = join('|',
        time(), $one, $five, $fifteen,
        $mem_total, $mem_free,
        defined $cpu_used ? sprintf('%.1f', $cpu_used) : '',
        $procs,
        $opt{blocks} // 0,
    );

    my @lines;
    if (open(my $fh, '<', _stats_file())) {
        flock($fh, LOCK_SH);
        @lines = <$fh>;
        close($fh);
    }
    push @lines, "$sample\n";
    shift @lines while @lines > $STATS_SAMPLES;

    eval { HGConfig::_write_atomic(_stats_file(), join('', @lines)); 1 }
        or HGLogger->debug("Cannot record statistics sample: $@");
    chmod(0600, _stats_file());

    return 1;
}

# Read the series back, oldest first.
sub statistics {
    my ($class, $limit) = @_;

    my @rows;
    return @rows unless -f _stats_file();

    open(my $fh, '<', _stats_file()) or return @rows;
    flock($fh, LOCK_SH);
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;
        my ($ts, $one, $five, $fifteen, $mem_total, $mem_free, $cpu, $procs, $blocks)
            = split(/\|/, $line);
        next unless defined $ts && $ts =~ /^\d+$/;
        push @rows, {
            time      => $ts,
            load1     => $one       // 0,
            load5     => $five      // 0,
            load15    => $fifteen   // 0,
            mem_total => $mem_total // 0,
            mem_free  => $mem_free  // 0,
            mem_used  => ($mem_total // 0) - ($mem_free // 0),
            cpu       => (defined $cpu && length $cpu) ? $cpu : undef,
            procs     => $procs     // 0,
            blocks    => $blocks    // 0,
        };
    }
    close($fh);

    if ($limit && @rows > $limit) {
        @rows = @rows[ @rows - $limit .. $#rows ];
    }

    return @rows;
}

# Total and available memory in kilobytes.
#
# MemAvailable is used where the kernel provides it: MemFree alone understates
# what is usable, because it counts reclaimable cache as taken.
sub _meminfo {
    my ($total, $free) = (0, 0);
    open(my $fh, '<', '/proc/meminfo') or return (0, 0);
    my $memfree = 0;
    while (my $line = <$fh>) {
        $total   = $1 if $line =~ /^MemTotal:\s+(\d+)/;
        $memfree = $1 if $line =~ /^MemFree:\s+(\d+)/;
        $free    = $1 if $line =~ /^MemAvailable:\s+(\d+)/;
    }
    close($fh);
    $free = $memfree unless $free;
    return ($total, $free);
}

# CPU busy percentage since the previous call.
#
# The first call has nothing to compare against and returns undef, which the
# sample records as an empty field rather than as a misleading zero.
{
    my @previous;
    sub _cpu_percent {
        open(my $fh, '<', '/proc/stat') or return undef;
        my $line = <$fh>;
        close($fh);
        return undef unless defined $line && $line =~ /^cpu\s+(.+)$/;

        my @now = split(/\s+/, $1);
        return undef unless @now >= 4;

        unless (@previous) {
            @previous = @now;
            return undef;
        }

        my ($total, $idle) = (0, 0);
        for my $i (0 .. $#now) {
            my $delta = ($now[$i] // 0) - ($previous[$i] // 0);
            $delta = 0 if $delta < 0;
            $total += $delta;
            # Fields four and five are idle and iowait.
            $idle += $delta if $i == 3 || $i == 4;
        }
        @previous = @now;

        return undef unless $total > 0;
        return (($total - $idle) / $total) * 100;
    }
}

sub _process_count {
    opendir(my $dh, '/proc') or return 0;
    my $count = grep { /^\d+$/ } readdir($dh);
    closedir($dh);
    return $count;
}

1;
