package HGProcess;
###############################################################################
# HostGuard Pro - Process and Temporary File Monitor
# /usr/local/hostguard/lib/HGProcess.pm
#
# Watches what is running and what has been dropped in the world-writable
# directories, which together are how a compromised account usually shows
# itself before anything else does.
#
# Four checks, each independently switchable:
#
#   scan_processes   - processes whose command line, executable path or
#                      deleted-binary state matches a known exploit shape
#   check_user_procs - accounts running more processes than they should
#   check_usage      - processes above a CPU or memory ceiling, optionally
#                      terminated
#   scan_temp_files  - executables and scripts in /tmp and its neighbours
#
# Everything is read from /proc directly rather than by parsing ps(1) output,
# so a process cannot hide behind a crafted argv and there is no command line
# to quote. System accounts and an administrator-supplied exception list are
# honoured throughout.
###############################################################################
use strict;
use warnings;
use HGConfig;
use HGLogger;
use HGAlert;

# Directories that any user may write to, and where a dropped payload is
# therefore worth reporting.
our @TEMP_DIRS = qw(/tmp /var/tmp /dev/shm /run/shm);

# Most individual notices one scan will attempt.
#
# The findings loops sent one notice per hit with no bound, and a hit is
# something an unprivileged local user creates: 5,000 files in /tmp named
# .a1.sh upwards is 5,000 HGAlert->send calls, each of which takes an
# exclusive lock, reads the state file and writes it back - because the hourly
# counter has to persist even when the notice itself is refused. So
# NOTIFY_MAX_PER_HOUR bounded the mail and nothing bounded the work, on the
# daemon's single main loop, while no log was being read.
#
# Past this many, one summary notice names the count instead. That is also more
# use to an operator than five thousand separate messages.
our $MAX_NOTICES_PER_SCAN = 20;

# Command line shapes that are worth a second look.
#
# None of these is proof of anything on its own - an administrator may well
# run a listener on purpose - so every hit is reported rather than acted on.
our @SUSPICIOUS = (
    [ 'reverse shell',        qr{(?:bash|sh|nc|ncat|netcat)\b.*(?:-e\s*/bin/(?:ba)?sh|>&\s*/dev/tcp/)} ],
    [ 'dev/tcp redirection',  qr{/dev/(?:tcp|udp)/\d} ],
    [ 'listener',             qr{\b(?:nc|ncat|netcat)\b.*\s-l} ],
    [ 'interpreter one-liner',qr{\b(?:perl|python[\d.]*|ruby|php)\b\s+-e\s} ],
    [ 'remote fetch to shell',qr{\b(?:curl|wget)\b[^|]*\|\s*(?:ba)?sh} ],
    [ 'mail injector',        qr{\bsendmail\b.*-f.*\@} ],
    [ 'known scanner',        qr{\b(?:masscan|zmap|nmap)\b} ],
    [ 'password cracker',     qr{\b(?:john|hashcat|hydra|medusa)\b} ],
    [ 'crypto miner',         qr{\b(?:xmrig|minerd|cpuminer|cgminer|ethminer|nicehash)\b} ],
    [ 'mining pool address',  qr{\bstratum\+tcp://} ],
    [ 'obfuscated payload',   qr{\b(?:base64\s+-d|eval\s*\(\s*base64_decode)} ],
    [ 'raw memory access',    qr{/dev/(?:mem|kmem)\b} ],
);

# Accounts whose processes are never counted or reported. These are the
# service accounts that legitimately run many long-lived processes.
our @SYSTEM_USERS = qw(
    root daemon bin sys sync games man lp mail news uucp proxy
    nobody nscd dbus systemd-network systemd-resolve polkitd chrony
    named mysql postgres redis memcached mailnull nagios munin
    apache httpd nginx exim dovecot dovenull cpanel cpanelrrdtool
    cpaneleximfilter cpaneleximscanner cpanellogin cpanelphpmyadmin
    cpanelphppgadmin cpanelroundcube cpanelconnecttrack cpanelanalytics
);

###############################################################################
# Process table
###############################################################################

# Read every process from /proc.
#
# Returns a list of hashrefs: pid, uid, user, exe, cmd, rss (KB), etime
# (seconds), pcpu (percent of one core over the process lifetime) and deleted,
# a flag set when the running executable has been unlinked from disk.
#
# A process that exits while it is being read simply disappears from the
# result; every read is guarded because /proc entries vanish under us.
sub snapshot {
    my ($class) = @_;

    my @procs;
    opendir(my $dh, '/proc') or do {
        HGLogger->log_warn("Cannot read /proc: $!");
        return @procs;
    };
    my @pids = grep { /^\d+$/ } readdir($dh);
    closedir($dh);

    my $clock = _clock_ticks();
    my $uptime = _uptime();

    for my $pid (@pids) {
        my $p = _read_proc($pid, $clock, $uptime);
        push @procs, $p if $p;
    }

    return @procs;
}

# Read one process from /proc, in the shape snapshot() returns.
#
# Separated out so the check that runs immediately before a signal can re-read
# a single entry rather than walking every process again.
sub _read_proc {
    my ($pid, $clock, $uptime) = @_;
    $clock  ||= _clock_ticks();
    $uptime ||= _uptime();

    my $dir = "/proc/$pid";

    my @st = stat($dir) or return undef;
    my $uid = $st[4];

    my $cmd = _slurp("$dir/cmdline");
    return undef unless defined $cmd;
    # cmdline separates arguments with NULs; the kernel leaves a trailing
    # one, which would otherwise show up in reports.
    $cmd =~ s/\0+$//;
    $cmd =~ tr/\0/ /;

    # A kernel thread has an empty cmdline. It cannot be a dropped payload,
    # so it is skipped rather than reported with a bare name.
    return undef unless length $cmd;

    my $exe = readlink("$dir/exe");
    my $deleted = 0;
    if (defined $exe && $exe =~ s/\s\(deleted\)$//) {
        $deleted = 1;
    }
    $exe = '' unless defined $exe;

    my ($rss, $utime, $stime, $starttime) = (0, 0, 0, 0);
    if (my $stat = _slurp("$dir/stat")) {
        # The second field is the command in parentheses and may itself
        # contain spaces or parentheses, so the split starts after the
        # final closing parenthesis rather than at the second field.
        my $rest = $stat;
        $rest =~ s/^\d+\s+\(.*\)\s+//s;
        my @f = split(/\s+/, $rest);
        # Fields are offset by two: state is index 0 here, which is field
        # three in proc(5).
        $utime     = $f[11] // 0;
        $stime     = $f[12] // 0;
        $starttime = $f[19] // 0;
        $rss       = (($f[21] // 0) * _page_size()) / 1024;
    }

    my $etime = 0;
    if ($clock && $uptime) {
        $etime = $uptime - ($starttime / $clock);
        $etime = 0 if $etime < 0;
    }

    my $pcpu = 0;
    if ($clock && $etime > 0) {
        $pcpu = ((($utime + $stime) / $clock) / $etime) * 100;
    }

    return {
        pid     => $pid,
        uid     => $uid,
        user    => _uid_to_name($uid),
        exe     => $exe,
        cmd     => $cmd,
        rss     => int($rss),
        etime   => int($etime),
        pcpu    => sprintf('%.1f', $pcpu),
        deleted => $deleted,
        # Clock ticks since boot at which this process started. Together
        # with the pid it identifies the process: the kernel reuses pids,
        # but a reused one cannot have the same start time.
        start   => $starttime,
    };
}

###############################################################################
# Suspicious process reporting
###############################################################################

# Report processes matching a known exploit shape, or running from a binary
# that has been deleted or lives in a world-writable directory.
#
# Nothing is ever terminated here. A false positive that killed a process
# would be worse than the report it replaced, so this check only ever tells
# the administrator what it found.
sub scan_processes {
    my ($class, $config, %opt) = @_;
    return 0 unless ($config->{PROC_SCAN} // '0') eq '1';

    my @exceptions = _exceptions($config);
    my $ignore_sys = ($config->{PROC_IGNORE_SYSTEM} // '1') eq '1';
    my @found;

    for my $p ($class->snapshot()) {
        next if $ignore_sys && _is_system_user($p->{user});
        next if _excepted($p, \@exceptions);

        my @reasons;

        for my $rule (@SUSPICIOUS) {
            my ($label, $re) = @$rule;
            push @reasons, $label if $p->{cmd} =~ $re;
        }

        # A process whose executable has been unlinked is the classic shape of
        # a payload that deleted itself after starting.
        push @reasons, 'running from a deleted binary'
            if $p->{deleted} && !_is_system_user($p->{user});

        # Anything executing out of a directory every user can write to.
        if (length $p->{exe}) {
            for my $dir (@TEMP_DIRS) {
                if (index($p->{exe}, "$dir/") == 0) {
                    push @reasons, "running from $dir";
                    last;
                }
            }
        }

        next unless @reasons;
        push @found, { proc => $p, reasons => \@reasons };
    }

    return 0 unless @found;

    my $notices = 0;
    for my $hit (@found) {
        my $p = $hit->{proc};
        my $why = join(', ', @{ $hit->{reasons} });
        HGLogger->log_warn("Suspicious process: pid=$p->{pid} user=$p->{user} "
                         . "($why) $p->{cmd}");

        if (++$notices > $MAX_NOTICES_PER_SCAN) {
            _summarise_scan('process', $config, scalar(@found),
                            $MAX_NOTICES_PER_SCAN) unless $opt{quiet};
            last;
        }

        HGAlert->send(
            kind    => 'process',
            config  => $config,
            subject => "Suspicious process by $p->{user}",
            # Keyed on user and command rather than pid, so a process that is
            # restarted in a loop does not generate a message per restart.
            ident   => "$p->{user}\0$p->{cmd}",
            vars    => _proc_vars($p, $why),
            body    => _proc_report($p, $why),
        ) unless $opt{quiet};
    }

    return scalar(@found);
}

###############################################################################
# Per-user process counts
###############################################################################

# Report accounts running more than PROC_USER_LIMIT processes.
#
# A shared host has a normal working range per account; a sudden multiple of
# it is either a runaway script or a fork bomb, and both want looking at.
sub check_user_procs {
    my ($class, $config, %opt) = @_;

    my $limit = $config->{PROC_USER_LIMIT} // 0;
    return 0 unless $limit =~ /^\d+$/ && $limit > 0;

    my $ignore_sys = ($config->{PROC_IGNORE_SYSTEM} // '1') eq '1';
    my %count;
    my %sample;

    for my $p ($class->snapshot()) {
        next if $ignore_sys && _is_system_user($p->{user});
        $count{ $p->{user} }++;
        $sample{ $p->{user} } //= $p->{cmd};
    }

    my $reported = 0;
    for my $user (sort keys %count) {
        next if $count{$user} <= $limit;
        $reported++;

        HGLogger->log_warn("User $user is running $count{$user} processes "
                         . "(limit $limit)");

        HGAlert->send(
            kind    => 'proc_count',
            config  => $config,
            subject => "$user is running $count{$user} processes",
            ident   => $user,
            vars    => {
                USER    => $user,
                COUNT   => $count{$user},
                LIMIT   => $limit,
                EXAMPLE => $sample{$user},
            },
            body    => "Account:   $user\n"
                     . "Processes: $count{$user}\n"
                     . "Limit:     $limit\n"
                     . "Example:   $sample{$user}\n\n"
                     . "This is a report only; no process has been terminated.\n",
        ) unless $opt{quiet};
    }

    return $reported;
}

###############################################################################
# Resource usage
###############################################################################

# Report, and optionally terminate, processes over a CPU or memory ceiling.
#
# A process is only considered once it has been running for PROC_USAGE_TIME
# seconds. Almost everything spikes at startup - a compile, an archive, a
# backup - and reporting those would train an administrator to ignore the
# whole check.
#
# Termination is off by default and, when enabled, sends TERM and leaves the
# process to exit on its own. HostGuard Pro does not send KILL: a process that
# ignores TERM is a decision for a person, not for a monitor.
sub check_usage {
    my ($class, $config, %opt) = @_;
    return 0 unless ($config->{PROC_USAGE_CHECK} // '0') eq '1';

    my $cpu_limit = $config->{PROC_USAGE_CPU}  // 0;
    my $mem_limit = $config->{PROC_USAGE_MEM}  // 0;
    my $min_time  = $config->{PROC_USAGE_TIME} // 300;
    my $terminate = ($config->{PROC_USAGE_KILL} // '0') eq '1';

    $cpu_limit = 0   unless $cpu_limit =~ /^\d+(?:\.\d+)?$/;
    $mem_limit = 0   unless $mem_limit =~ /^\d+$/;
    $min_time  = 300 unless $min_time  =~ /^\d+$/;
    return 0 unless $cpu_limit > 0 || $mem_limit > 0;

    my @exceptions = _exceptions($config);
    my $ignore_sys = ($config->{PROC_IGNORE_SYSTEM} // '1') eq '1';
    my $reported   = 0;

    for my $p ($class->snapshot()) {
        next if $ignore_sys && _is_system_user($p->{user});
        next if _excepted($p, \@exceptions);
        next if $p->{etime} < $min_time;

        my @over;
        push @over, "CPU $p->{pcpu}% (limit $cpu_limit%)"
            if $cpu_limit > 0 && $p->{pcpu} > $cpu_limit;
        push @over, "memory $p->{rss}KB (limit ${mem_limit}KB)"
            if $mem_limit > 0 && $p->{rss} > $mem_limit;
        next unless @over;

        my $why = join(' and ', @over);
        $reported++;

        my $action = 'reported only';
        if ($terminate) {
            # Never signal init, ourselves, or anything in our own process
            # group: the mailer and the block report hook run there.
            if ($p->{pid} <= 1 || $p->{pid} == $$ || _in_our_group($p->{pid})) {
                $action = 'not terminated (protected pid)';

            } else {
                # Re-read the process immediately before signalling it.
                #
                # Everything above was decided from a snapshot taken before the
                # scan walked /proc. By now the process may have exited and its
                # pid been reused, and killing on the pid alone would signal
                # whatever holds it now.
                my $fresh = $class->verify_identity($p);

                if (!$fresh) {
                    $action = 'not terminated (process exited or pid reused)';
                    HGLogger->info("Not terminating pid $p->{pid}: it is no "
                                 . "longer the process that was scanned");

                } elsif (!_over_limit($fresh, $cpu_limit, $mem_limit)) {
                    # Still the same process, but no longer over the ceiling.
                    $action = 'not terminated (back within limits)';
                    HGLogger->info("Not terminating pid $p->{pid}: usage fell "
                                 . "back within limits before the signal");

                } elsif (kill('TERM', $p->{pid})) {
                    $action = 'sent SIGTERM';
                    HGLogger->info("Terminated pid $p->{pid} ($p->{user}): $why");

                } else {
                    $action = "could not signal: $!";
                }
            }
        }

        HGLogger->log_warn("Excessive usage: pid=$p->{pid} user=$p->{user} "
                         . "$why - $action");

        HGAlert->send(
            kind    => 'proc_usage',
            config  => $config,
            subject => "$p->{user} process over resource limit",
            ident   => "$p->{user}\0$p->{cmd}",
            vars    => { %{ _proc_vars($p, $why) }, ACTION => $action },
            body    => _proc_report($p, $why) . "Action: $action\n",
        ) unless $opt{quiet};
    }

    return $reported;
}

###############################################################################
# Temporary directory scanning
###############################################################################

# Report executables and scripts sitting in world-writable directories.
#
# A payload has to land somewhere before it runs, and these directories are
# where it lands. Directories are walked to a bounded depth and a bounded
# number of entries so the check cannot itself become the load problem on a
# host with a large /tmp.
sub scan_temp_files {
    my ($class, $config, %opt) = @_;
    return 0 unless ($config->{FILE_SCAN} // '0') eq '1';

    my $max_entries = $config->{FILE_SCAN_MAX} // 5000;
    $max_entries = 5000 unless $max_entries =~ /^\d+$/ && $max_entries > 0;

    my @dirs = @TEMP_DIRS;
    if (my $extra = $config->{FILE_SCAN_DIRS}) {
        for my $d (split(/,/, $extra)) {
            $d =~ s/^\s+//;
            $d =~ s/\s+$//;
            push @dirs, $d if length $d && $d =~ m{^/};
        }
    }

    my @exceptions = _exceptions($config);
    my @found;
    my $seen = 0;

    for my $dir (@dirs) {
        next unless -d $dir;
        $class->_walk($dir, 0, \$seen, $max_entries, sub {
            my ($path, @st) = @_;

            my $mode = $st[2] & 07777;
            my $name = $path;
            $name =~ s{^.*/}{};

            my @reasons;

            # Anything with an execute bit in a directory whose purpose is
            # scratch data.
            push @reasons, 'executable' if $mode & 0111;

            # Set-user-id or set-group-id here is a privilege escalation
            # attempt; there is no legitimate reason for one.
            push @reasons, 'setuid'  if $mode & 04000;
            push @reasons, 'setgid'  if $mode & 02000;

            # A script kept by extension even without the execute bit, since
            # it can still be run by naming the interpreter.
            push @reasons, 'script'
                if $name =~ /\.(?:pl|py|sh|php|rb|lua|pyc)$/i && !@reasons;

            # A name starting with a dot in a scratch directory is usually
            # there to stay out of a casual listing.
            push @reasons, 'hidden' if $name =~ /^\./ && @reasons;

            return unless @reasons;
            return if _path_excepted($path, \@exceptions);

            push @found, {
                path    => $path,
                owner   => _uid_to_name($st[4]),
                size    => $st[7],
                mode    => sprintf('%04o', $mode),
                reasons => \@reasons,
            };
        });
    }

    return 0 unless @found;

    my $notices = 0;
    for my $f (@found) {
        my $why = join(', ', @{ $f->{reasons} });
        HGLogger->log_warn("Suspicious file: $f->{path} ($why) "
                         . "owner=$f->{owner} mode=$f->{mode}");

        if (++$notices > $MAX_NOTICES_PER_SCAN) {
            _summarise_scan('susp_file', $config, scalar(@found),
                            $MAX_NOTICES_PER_SCAN) unless $opt{quiet};
            last;
        }

        HGAlert->send(
            kind    => 'susp_file',
            config  => $config,
            subject => "Suspicious file in a world-writable directory",
            ident   => $f->{path},
            vars    => {
                PATH   => $f->{path},
                OWNER  => $f->{owner},
                MODE   => $f->{mode},
                SIZE   => $f->{size},
                REASON => $why,
            },
            body    => "Path:  $f->{path}\n"
                     . "Owner: $f->{owner}\n"
                     . "Mode:  $f->{mode}\n"
                     . "Size:  $f->{size} bytes\n"
                     . "Why:   $why\n\n"
                     . "The file has not been changed or removed. Inspect it "
                     . "before deleting it.\n",
        ) unless $opt{quiet};
    }

    return scalar(@found);
}

# Walk a directory to a bounded depth, calling back for each plain file.
#
# Symbolic links are never followed: a link in /tmp pointing at / would
# otherwise walk the whole filesystem.
sub _walk {
    my ($class, $dir, $depth, $seen_ref, $max, $cb) = @_;
    return if $depth > 3;
    return if $$seen_ref >= $max;

    opendir(my $dh, $dir) or return;
    my @entries = readdir($dh);
    closedir($dh);

    for my $entry (@entries) {
        next if $entry eq '.' || $entry eq '..';
        last if $$seen_ref >= $max;

        my $path = "$dir/$entry";
        my @st = lstat($path) or next;

        # -l is checked before -d so a symlinked directory is not descended.
        next if -l _;
        $$seen_ref++;

        if (-d _) {
            $class->_walk($path, $depth + 1, $seen_ref, $max, $cb);
        } elsif (-f _) {
            $cb->($path, @st);
        }
    }
}

###############################################################################
# Helpers
###############################################################################

# One notice standing in for the ones not sent individually.
#
# Its ident carries only the kind and the hour, so a flood produces one extra
# message per hour however large it is - which is the point: the individual
# notices are what an attacker can multiply, and this one they cannot.
sub _summarise_scan {
    my ($kind, $config, $total, $shown) = @_;

    my $skipped = $total - $shown;
    return unless $skipped > 0;

    HGLogger->log_warn("$kind scan found $total items; $shown were reported "
                     . "individually and $skipped were not. Everything found "
                     . "is in the log above.");

    HGAlert->send(
        kind    => $kind,
        config  => $config,
        subject => "$total findings in one scan, $skipped not reported individually",
        ident   => "summary\0$kind\0" . int(time() / 3600),
        # Every placeholder both templates use, because an unrecognised one is
        # now left visible rather than blanked - which is right for a real
        # notice and would read as a bug in a summary.
        vars    => {
            PATH    => '(many - see the log)',
            OWNER   => '(various)',
            MODE    => '-',
            SIZE    => '-',
            USER    => '(various)',
            CMD     => '(many - see the log)',
            COMMAND => '(many - see the log)',
            BINARY  => '(various)',
            PID     => '-',
            CPU     => '-',
            MEMORY  => '-',
            RUNTIME => '-',
            REASON  => "$total findings in a single scan",
        },
        body    => "A single scan produced $total findings.\n\n"
                 . "$shown were sent as individual notices; $skipped were not, "
                 . "because a scan that can produce thousands of findings is "
                 . "usually someone creating them deliberately, and one notice "
                 . "per finding would be the denial of service rather than the "
                 . "report of it.\n\n"
                 . "Every finding is in the daemon log. Look there for the "
                 . "full list.\n",
    );
    return;
}

# Administrator-supplied exceptions, one per line in procignore.conf.
#
# A line is either a bare user name, a path prefix, or "cmd:" followed by a
# substring of the command line.
sub _exceptions {
    my ($config) = @_;

    my $file = "$HGConfig::CONFIG_DIR/procignore.conf";
    my @rules;

    return @rules unless -f $file;
    open(my $fh, '<', $file) or return @rules;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        $line =~ s/\s*#.*$//;
        next unless length $line;

        if ($line =~ /^cmd:(.+)$/i) {
            push @rules, { type => 'cmd', value => $1 };
        } elsif ($line =~ m{^/}) {
            push @rules, { type => 'path', value => $line };
        } else {
            push @rules, { type => 'user', value => $line };
        }
    }
    close($fh);

    return @rules;
}

sub _excepted {
    my ($p, $rules) = @_;
    for my $r (@$rules) {
        if ($r->{type} eq 'user') {
            return 1 if $p->{user} eq $r->{value};
        } elsif ($r->{type} eq 'path') {
            return 1 if length $p->{exe} && index($p->{exe}, $r->{value}) == 0;
        } elsif ($r->{type} eq 'cmd') {
            return 1 if index($p->{cmd}, $r->{value}) >= 0;
        }
    }
    return 0;
}

sub _path_excepted {
    my ($path, $rules) = @_;
    for my $r (@$rules) {
        next unless $r->{type} eq 'path';
        return 1 if index($path, $r->{value}) == 0;
    }
    return 0;
}

# True when a pid belongs to our own process group.
#
# The mailer and any block report hook are started from here and inherit it.
# Terminating one of those because it briefly used memory would be the check
# killing its own machinery.
sub _in_our_group {
    my ($pid) = @_;
    my $ours = eval { getpgrp(0) } or return 0;
    my $theirs = eval { getpgrp($pid) } or return 0;
    return $ours == $theirs ? 1 : 0;
}

# Whether a process is over either ceiling, using the same test the scan used.
sub _over_limit {
    my ($p, $cpu_limit, $mem_limit) = @_;
    return 1 if $cpu_limit > 0 && $p->{pcpu} > $cpu_limit;
    return 1 if $mem_limit > 0 && $p->{rss}  > $mem_limit;
    return 0;
}

sub _is_system_user {
    my ($user) = @_;
    return 0 unless defined $user;
    for my $sys (@SYSTEM_USERS) {
        return 1 if $user eq $sys;
    }
    return 0;
}

# Template variables for a process, matching the fields _proc_report prints.
# Confirm the process behind a pid is still the one that was scanned.
#
# A pid identifies a process only for as long as that process is alive. The
# scan walks every entry under /proc, reads and digests what it finds, and only
# then decides; on a busy host that is long enough for a process to exit and
# its pid to be handed to something else. Signalling on the pid alone means
# signalling whatever holds it now, which on a server that recycles pids
# quickly could be anything at all.
#
# The pair (pid, start time) is stable: the kernel may reuse the number, but
# the new process starts later, so the start time differs. The uid is checked
# as well, since a matching start time with a different owner would mean the
# read raced with something stranger still.
#
# Returns the fresh process if it is the same one, undef otherwise.
sub verify_identity {
    my ($class, $p) = @_;
    return undef unless $p && $p->{pid};

    my $dir = "/proc/$p->{pid}";
    my @st  = stat($dir) or return undef;      # gone
    return undef unless $st[4] == $p->{uid};   # different owner

    my $stat = _slurp("$dir/stat") or return undef;
    my $rest = $stat;
    $rest =~ s/^\d+\s+\(.*\)\s+//s;
    my @f = split(/\s+/, $rest);
    my $start = $f[19] // 0;

    return undef unless defined $p->{start} && $start eq $p->{start};

    # Same process. Hand back a fresh reading so the caller decides on current
    # numbers rather than on ones taken before the scan began.
    return _read_proc($p->{pid});
}

sub _proc_vars {
    my ($p, $why) = @_;
    return {
        PID     => $p->{pid},
        USER    => $p->{user},
        COMMAND => $p->{cmd},
        BINARY  => (length $p->{exe} ? $p->{exe} : 'unknown')
                 . ($p->{deleted} ? ' (deleted)' : ''),
        CPU     => $p->{pcpu},
        MEMORY  => $p->{rss},
        RUNTIME => $p->{etime},
        REASON  => $why,
    };
}

# Format the common part of a process report.
sub _proc_report {
    my ($p, $why) = @_;
    return "PID:      $p->{pid}\n"
         . "User:     $p->{user}\n"
         . "Command:  $p->{cmd}\n"
         . "Binary:   " . (length $p->{exe} ? $p->{exe} : 'unknown')
                        . ($p->{deleted} ? ' (deleted)' : '') . "\n"
         . "CPU:      $p->{pcpu}%\n"
         . "Memory:   $p->{rss} KB\n"
         . "Running:  $p->{etime}s\n"
         . "Why:      $why\n\n";
}

sub _slurp {
    my ($file) = @_;
    open(my $fh, '<', $file) or return undef;
    my $data = do { local $/; <$fh> };
    close($fh);
    return $data;
}

# Name for a uid, resolved once each per process.
{
    my %cache;
    sub _uid_to_name {
        my ($uid) = @_;
        return 'unknown' unless defined $uid;
        return $cache{$uid} if exists $cache{$uid};
        my $name = getpwuid($uid);
        $cache{$uid} = defined $name && length $name ? $name : $uid;
        return $cache{$uid};
    }
}

{
    my $ticks;
    sub _clock_ticks {
        return $ticks if defined $ticks;
        $ticks = eval { require POSIX; POSIX::sysconf(POSIX::_SC_CLK_TCK()) } || 100;
        $ticks = 100 unless $ticks && $ticks > 0;
        return $ticks;
    }
}

{
    my $size;
    sub _page_size {
        return $size if defined $size;
        $size = eval { require POSIX; POSIX::sysconf(POSIX::_SC_PAGESIZE()) } || 4096;
        $size = 4096 unless $size && $size > 0;
        return $size;
    }
}

sub _uptime {
    my $data = _slurp('/proc/uptime') or return 0;
    my ($up) = split(/\s+/, $data);
    return $up && $up =~ /^[\d.]+$/ ? $up : 0;
}

# Current load averages, as a three element list.
sub loadavg {
    my $data = _slurp('/proc/loadavg') or return (0, 0, 0);
    my @f = split(/\s+/, $data);
    return (($f[0] // 0), ($f[1] // 0), ($f[2] // 0));
}

1;
