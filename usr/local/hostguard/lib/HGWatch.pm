package HGWatch;
###############################################################################
# HostGuard Pro - Change Detection
# /usr/local/hostguard/lib/HGWatch.pm
#
# Notices when something on the host stops matching what it looked like last
# time. Three independent watchers share one mechanism:
#
#   watch_paths   - files and directories named in watch.conf, for a site that
#                   wants to know when a particular configuration changes
#   integrity     - the system and application binaries, so a replaced ls,
#                   ps or sshd is reported. This is the last line of
#                   detection: by the time a binary has changed, everything
#                   earlier has already been got past
#   accounts      - the account database, reporting a changed shell, uid,
#                   home directory or password independently of each other
#
# Each watcher keeps a baseline under the data directory. The first run after
# a watcher is enabled records the baseline and reports nothing, because
# everything would otherwise look new. Later runs report the difference.
#
# A file is compared by content digest where one can be taken, and by size,
# mtime, mode and ownership always. Metadata alone catches a replacement that
# preserves content; the digest catches an edit that preserves metadata.
###############################################################################
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
use HGConfig;
use HGLogger;

# Files stamped without a content digest during the current integrity pass.
# See _stamp_file.
my $NO_DIGEST = 0;
use HGAlert;

# Directories whose executables are compared when the integrity monitor is on.
our @INTEGRITY_DIRS = qw(
    /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
);

# Files holding the account database.
our @ACCOUNT_FILES = qw(/etc/passwd /etc/shadow /etc/group);

sub _watch_db     { return "$HGConfig::DATA_DIR/watch.db" }
sub _integrity_db { return "$HGConfig::DATA_DIR/integrity.db" }
sub _account_db   { return "$HGConfig::DATA_DIR/accounts.db" }

###############################################################################
# Watched paths
###############################################################################

# Compare the paths named in watch.conf against their baseline.
#
# A directory is compared by its immediate entries rather than recursively:
# the question a site asks of a watched directory is almost always "has
# anything appeared or gone", and walking a deep tree on a timer is a cost
# without a matching benefit.
sub watch_paths {
    my ($class, $config, %opt) = @_;
    return 0 unless ($config->{WATCH_ENABLE} // '0') eq '1';

    my @paths = $class->_watch_list();
    return 0 unless @paths;

    _report_pending('watch_change') unless $opt{quiet};

    my $old   = _load_db(_watch_db());
    my $first = !%$old;
    my %new;

    for my $path (@paths) {
        if (-d $path) {
            # Record the directory itself, then one entry per immediate child,
            # so both a changed file and an added or removed one are seen.
            $new{$path} = _stamp_dir($path);
            opendir(my $dh, $path) or next;
            for my $entry (sort readdir($dh)) {
                next if $entry eq '.' || $entry eq '..';
                my $child = "$path/$entry";
                next if -d $child;
                $new{$child} = _stamp_file($child, $config);
            }
            closedir($dh);
        } elsif (-e $path) {
            $new{$path} = _stamp_file($path, $config);
        } else {
            # A path that does not exist is still recorded, so its later
            # appearance is reported as an addition.
            $new{$path} = 'missing';
        }
    }

    my $changes = _diff($old, \%new);

    if ($first) {
        _save_db(_watch_db(), \%new);
        HGLogger->info("Path watch baseline recorded for " . scalar(keys %new) . " path(s)");
        return 0;
    }

    unless (@$changes) {
        _save_db(_watch_db(), \%new);
        return 0;
    }

    # Logged and marked pending before the baseline moves. See _pending_file.
    for my $c (@$changes) {
        HGLogger->log_warn("Watched path $c->{what}: $c->{path}");
    }
    _mark_pending('watch_change', scalar(@$changes) . " watched path(s) changed at "
                                . scalar(localtime()))
        unless $opt{quiet};

    _save_db(_watch_db(), \%new);

    _send_and_clear('watch_change',
        kind    => 'watch_change',
        config  => $config,
        subject => scalar(@$changes) . " watched path(s) changed",
        ident   => join(',', map { "$_->{what}:$_->{path}" } @$changes),
        vars    => {
            COUNT   => scalar(@$changes),
            CHANGES => _change_list($changes),
        },
        body    => _change_report("Watched paths", $changes),
    ) unless $opt{quiet};

    return scalar(@$changes);
}

# Paths to watch, one per line in watch.conf.
sub _watch_list {
    my ($class) = @_;

    my $file = "$HGConfig::CONFIG_DIR/watch.conf";
    my @paths;
    return @paths unless -f $file;

    open(my $fh, '<', $file) or return @paths;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/^\s+//;
        $line =~ s/\s+$//;
        $line =~ s/\s*#.*$//;
        next unless length $line;
        unless ($line =~ m{^/}) {
            HGLogger->error("Ignoring watch.conf entry that is not an absolute path: $line");
            next;
        }
        push @paths, $line;
    }
    close($fh);

    return @paths;
}

###############################################################################
# Binary integrity
###############################################################################

# Compare the system binaries against their baseline.
#
# Only regular files with an execute bit are recorded. The scan is bounded by
# INTEGRITY_MAX_FILES so that an unusual host cannot turn a periodic check
# into a long one, and by INTEGRITY_MAX_SIZE so that digesting does not read
# an enormous file on every pass.
sub check_integrity {
    my ($class, $config, %opt) = @_;
    return 0 unless ($config->{INTEGRITY_ENABLE} // '0') eq '1';

    my $max_files = $config->{INTEGRITY_MAX_FILES} // 8000;
    $max_files = 8000 unless $max_files =~ /^\d+$/ && $max_files > 0;

    my @dirs = @INTEGRITY_DIRS;
    my $configured = 0;
    if (my $extra = $config->{INTEGRITY_DIRS}) {
        @dirs = ();
        $configured = 1;
        for my $d (split(/,/, $extra)) {
            $d =~ s/^\s+//;
            $d =~ s/\s+$//;
            unless (length $d && $d =~ m{^/}) {
                HGLogger->error("Ignoring INTEGRITY_DIRS entry that is not an "
                              . "absolute path: $d");
                next;
            }
            push @dirs, $d;
        }
    }

    # INTEGRITY_DIRS replaces the defaults rather than adding to them, so a typo
    # in it narrows monitoring instead of widening it. A directory that does not
    # exist is therefore reported rather than skipped: the only other symptom
    # would be the absence of alerts, which reads as "nothing changed".
    my @present = grep { -d $_ } @dirs;
    if ($configured) {
        for my $d (@dirs) {
            HGLogger->error("INTEGRITY_DIRS names $d, which is not a directory "
                          . "on this host; it is not being monitored")
                unless -d $d;
        }
    }
    unless (@present) {
        HGLogger->error("Integrity checking is enabled but none of the "
                      . "configured directories exist ("
                      . join(', ', @dirs) . "), so nothing is being checked. "
                      . "Fix INTEGRITY_DIRS or unset it to use the defaults.");
        return 0;
    }

    _report_pending('integrity') unless $opt{quiet};

    my $old   = _load_db(_integrity_db());
    my $first = !%$old;
    my %new;
    my $count = 0;
    $NO_DIGEST = 0;

    for my $dir (@present) {
        next unless -d $dir;
        opendir(my $dh, $dir) or next;
        my @entries = sort readdir($dh);
        closedir($dh);

        for my $entry (@entries) {
            next if $entry eq '.' || $entry eq '..';
            last if $count >= $max_files;

            my $path = "$dir/$entry";
            my @st = lstat($path) or next;

            # A symlink is recorded by its target, which is what changes when
            # an alternatives link is repointed at a different binary.
            if (-l _) {
                my $target = readlink($path);
                $new{$path} = 'link:' . (defined $target ? $target : 'unreadable');
                $count++;
                next;
            }
            next unless -f _;
            next unless $st[2] & 0111;

            $new{$path} = _stamp_file($path, $config, \@st);
            $count++;
        }
    }

    my $changes = _diff($old, \%new);

    if ($NO_DIGEST) {
        HGLogger->log_warn("$NO_DIGEST of $count file(s) were stamped from "
                         . "metadata only, without a content digest, because "
                         . "they exceed INTEGRITY_MAX_SIZE or could not be "
                         . "read. A change to one of those is only detected if "
                         . "it alters the size, mtime or mode. Raise "
                         . "INTEGRITY_MAX_SIZE to cover them.");
    }

    if ($first) {
        _save_db(_integrity_db(), \%new);
        HGLogger->info("Integrity baseline recorded for $count binaries");
        return 0;
    }

    unless (@$changes) {
        _save_db(_integrity_db(), \%new);
        return 0;
    }

    # Logged and marked pending before the baseline moves. See _pending_file.
    for my $c (@$changes) {
        HGLogger->log_warn("System binary $c->{what}: $c->{path}");
    }
    _mark_pending('integrity', scalar(@$changes) . " system binary change(s) at "
                             . scalar(localtime()))
        unless $opt{quiet};

    _save_db(_integrity_db(), \%new);

    _send_and_clear('integrity',
        kind    => 'integrity',
        config  => $config,
        subject => scalar(@$changes) . " system binary change(s) detected",
        ident   => join(',', map { "$_->{what}:$_->{path}" } @$changes),
        vars    => {
            COUNT   => scalar(@$changes),
            CHANGES => _change_list($changes),
        },
        body    => _change_report("System binaries", $changes)
                 . "\nA changed binary is expected after a package update. If no "
                 . "update was made, treat this as a compromise until proven "
                 . "otherwise.\n",
    ) unless $opt{quiet};

    return scalar(@$changes);
}

# Discard the integrity baseline so the next run records a fresh one. Used
# after a deliberate package update, when every change is expected.
sub reset_integrity {
    unlink(_integrity_db());
    HGLogger->info("Integrity baseline cleared; it will be rebuilt on the next check");
    return 1;
}

###############################################################################
# Account modification
###############################################################################

# Report changes to the account database, field by field.
#
# The password hash is never stored or reported: only a digest of it is kept,
# so HostGuard Pro can say that a password changed without holding the
# material that would let anyone act on it.
sub check_accounts {
    my ($class, $config, %opt) = @_;
    return 0 unless ($config->{NOTIFY_ACCOUNT_MOD} // '0') eq '1';

    my $old   = _load_db(_account_db());
    my $first = !%$old;
    my %new   = %{ $class->_account_snapshot() };

    my @changes;
    for my $user (sort keys %new) {
        unless (exists $old->{$user}) {
            push @changes, { path => $user, what => 'created', detail => $new{$user} };
            next;
        }
        next if $old->{$user} eq $new{$user};

        my %was = _split_account($old->{$user});
        my %now = _split_account($new{$user});
        my @fields;
        for my $f (qw(uid gid home shell password)) {
            next if ($was{$f} // '') eq ($now{$f} // '');
            if ($f eq 'password') {
                push @fields, 'password changed';
            } else {
                push @fields, "$f: " . ($was{$f} // '?') . " -> " . ($now{$f} // '?');
            }
        }
        next unless @fields;
        push @changes, { path => $user, what => 'modified', detail => join(', ', @fields) };
    }
    for my $user (sort keys %$old) {
        push @changes, { path => $user, what => 'removed', detail => '' }
            unless exists $new{$user};
    }

    if ($first) {
        _save_db(_account_db(), \%new);
        HGLogger->info("Account baseline recorded for " . scalar(keys %new) . " account(s)");
        return 0;
    }

    unless (@changes) {
        _save_db(_account_db(), \%new);
        return 0;
    }

    # Logged and marked pending before the baseline moves. See _pending_file.
    my $body = "Account database changes\n\n";
    for my $c (@changes) {
        HGLogger->log_warn("Account $c->{what}: $c->{path}"
                         . (length $c->{detail} ? " ($c->{detail})" : ''));
        $body .= sprintf("  %-10s %s%s\n", $c->{what}, $c->{path},
                         length $c->{detail} ? " - $c->{detail}" : '');
    }
    _mark_pending('account_mod', scalar(@changes) . " account change(s) at "
                               . scalar(localtime()))
        unless $opt{quiet};

    _save_db(_account_db(), \%new);

    _send_and_clear('account_mod',
        kind    => 'account_mod',
        config  => $config,
        subject => scalar(@changes) . " account change(s)",
        ident   => join(',', map { "$_->{what}:$_->{path}" } @changes),
        vars    => {
            COUNT   => scalar(@changes),
            CHANGES => join('', map {
                           sprintf("  %-10s %s%s\n", $_->{what}, $_->{path},
                                   length $_->{detail} ? " - $_->{detail}" : '')
                       } @changes),
        },
        body    => $body,
    ) unless $opt{quiet};

    return scalar(@changes);
}

# One record per account: uid, gid, home, shell and a digest of the password
# field. Group membership is folded in so an account added to wheel is seen.
sub _account_snapshot {
    my ($class) = @_;

    my %acct;

    if (open(my $fh, '<', '/etc/passwd')) {
        flock($fh, LOCK_SH);
        while (my $line = <$fh>) {
            chomp $line;
            next unless length $line && $line !~ /^\s*#/;
            my ($user, undef, $uid, $gid, undef, $home, $shell) = split(/:/, $line, 7);
            next unless defined $user && length $user;
            $acct{$user} = {
                uid   => $uid   // '',
                gid   => $gid   // '',
                home  => $home  // '',
                shell => $shell // '',
            };
        }
        close($fh);
    }

    # The hash itself never leaves this scope; only its digest is stored.
    if (open(my $fh, '<', '/etc/shadow')) {
        flock($fh, LOCK_SH);
        while (my $line = <$fh>) {
            chomp $line;
            next unless length $line && $line !~ /^\s*#/;
            my ($user, $hash) = split(/:/, $line, 3);
            next unless defined $user && exists $acct{$user};
            $acct{$user}{password} = substr(_digest(defined $hash ? $hash : ''), 0, 16);
        }
        close($fh);
    }

    my %flat;
    for my $user (keys %acct) {
        my $a = $acct{$user};
        $flat{$user} = join('|',
            "uid=" . $a->{uid},
            "gid=" . $a->{gid},
            "home=" . $a->{home},
            "shell=" . $a->{shell},
            "password=" . ($a->{password} // ''),
        );
    }

    return \%flat;
}

sub _split_account {
    my ($record) = @_;
    my %f;
    for my $pair (split(/\|/, $record)) {
        my ($k, $v) = split(/=/, $pair, 2);
        $f{$k} = $v if defined $k;
    }
    return %f;
}

###############################################################################
# Baseline storage
###############################################################################

# One "path<TAB>stamp" record per line.
sub _load_db {
    my ($file) = @_;
    my %db;
    return \%db unless -f $file;

    open(my $fh, '<', $file) or return \%db;
    flock($fh, LOCK_SH);
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;
        my ($path, $stamp) = split(/\t/, $line, 2);
        next unless defined $path && defined $stamp;
        $db{$path} = $stamp;
    }
    close($fh);

    return \%db;
}

# Findings that have been seen but not yet successfully mailed.
#
# The order in which a watcher reports and commits matters, and it is the reason
# this file exists. If the baseline were written before the change was reported,
# there would be a moment when nothing anywhere recorded that a change had been
# seen - and a process dying there, from an OOM kill or a systemctl restart
# during a package update, would leave the modified file as the new baseline for
# the next pass to diff against and find nothing. A monitor that certifies the
# binary it was meant to flag is worse than no monitor, because silence reads as
# "nothing changed".
#
# So each watcher does two things before it commits. It writes the finding to
# the log, which closes the window in which it could be lost entirely. And it
# records the notice as pending here, clearing it only once the mailer reports
# success, so a failed or interrupted send is reported again on the next pass.
# That is at-least-once rather than at-most-once, which is the right direction
# for a security signal: a duplicate notice costs an operator ten seconds, a
# dropped one costs them the compromise.
sub _pending_file { return "$HGConfig::DATA_DIR/watch_pending.dat" }

sub _read_pending {
    my %pending;
    open(my $fh, '<', _pending_file()) or return %pending;
    while (my $l = <$fh>) {
        chomp $l;
        next unless length $l;
        my ($kind, $summary) = split(/\t/, $l, 2);
        next unless defined $kind && defined $summary;
        $pending{$kind} = $summary;
    }
    close($fh);
    return %pending;
}

sub _write_pending {
    my (%pending) = @_;
    my $out = join('', map { "$_\t$pending{$_}\n" } sort keys %pending);
    if (length $out) {
        eval { HGConfig::_write_atomic(_pending_file(), $out); 1 }
            or HGLogger->error("Cannot record a pending notice: $@");
        chmod(0600, _pending_file());
    } else {
        unlink(_pending_file());
    }
    return;
}

sub _mark_pending {
    my ($kind, $summary) = @_;
    my %pending = _read_pending();
    $pending{$kind} = $summary;
    _write_pending(%pending);
    return;
}

sub _clear_pending {
    my ($kind) = @_;
    my %pending = _read_pending();
    return unless exists $pending{$kind};
    delete $pending{$kind};
    _write_pending(%pending);
    return;
}

# Send a notice and clear its pending mark only if it went out.
sub _send_and_clear {
    my ($kind, @args) = @_;
    my $sent = HGAlert->send(@args);
    if ($sent) {
        _clear_pending($kind);
    } else {
        # HGAlert returns 0 both for "suppressed" and for "could not send",
        # and it cannot currently tell the caller which. Leaving the mark on
        # either is the safe direction: a mark that outlives a suppressed
        # notice costs one warning line per pass, and one that is cleared on a
        # failed send costs the finding.
        HGLogger->debug("$kind notice was not confirmed sent; it stays pending");
    }
    return $sent;
}

# Findings recorded as seen but never confirmed reported.
#
# Read by the watcher that owns each kind, at the start of its run, and by
# "hostguard -s". Without a reader the marker file would be a record nobody
# looks at, which is the same failure it exists to prevent one level up.
sub pending_notices {
    my ($class) = @_;
    my %pending = _read_pending();
    return map { { kind => $_, summary => $pending{$_} } } sort keys %pending;
}

# Report, once per run, that a previous finding of this kind was not confirmed
# delivered. The finding itself is already in the log from the pass that saw it;
# this says that it was never acknowledged, which is the part an operator would
# otherwise have no way to know.
sub _report_pending {
    my ($kind) = @_;
    my %pending = _read_pending();
    return unless exists $pending{$kind};
    HGLogger->log_warn("A previous $kind finding was recorded but its notice "
                     . "was never confirmed sent: $pending{$kind}. Search the "
                     . "log around that time for the detail. It will be "
                     . "reported again if the change is still present.");
    return;
}

sub _save_db {
    my ($file, $db) = @_;

    my $out = '';
    for my $path (sort keys %$db) {
        my $stamp = $db->{$path};
        next unless defined $stamp;
        # A path containing a tab or newline would corrupt the record; such a
        # name is pathological, and folding it keeps the file parseable.
        my $safe = $path;
        $safe =~ s/[\t\n]/ /g;
        $stamp =~ s/[\t\n]/ /g;
        $out .= "$safe\t$stamp\n";
    }

    eval { HGConfig::_write_atomic($file, $out); 1 }
        or HGLogger->error("Cannot save baseline $file: $@");
    chmod(0600, $file);
    return 1;
}

# Compare two snapshots, returning added, removed and changed paths.
sub _diff {
    my ($old, $new) = @_;
    my @changes;

    for my $path (sort keys %$new) {
        unless (exists $old->{$path}) {
            push @changes, { path => $path, what => 'added' };
            next;
        }
        push @changes, { path => $path, what => 'changed' }
            if $old->{$path} ne $new->{$path};
    }
    for my $path (sort keys %$old) {
        push @changes, { path => $path, what => 'removed' }
            unless exists $new->{$path};
    }

    return \@changes;
}

# The change lines on their own, for a template that supplies its own wording
# around them.
sub _change_list {
    my ($changes) = @_;
    return join('', map { sprintf("  %-8s %s
", $_->{what}, $_->{path}) } @$changes);
}

sub _change_report {
    my ($title, $changes) = @_;
    my $body = "$title\n\n";
    for my $c (@$changes) {
        $body .= sprintf("  %-8s %s\n", $c->{what}, $c->{path});
    }
    $body .= "\n" . scalar(@$changes) . " change(s) in total.\n";
    return $body;
}

###############################################################################
# Stamps
###############################################################################

# A file's fingerprint: metadata always, content digest when the file is small
# enough to be worth reading.
#
# Metadata alone catches a replacement; the digest catches an edit that
# restored the original mtime. Together they are hard to slip past without
# root, and by the time an attacker has root this check has already done the
# job it can do.
sub _stamp_file {
    my ($path, $config, $st) = @_;

    my @s = $st ? @$st : lstat($path);
    return 'missing' unless @s;

    my $stamp = join(':', 'f', $s[7], $s[9], sprintf('%04o', $s[2] & 07777), $s[4], $s[5]);

    my $max = $config->{INTEGRITY_MAX_SIZE} // 10485760;
    $max = 10485760 unless $max =~ /^\d+$/;

    # A file above the ceiling, or one that cannot be read, is stamped from its
    # metadata alone - size, mtime, mode, owner. That is defeated by anyone who
    # preserves size and mtime, which is not a demanding thing to do, so the
    # fallback is recorded in the stamp rather than being invisible.
    #
    # Two things follow from marking it. The operator can see which files are
    # only shallowly monitored, via the count logged by check_integrity; and a
    # file crossing the threshold in either direction changes its own stamp, so
    # it is reported instead of quietly changing category.
    if ($max > 0 && $s[7] > $max) {
        $NO_DIGEST++;
        return $stamp . ':nodigest-toolarge';
    }

    my $digest = _file_digest($path);
    unless (defined $digest) {
        $NO_DIGEST++;
        return $stamp . ':nodigest-unreadable';
    }
    $stamp .= ':' . substr($digest, 0, 32);

    return $stamp;
}

# A directory's fingerprint is its own metadata plus the number of entries, so
# an addition or removal is visible even when no watched child changed.
sub _stamp_dir {
    my ($path) = @_;
    my @s = stat($path) or return 'missing';

    my $entries = 0;
    if (opendir(my $dh, $path)) {
        $entries = scalar(grep { $_ ne '.' && $_ ne '..' } readdir($dh));
        closedir($dh);
    }

    return join(':', 'd', $entries, $s[9], sprintf('%04o', $s[2] & 07777), $s[4], $s[5]);
}

# SHA-256 of a file's contents, or undef when it cannot be read.
#
# Digest::SHA is core Perl and present on cPanel servers. Without it the stamp
# falls back to metadata alone, which still detects a replaced binary.
sub _file_digest {
    my ($path) = @_;

    my $hex = eval {
        require Digest::SHA;
        my $sha = Digest::SHA->new(256);
        $sha->addfile($path);
        $sha->hexdigest;
    };
    return $hex if defined $hex && length $hex;
    return undef;
}

sub _digest {
    my ($data) = @_;
    my $hex = eval {
        require Digest::SHA;
        Digest::SHA::sha256_hex($data);
    };
    return $hex if defined $hex && length $hex;

    # Same inline fallback as the WHM interface uses, so a host without
    # Digest::SHA still produces a stable value.
    my $h1 = 0x1505;
    my $h2 = 0x7fed;
    for my $c (unpack('C*', $data)) {
        $h1 = (($h1 * 33) ^ $c) & 0xFFFFFFFF;
        $h2 = (($h2 * 31) + $c) & 0xFFFFFFFF;
    }
    return sprintf('%08x%08x', $h1, $h2);
}

1;
