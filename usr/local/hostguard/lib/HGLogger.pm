package HGLogger;
###############################################################################
# HostGuard Pro - Logging Module
# /usr/local/hostguard/lib/HGLogger.pm
###############################################################################
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
use POSIX qw(strftime);

my $LOG_FILE  = "/var/log/hostguard/daemon.log";
my $LOG_LEVEL = 1;

# Size-based rotation threshold in bytes; 0 disables it.
#
# Rotation is normally handled by logrotate (/etc/logrotate.d/hostguard), so
# this is disabled by default. Two rotators running against one file compete to
# create daemon.log.1 and overwrite each other's archive. Set LOG_MAX_SIZE on a
# host that has no logrotate.
my $MAX_SIZE  = 0;

sub init {
    my ($class, %opts) = @_;
    $LOG_FILE  = $opts{file}  if $opts{file};
    $LOG_LEVEL = $opts{level} if defined $opts{level};
    $MAX_SIZE  = $opts{max_size} if defined $opts{max_size};

    # Ensure log directory exists
    my $dir = $LOG_FILE;
    $dir =~ s|/[^/]+$||;
    unless (-d $dir) {
        system("mkdir", "-p", $dir);
        chmod(0750, $dir);
    }

    return 1;
}

sub error   { _log('ERROR', @_); }
sub log_warn { _log('WARN',  @_); }
sub info    { _log('INFO',  @_); }
sub verbose { _log('VERBOSE', @_) if $LOG_LEVEL >= 2; }
sub debug { _log('DEBUG', @_) if $LOG_LEVEL >= 3; }

sub _log {
    my ($level, $class_or_msg, $msg) = @_;

    # Handle both HGLogger->info("msg") and HGLogger::info("msg")
    if (!defined $msg) {
        $msg = $class_or_msg;
    }

    _rotate_if_needed();

    my $ts = strftime("%Y-%m-%d %H:%M:%S", localtime);
    my $line = "[$ts] [$level] $msg\n";

    # The mode is stated rather than inherited from the caller's umask.
    #
    # The installer creates daemon.log as 0640, but rotation replaces it, and
    # whichever process logs first afterwards was the one deciding the mode.
    # The daemon sets umask(0027) and got 0640; the CLI and the WHM CGI set
    # none, so a root shell with the usual umask 022 produced a world-readable
    # log holding blocked addresses, account names taken from authentication
    # logs, and the WHM policy-change audit trail. /var/log/hostguard is 0750,
    # so nothing could reach it - but that is the directory's guarantee, not
    # this file's, and only one of the two is stated here.
    sysopen(my $fh, $LOG_FILE, O_WRONLY | O_APPEND | O_CREAT, 0640) or return;
    flock($fh, LOCK_EX);
    print $fh $line;
    close($fh);

    # Also print to STDERR if running in foreground debug mode
    if ($LOG_LEVEL >= 3) {
        print STDERR $line;
    }
}

# When this process last looked at the log's size.
#
# The size check ran on every single line, in every process that logs, which is
# a stat per event - and under the flood that fills the log, events are what
# there is a lot of. Once a second is as often as a rotation threshold can
# usefully be tested.
my $LAST_SIZE_CHECK = 0;

sub _rotate_if_needed {
    return unless $MAX_SIZE && $MAX_SIZE > 0;

    my $now = time();
    return if $now == $LAST_SIZE_CHECK;
    $LAST_SIZE_CHECK = $now;

    return unless -f $LOG_FILE;
    my $size = -s $LOG_FILE;
    return unless $size && $size > $MAX_SIZE;

    # One rotation at a time, across every process that logs.
    #
    # This took no lock, and the daemon, each CLI invocation and each CGI
    # request all run it. Two processes crossing the threshold together
    # interleaved as:
    #
    #   P1: rename(LOG, LOG.1)          LOG.1 now holds the rotated log
    #   P2: rename(LOG.1, LOG.1.old)    P1's rotated log moves aside
    #   P2: rename(LOG, LOG.1)          fails; LOG is gone. Ignored.
    #   P2: unlink(LOG.1.old)           P1's rotated log is deleted
    #
    # so the log covering an attack was destroyed during the attack, silently.
    # The lock is a separate file because the log itself is about to be renamed
    # and a lock on a file that is being replaced belongs to the old inode.
    #
    # Non-blocking: if another process holds it, that process is already doing
    # the rotation and there is nothing to wait for.
    my $lockfile = "$LOG_FILE.rotate";
    sysopen(my $lock, $lockfile, O_WRONLY | O_CREAT, 0600) or return;
    unless (flock($lock, LOCK_EX | LOCK_NB)) {
        close($lock);
        return;
    }

    # Re-checked under the lock. The loser of the race would otherwise rotate a
    # file that has just been rotated and is now empty.
    my $recheck = -s $LOG_FILE;
    unless (defined $recheck && $recheck > $MAX_SIZE) {
        close($lock);
        return;
    }

    # Two generations, renamed oldest first, so no temporary name is needed and
    # nothing has to be deleted to make room. Shuffling through a temporary name
    # instead would give a concurrent rotation something to destroy.
    unlink("$LOG_FILE.2", "$LOG_FILE.2.gz");
    for my $pair (["$LOG_FILE.1.gz", "$LOG_FILE.2.gz"],
                  ["$LOG_FILE.1",    "$LOG_FILE.2"]) {
        rename($pair->[0], $pair->[1]) if -f $pair->[0];
    }
    rename($LOG_FILE, "$LOG_FILE.1");

    # Compression is detached. gzip on a log large enough to have tripped the
    # threshold is not work to do on the daemon's main loop, and the rotation
    # is already complete without it.
    if (-f "$LOG_FILE.1" && -x '/usr/bin/gzip') {
        my $pid = fork();
        if (defined $pid && $pid == 0) {
            # Child: detach from the parent's descriptors, including the lock,
            # so releasing it does not wait on the compression.
            close($lock);
            open(STDIN,  '<', '/dev/null');
            open(STDOUT, '>', '/dev/null');
            open(STDERR, '>', '/dev/null');
            exec { '/usr/bin/gzip' } '/usr/bin/gzip', '-q', "$LOG_FILE.1"
                or POSIX::_exit(127);
        }
        # The parent does not wait. A caller with SIGCHLD set to IGNORE leaves
        # nothing to reap; one without it reaps on its next wait, and a stray
        # zombie from a log rotation is not worth a signal handler here.
    }

    close($lock);
    return;
}

# Read the last N lines of the log.
#
# The file is walked backwards in blocks from the end, so a log of tens of
# megabytes costs only the tail in memory rather than the whole file.
sub tail {
    my ($class, $lines) = @_;
    $lines //= 50;
    return () unless -f $LOG_FILE;

    open(my $fh, '<', $LOG_FILE) or return ();
    binmode($fh);
    my $size = -s $fh;
    unless ($size) {
        close($fh);
        return ();
    }

    my $block = 8192;
    my $pos   = $size;
    my $data  = '';
    while ($pos > 0) {
        my $read = $pos < $block ? $pos : $block;
        $pos -= $read;
        seek($fh, $pos, 0) or last;
        my $buf;
        read($fh, $buf, $read) or last;
        $data = $buf . $data;
        last if (($data =~ tr/\n//) > $lines);
        last if length($data) > 4 * 1024 * 1024;
    }
    close($fh);

    my @all = split(/\n/, $data);
    shift @all if $pos > 0 && @all;    # drop the partial first line
    my $start = @all > $lines ? @all - $lines : 0;
    return @all[$start .. $#all];
}

1;
