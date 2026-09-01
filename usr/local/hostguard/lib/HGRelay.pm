package HGRelay;
###############################################################################
# HostGuard Pro - Outbound Mail Tracking
# /usr/local/hostguard/lib/HGRelay.pm
#
# Counts what leaves the host by mail, per account and per sending script, and
# reports an account or script that sends more in an hour than it should.
#
# A compromised site almost always shows itself here first. The account is
# real, the credentials are real, and nothing in the firewall or the login
# logs looks wrong - the only visible symptom is the volume.
#
# Exim writes one line per accepted message, marked "<=", carrying the sender
# and, depending on how the message was submitted, one of:
#
#   A=...      the authenticated account, for mail sent through SMTP AUTH
#   U=...      the Unix account, for mail handed to the sendmail binary
#   cwd=...    the directory the sending script ran from
#
# Counts are held per clock hour and persisted, so a restart does not reset an
# account that is midway through sending too much.
###############################################################################
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
use HGConfig;
use HGLogger;
use HGAlert;

sub _state_file { return "$HGConfig::DATA_DIR/relay.state" }

# Message acceptance line. Only "<=" lines are counted: they are the point at
# which the host takes responsibility for a message, and each appears once.
# Delivery lines ("=>") would count a message once per recipient.
our $ARRIVAL = qr/\s<=\s/;

# Accounts whose mail is never counted. System mail - cron output, bounces,
# the daemon's own notices - is not what this check is for, and counting it
# would put a floor under every account's numbers.
our @SYSTEM_SENDERS = qw(root mailnull exim nobody daemon cpanel);

my %COUNTS;
my $LOADED = 0;
my $DIRTY  = 0;

###############################################################################
# Line processing
###############################################################################

# Examine one exim log line and count it if it is a message arrival.
#
# Returns the account it was attributed to, or undef. The daemon calls this
# for every line it reads from the mail log, so it does the least work it can
# before deciding the line is uninteresting.
sub process_line {
    my ($class, $line, $config) = @_;

    return undef unless ($config->{RELAY_TRACK} // '0') eq '1';
    return undef unless $line =~ $ARRIVAL;

    my ($account, $source) = _attribute($line);
    return undef unless defined $account;

    return undef if _is_system_sender($account);

    _load_state();

    my $hour = int(time() / 3600);
    my $slot = $COUNTS{$account};
    if (!$slot || ($slot->{hour} // -1) != $hour) {
        $COUNTS{$account} = { hour => $hour, count => 0, source => $source // '' };
        $slot = $COUNTS{$account};
    }
    $slot->{count}++;
    $slot->{source} = $source if defined $source && length $source;
    $DIRTY = 1;

    return $account;
}

# Work out who a message should be counted against.
#
# Authenticated submission is the most specific attribution and is preferred.
# Otherwise the Unix account is used, and the script directory is carried
# alongside so a report can name the file rather than only the account.
sub _attribute {
    my ($line) = @_;

    my ($account, $source);

    # The envelope sender is skipped before anything is looked for.
    #
    # Exim writes "<= <sender>" and then its own keyed fields, and for inbound
    # mail the sender is chosen by whoever is sending. The markers were looked
    # for anywhere on the line, so a sender of
    #
    #     "x U=victim"@evil.com
    #
    # attributed an inbound message to the local account "victim", and an
    # injected cwd= supplied the script path the alert then reported. Since the
    # alert ident is the account and the hour, twenty forged messages naming
    # twenty accounts consumed the whole hour's ceiling for this notice kind -
    # so a genuinely compromised account sending real spam in the same hour was
    # reported to nobody.
    #
    # Everything up to and including the sender token is discarded, and the
    # keyed fields are read only from what exim wrote after it.
    # The sender may be a quoted string, and a quoted string may contain
    # spaces - which is the whole of the trick. "x U=victim"@evil.com is one
    # address and four space-separated tokens, so consuming \S+ leaves
    # " U=victim\"@evil.com" behind for the marker search to find. The quoted
    # form is consumed as a unit, with the domain that follows it.
    # The sender may be a quoted string, and a quoted string may contain
    # spaces - which is the whole of the trick. "x U=victim"@evil.com is one
    # address and four space-separated tokens, so consuming \S+ leaves
    # ` U=victim"@evil.com` behind for the marker search to find. The quoted
    # form is consumed as a unit, together with the domain that follows it.
    my $fields = $line;
    unless ($fields =~ s/^.*?\s<=\s+("[^"]*"\S*|\S+)\s+//s) {
        # No sender token after the marker. Nothing can be attributed from a
        # line whose shape is not the one exim writes.
        return (undef, undef);
    }
    my $sender = $1;

    # And refused outright if the sender carried a marker at all.
    #
    # Belt and braces on top of consuming it correctly. Whatever a given exim
    # build's log quoting does, an envelope sender containing U=, A= or cwd= is
    # not something to attribute a count from, and saying so explicitly means
    # the intent survives a future edit to the pattern above.
    if (defined $sender && $sender =~ /(?:^|[^A-Za-z])(?:U|A|cwd)=/) {
        HGLogger->log_warn("Ignoring a mail line whose envelope sender carries "
                         . "what looks like an exim field marker, so it cannot "
                         . "be attributed to an account: $sender");
        return (undef, undef);
    }

    if ($fields =~ /^A=(?:dovecot_|courier_|fixed_)?(?:login|plain|cram_md5):(\S+)/i
        || $fields =~ /\sA=(?:dovecot_|courier_|fixed_)?(?:login|plain|cram_md5):(\S+)/i) {
        $account = $1;
    } elsif ($fields =~ /^U=(\S+)/ || $fields =~ /\sU=(\S+)/) {
        $account = $1;
    }

    if ($fields =~ /^cwd=(\S+)/ || $fields =~ /\scwd=(\S+)/) {
        $source = $1;
        # Reported to an operator as the directory a script ran from, so it is
        # held to the shape of a path rather than passed through as written.
        $source = '' unless $source =~ m{^/[\w./+-]*$};
    }

    # A message with neither marker came from outside; inbound mail is not
    # this check's business.
    return (undef, undef) unless defined $account;

    # Strip a domain from an authenticated identity so bob and bob@example.com
    # are one account rather than two.
    $account =~ s/\@.*$// if $account =~ /\@/;
    $account =~ s/[^A-Za-z0-9._-]//g;
    return (undef, undef) unless length $account;

    return ($account, $source);
}

###############################################################################
# Reporting
###############################################################################

# Report every account over the hourly limit.
#
# Called on a timer rather than per message, so an account that crosses the
# limit mid-burst is reported once for the hour rather than on every message
# after the threshold.
sub check {
    my ($class, $config, %opt) = @_;

    return 0 unless ($config->{RELAY_TRACK} // '0') eq '1';

    my $limit = $config->{RELAY_LIMIT} // 0;
    return 0 unless $limit =~ /^\d+$/ && $limit > 0;

    _load_state();
    _save_state();

    my $hour     = int(time() / 3600);
    my $reported = 0;

    for my $account (sort keys %COUNTS) {
        my $slot = $COUNTS{$account};
        next unless ($slot->{hour} // -1) == $hour;
        next unless $slot->{count} > $limit;

        $reported++;
        my $source = length($slot->{source} // '') ? $slot->{source} : 'not recorded';

        HGLogger->log_warn("Account $account has sent $slot->{count} messages "
                         . "this hour (limit $limit)");

        HGAlert->send(
            kind    => 'relay',
            config  => $config,
            subject => "$account has sent $slot->{count} messages this hour",
            # Keyed on the account and the hour, so a sustained sender is
            # reported once an hour rather than on every check inside it.
            ident   => "$account\0$hour",
            vars    => {
                ACCOUNT => $account,
                COUNT   => $slot->{count},
                LIMIT   => $limit,
                SOURCE  => $source,
            },
            body    => "Account:  $account\n"
                     . "Messages: $slot->{count} in the current hour\n"
                     . "Limit:    $limit\n"
                     . "Script:   $source\n\n"
                     . "This is a report only; no mail has been blocked and no "
                     . "account has been suspended.\n\n"
                     . "If the account is not expected to send at this rate, "
                     . "check the directory above for a script that is sending "
                     . "on its behalf.\n",
        ) unless $opt{quiet};
    }

    return $reported;
}

# Current hour's counts, highest first, for the status output and WHM page.
sub top_senders {
    my ($class, $limit) = @_;
    $limit //= 10;

    _load_state();
    my $hour = int(time() / 3600);

    my @rows;
    for my $account (keys %COUNTS) {
        my $slot = $COUNTS{$account};
        next unless ($slot->{hour} // -1) == $hour;
        push @rows, {
            account => $account,
            count   => $slot->{count},
            source  => $slot->{source} // '',
        };
    }

    @rows = sort { $b->{count} <=> $a->{count} || $a->{account} cmp $b->{account} } @rows;
    @rows = @rows[0 .. $limit - 1] if @rows > $limit;

    return @rows;
}

sub _is_system_sender {
    my ($account) = @_;
    for my $s (@SYSTEM_SENDERS) {
        return 1 if $account eq $s;
    }
    return 0;
}

###############################################################################
# State
###############################################################################

sub _load_state {
    return if $LOADED;
    $LOADED = 1;
    %COUNTS = ();

    return unless -f _state_file();
    open(my $fh, '<', _state_file()) or return;
    flock($fh, LOCK_SH);

    my $hour = int(time() / 3600);
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;
        my ($account, $h, $count, $source) = split(/\t/, $line, 4);
        next unless defined $account && defined $h && defined $count;
        next unless $h =~ /^\d+$/ && $count =~ /^\d+$/;
        # An entry from a previous hour can never be reported again, so it is
        # dropped on the way in rather than carried forward.
        next unless $h == $hour;
        $COUNTS{$account} = { hour => $h, count => $count, source => $source // '' };
    }
    close($fh);
}

sub _save_state {
    return unless $DIRTY;
    $DIRTY = 0;

    my $hour = int(time() / 3600);
    my $out  = '';
    for my $account (sort keys %COUNTS) {
        my $s = $COUNTS{$account};
        next unless ($s->{hour} // -1) == $hour;
        my $source = $s->{source} // '';
        $source =~ s/[\t\n]/ /g;
        $out .= "$account\t$s->{hour}\t$s->{count}\t$source\n";
    }

    eval { HGConfig::_write_atomic(_state_file(), $out); 1 }
        or HGLogger->debug("Cannot save relay state: $@");
    chmod(0600, _state_file());
}

# Flush counters to disk. The daemon calls this before it exits so a shutdown
# does not lose the current hour.
sub flush {
    _save_state();
    return 1;
}

sub reset_state {
    _save_state();
    $LOADED = 0;
    %COUNTS = ();
    return 1;
}

1;
