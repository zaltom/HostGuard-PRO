package HGFirewall;
###############################################################################
# HostGuard Pro - Firewall Engine Module
# /usr/local/hostguard/lib/HGFirewall.pm
#
# Manages iptables/ip6tables rules with ipset for performance.
# Supports stateful rules, allowlist/denylist, port filtering, and
# connection limits.
#
# Note: this module drives the iptables command only. On a host using the
# nftables backend it relies on the iptables-nft compatibility shim, which is
# the default on AlmaLinux/Rocky 8+. There is no native nftables support.
#
# Commands are executed via _run/_run_quiet, which take an argument list and
# exec directly. No command string is ever handed to a shell, so values taken
# from the configuration and IP lists cannot be interpreted as shell syntax.
# Callers must pass a list, never a pre-joined string.
###############################################################################
use strict;
use warnings;
use Fcntl qw(:DEFAULT :flock);
use HGConfig;
use HGLogger;
use HGBlocklist;
use HGGeo;
use HGNotice;

my $IPTABLES;
my $IP6TABLES;
my $IPSET;
my $USE_IPSET;
my $IPV6;

# Chain and ipset names carry a slot suffix, _A or _B.
#
# Two slots allow a ruleset to be swapped in without ever leaving the host
# unfiltered. A start or reload assembles a complete ruleset in whichever slot
# is idle while the live slot continues to filter traffic, attaches it by
# inserting a jump at the top of each built-in chain, and only then dismantles
# the slot it replaced. At no point is the host without rules.
#
# Attaching is two commands, or four with IPv6, and iptables cannot issue them
# as one. It is made all-or-nothing instead: see _activate_slot.
#
# The swap is only safe if the assembled ruleset is complete, so every command
# that builds one is checked. A rule that iptables rejects is counted, and a
# slot with any such failure is never activated: it is torn down and the slot
# already serving traffic carries on. Rules that only add a refinement - flood
# mitigation, rate limits, logging - are run through _run_opt instead, so a
# kernel without xt_recent loses flood protection rather than the firewall.
#
# Teardown also recognises the unsuffixed names, so any HostGuard chain or set
# present on the host is removed regardless of which slot created it.
my @SLOTS = ('_A', '_B');

my $SLOT;
my ($CHAIN_IN, $CHAIN_OUT, $CHAIN_DENY, $CHAIN_ALLOW, $CHAIN_LOGDROP,
    $CHAIN_SYNFLOOD, $CHAIN_SCAN, $CHAIN_GEO, $CHAIN6_IN, $CHAIN6_OUT,
    $CHAIN6_DENY, $CHAIN6_ALLOW, $CHAIN6_GEO,
    $CHAIN6_LOGDROP, $CHAIN6_SYNFLOOD, $CHAIN6_SCAN);

# Advanced filter lines - "tcp|in|d=22|s=10.0.0.5" - get four chains of their
# own, one per direction and per verdict.
#
# The chains exist so that where an advanced filter sits is decided in one
# place, alongside every other ordering decision, rather than by where in the
# build it happens to be emitted.
#
# The allow and deny lists are loaded after the rest of the ruleset is
# assembled. A filter written straight into the input chain would therefore
# have to be inserted, and an insert lands at position 1 - above the loopback
# accept, above ESTABLISHED,RELATED, above the allowlist match.
#
# That position matters in both directions, and wrongly in each. A
# "tcp|in|d=22" line in deny.conf is the documented way to restrict SSH; it
# has to sit below the allowlist, or a reload cuts off the administrator's own
# session along with everyone else's. A "tcp|in|d=80" line in allow.conf has to
# sit above the deny and temporary block sets, because that is what an
# allowlist entry means - and below the state match, so it does not exempt the
# port from the connection tracking the rest of the ruleset depends on.
#
# With the rules in chains, the jump decides the position, and appending inside
# each chain preserves the order the lines appear in the file.
my ($CHAIN_AALLOW_IN, $CHAIN_AALLOW_OUT, $CHAIN_ADENY_IN, $CHAIN_ADENY_OUT);
my ($SET_ALLOW4, $SET_DENY4, $SET_TEMP4, $SET_ALLOW6, $SET_DENY6, $SET_TEMP6);

# Commands that failed while a ruleset was being built. A slot with any entry
# here is never activated, so anything that contributes to a ruleset being
# complete records its failures here rather than logging and moving on.
# Declared with the other file-level state because it is written from both
# ends of this file.
my @BUILD_FAILURES;

# The largest timeout an ipset entry can carry, in seconds - a little over 24
# days. ipset refuses anything longer, and a refused add is not a longer block
# but no block at all, so a duration past this is brought down to it rather
# than being sent to the kernel to fail. Both the operations that take a
# duration and the restore paths that read one back off disk clamp here.
our $MAX_TIMEOUT = 2147483;

# Temporary allows and the bogon set.
#
# A temporary allow is held in its own set rather than in the allow set, so it
# expires on its own without rewriting allow.conf, and so that a permanent
# allow is never removed by an expiring one.
my ($SET_TALLOW4, $SET_TALLOW6, $SET_BOGON4, $SET_BOGON6);

# Block list definitions for the rebuild in progress.
#
# Set creation, rule emission and set population each need the same list, and
# reading blocklists.conf once means all three agree even if the file is edited
# while a rebuild is running.
my @BLOCKLISTS;
my $BLOCKLISTS_LOADED = 0;

sub _blocklists {
    unless ($BLOCKLISTS_LOADED) {
        @BLOCKLISTS = HGBlocklist->load();
        $BLOCKLISTS_LOADED = 1;
    }
    return @BLOCKLISTS;
}

# Discard the cached definitions so the next read picks up the file again.
sub _reset_blocklists {
    @BLOCKLISTS = ();
    $BLOCKLISTS_LOADED = 0;
}

# Point every chain and set name at the given slot.
sub _use_slot {
    my ($slot) = @_;
    $slot = '' unless defined $slot;
    $SLOT = $slot;

    $CHAIN_IN       = "HOSTGUARD_IN$slot";
    $CHAIN_OUT      = "HOSTGUARD_OUT$slot";
    $CHAIN_DENY     = "HOSTGUARD_DENY$slot";
    $CHAIN_ALLOW    = "HOSTGUARD_ALLOW$slot";
    $CHAIN_LOGDROP  = "HOSTGUARD_LOGDROP$slot";
    $CHAIN_SYNFLOOD = "HOSTGUARD_SYNFLOOD$slot";
    $CHAIN_SCAN     = "HOSTGUARD_SCAN$slot";
    $CHAIN_GEO      = "HOSTGUARD_GEO$slot";
    $CHAIN_AALLOW_IN  = "HOSTGUARD_AALLOW_IN$slot";
    $CHAIN_AALLOW_OUT = "HOSTGUARD_AALLOW_OUT$slot";
    $CHAIN_ADENY_IN   = "HOSTGUARD_ADENY_IN$slot";
    $CHAIN_ADENY_OUT  = "HOSTGUARD_ADENY_OUT$slot";
    $CHAIN6_IN      = "HOSTGUARD6_IN$slot";
    $CHAIN6_OUT     = "HOSTGUARD6_OUT$slot";
    $CHAIN6_DENY    = "HOSTGUARD6_DENY$slot";
    $CHAIN6_ALLOW   = "HOSTGUARD6_ALLOW$slot";
    $CHAIN6_GEO     = "HOSTGUARD6_GEO$slot";
    $CHAIN6_LOGDROP = "HOSTGUARD6_LOGDROP$slot";
    $CHAIN6_SYNFLOOD= "HOSTGUARD6_SYNFLOOD$slot";
    $CHAIN6_SCAN    = "HOSTGUARD6_SCAN$slot";

    # ipset names are lowercase by convention; all stay under the 31-char cap.
    my $t = lc($slot);
    $SET_ALLOW4 = "hg_allow4$t";
    $SET_DENY4  = "hg_deny4$t";
    $SET_TEMP4  = "hg_tempblock4$t";
    $SET_ALLOW6 = "hg_allow6$t";
    $SET_DENY6  = "hg_deny6$t";
    $SET_TEMP6  = "hg_tempblock6$t";

    $SET_TALLOW4 = "hg_tempallow4$t";
    $SET_TALLOW6 = "hg_tempallow6$t";
    $SET_BOGON4  = "hg_bogon4$t";
    $SET_BOGON6  = "hg_bogon6$t";
    return $slot;
}
_use_slot('_A');

# ipset name for one country's ranges in the current slot.
#
# A country code is two characters, so "hgc6_" plus the code plus the slot
# suffix stays well inside the kernel's 31 character limit.
sub _geo_set {
    my ($cc, $family) = @_;
    my $prefix = ($family && $family eq 'inet6') ? 'hgc6_' : 'hgc_';
    return $prefix . lc($cc) . lc($SLOT);
}

# Country codes for the rebuild in progress, read once for the same reason the
# block list definitions are: set creation, rule emission and population must
# all agree even if the configuration changes underneath them.
my @GEO_CODES;
my $GEO_MODE          = '';
my $GEO_LOADED        = 0;

# Which families got a country allowlist during this build, so a policy that is
# off everywhere can be told from one that is only off for a family that has
# something to filter. See _apply_geo_rules and _check_geo_symmetry.
my %GEO_ALLOW_APPLIED;

sub _geo {
    my ($config) = @_;
    unless ($GEO_LOADED) {
        # HGGeo reads a plain hash; the firewall carries an HGConfig object.
        my %flat = $config->config();
        ($GEO_MODE, @GEO_CODES) = HGGeo->mode(\%flat);
        $GEO_LOADED = 1;
    }
    return ($GEO_MODE, @GEO_CODES);
}

sub _reset_geo {
    @GEO_CODES  = ();
    $GEO_MODE   = '';
    $GEO_LOADED = 0;
    %GEO_ALLOW_APPLIED = ();
}

# ipset name for one external block list in the current slot.
#
# The kernel caps a set name at 31 characters, which HGBlocklist enforces by
# limiting a list name to 24: "hgb6_" plus the name plus a slot suffix.
sub _bl_set {
    my ($name, $family) = @_;
    my $prefix = ($family && $family eq 'inet6') ? 'hgb6_' : 'hgb_';
    return $prefix . lc($name) . lc($SLOT);
}

# The slot currently serving traffic. The next rebuild targets the other one.
#
# The file is the record, not the authority. The kernel is the authority: the
# slot serving traffic is whichever HOSTGUARD_IN chain is jumped to from
# INPUT, and that is true whatever this file says. When the two disagree the
# file is wrong, so it is checked against the kernel rather than believed.
# What the record says, or undef if it says nothing usable.
sub _read_slot_file {
    my $f = "$HGConfig::DATA_DIR/active_slot";

    my $v;
    if (open(my $fh, '<', $f)) {
        $v = <$fh>;
        close($fh);
        chomp $v if defined $v;
    }

    return (defined $v && grep { $_ eq $v } @SLOTS) ? $v : undef;
}

sub _read_slot {
    my $v = _read_slot_file();
    return $v if defined $v;

    # No usable record. Rather than guessing at _A - which is how a lost file
    # came to mean "tear down whatever is running" - ask the kernel.
    my $live = _detect_slot();
    if (defined $live && length $live) {
        HGLogger->log_warn("$HGConfig::DATA_DIR/active_slot does not name a "
                         . "usable slot, but slot $live is attached to INPUT; "
                         . "using that");
        return $live;
    }

    return undef;
}

# The slot serving traffic, with the kernel deciding when the two disagree.
#
# Costs one "iptables -S INPUT", so it is used where that is affordable: once
# when a process initialises, when a ruleset is rebuilt, and on the daemon's
# minute timer. The per-operation path reads the record alone, which is why
# the checks that do run correct the record rather than only their own idea of
# the slot.
sub _live_slot {
    my ($quiet) = @_;

    my $record = _read_slot_file();
    my $live   = _detect_slot();

    # Nothing of ours is attached: the firewall is stopped, or was never
    # started. The record is all there is, and nothing it names is filtering
    # anything, so there is nothing to disagree about.
    return $record unless defined $live && length $live;

    if (!defined $record || $record ne $live) {
        HGLogger->log_warn("The recorded active slot ("
                         . (defined $record ? $record : 'none')
                         . ") is not the one attached to INPUT ($live). "
                         . "The kernel decides; the record is wrong.")
            unless $quiet;
    }

    return $live;
}

# Correct the record if it has stopped matching the kernel.
#
# The window this closes is small and real: a crash between attaching a slot
# and recording it leaves both slots attached, the new one on top, and the
# record naming the old one. Nothing rolls that back, because nothing runs.
#
# Until the record is corrected, every operation that reads it acts on the
# outgoing slot - and because that slot's sets still exist, the operation
# succeeds. An address is added to a set that nothing consults, and reported
# as blocked. That is the one place left where this could still say something
# untrue, so it is checked on a timer rather than waited out until the next
# reload.
#
# Returns the slot in force.
sub verify_slot {
    my ($class) = @_;

    my $record = _read_slot_file();
    my $live   = _detect_slot();
    return $record unless defined $live && length $live;
    return $live if defined $record && $record eq $live;

    my $got = HGFirewall->_with_lock('verify_slot', sub {
        # Read again under the lock: a rebuild may have been half way through
        # the swap when this looked, and be finished now.
        my $r = _read_slot_file();
        my $l = _detect_slot();
        return $r unless defined $l && length $l;
        return $l if defined $r && $r eq $l;

        HGLogger->log_warn("The recorded active slot ("
                         . (defined $r ? $r : 'none')
                         . ") is not the one attached to INPUT ($l); "
                         . "correcting the record. Operations taken since the "
                         . "two diverged may have gone to the wrong slot.");

        _write_slot($l);
        _use_slot($l);
        return $l;
    });

    # _with_lock returns 0 when it could not take the lock, and 0 is not a
    # slot: passed on, it would build chain names with no suffix at all. What
    # the kernel said before the lock was attempted is the better answer.
    return (defined $got && grep { $_ eq $got } @SLOTS) ? $got : $live;
}

# Which slot is attached to INPUT right now, according to iptables.
#
# Returns the suffix ('_A', '_B'), the empty string for an unsuffixed chain
# left by an older release, or undef when nothing of ours is attached - which
# is the ordinary answer on a host where the firewall is stopped.
#
# iptables lists rules in order, so the first jump found is the topmost one,
# and the topmost one is the one deciding traffic.
sub _detect_slot {
    return undef unless $IPTABLES && -x $IPTABLES;

    my ($rc, $out) = _exec($IPTABLES, '-S', 'INPUT');
    return undef if $rc;

    for my $line (split(/\n/, $out // '')) {
        next unless $line =~ /^-A\s+INPUT\b/;
        return defined $1 ? $1 : '' if $line =~ /-j\s+HOSTGUARD_IN(_A|_B)?\s*$/;
    }
    return undef;
}

# Record the live slot so later invocations act on the correct chains and sets.
#
# Returns whether the record was written, and the caller must act on that
# rather than carry on.
#
# By the time this runs the new slot is attached and filtering, so a record
# still naming the old one describes a ruleset that is about to be dismantled.
# Every short-lived caller would then operate on destroyed chains, and - the
# part that costs the host its protection - the next rebuild would read the
# stale name, pick "the other slot", and tear down the one actually serving
# traffic.
sub _write_slot {
    my ($slot) = @_;
    my $file = "$HGConfig::DATA_DIR/active_slot";

    unless (eval { HGConfig::_write_atomic($file, "$slot\n"); 1 }) {
        my $err = $@ || 'unknown error';
        chomp $err;
        HGLogger->error("Cannot record active slot in $file: $err");
        return 0;
    }
    return 1;
}

###############################################################################
# Initialization
###############################################################################

sub init {
    my ($class, $config) = @_;

    # A configured path is checked before it is believed; see _safe_bin.
    $IPTABLES  = _safe_bin($config->get('IPTABLES'),  'IPTABLES')  || _find_bin('iptables');
    $IP6TABLES = _safe_bin($config->get('IP6TABLES'), 'IP6TABLES') || _find_bin('ip6tables');
    $IPSET     = _safe_bin($config->get('IPSET'),     'IPSET')     || _find_bin('ipset');
    $USE_IPSET = ($config->get('LF_IPSET') // 1) && $IPSET;
    $IPV6      = $config->get('IPV6') // 0;

    unless ($IPTABLES && -x $IPTABLES) {
        HGLogger->error("FATAL: iptables not found. Cannot start firewall.");
        return 0;
    }

    _detect_ipt_wait();

    # Adopt the slot that is serving traffic. Short-lived callers - the CLI
    # adding a deny, the daemon installing a temporary block - must operate on
    # the live slot's chains and sets. start() selects its own target slot
    # after calling init().
    #
    # This read is a starting position, not a fact to be relied on afterwards.
    # A long-lived caller like the daemon calls init() once and then runs for
    # weeks, during which any number of reloads can swap the slot underneath
    # it. Every operation that touches the live ruleset therefore re-reads the
    # slot while holding the firewall lock rather than trusting what was read
    # here; see _with_lock.
    # Reconciled against the kernel rather than read from the record alone,
    # and the record is corrected where it is wrong.
    #
    # Correcting our own idea of the slot would not be enough: every operation
    # takes the firewall lock and re-reads the record on the way in, so a
    # stale record would be read straight back over it. The record is what
    # every later reader believes, so the record is what has to be right.
    #
    # It costs one "iptables -S INPUT" per process, and only takes the lock in
    # the rare case where there is something to correct. That is what lets a
    # CLI invocation or a restarted daemon recover at once from a record left
    # stale by a crash between attaching a slot and recording it.
    my $slot = HGFirewall->verify_slot();
    _use_slot((defined $slot && grep { $_ eq $slot } @SLOTS) ? $slot : '_A');

    # An address family nothing is filtering, said plainly.
    #
    # With IPV6=0 no ip6tables chain is built and none is attached, so the v6
    # policy stays ACCEPT with no rules: every port open, and no allowlist,
    # denylist, block list, country rule or temporary block applying to a
    # single packet. That is the right default for a host with no IPv6 and a
    # complete bypass of the product for one that has it, and the two cases are
    # indistinguishable from the log unless the difference is said out loud.
    if (!$IPV6 && _has_global_ipv6()) {
        HGLogger->error("IPV6=0, but this host has a global IPv6 address. "
                      . "Nothing is filtering IPv6: every port is open on it, "
                      . "and no allow, deny, block list, country rule or "
                      . "temporary block applies. Set IPV6=1 in "
                      . "hostguard.conf and reload, or remove the address.");
    }

    HGLogger->info("Firewall engine initialized: iptables=$IPTABLES ipset=" .
                    ($USE_IPSET ? $IPSET : "disabled") .
                    " ipv6=" . ($IPV6 ? "yes" : "no"));
    return 1;
}

# Whether this host holds an IPv6 address that the internet can reach.
#
# Read from /proc rather than by running "ip", so it costs nothing and works
# in the units' restricted environments. Column two of each line is the
# interface index and the last column the scope; a global address has scope 0
# and is not on the loopback interface.
sub _has_global_ipv6 {
    open(my $fh, '<', '/proc/net/if_inet6') or return 0;
    while (my $line = <$fh>) {
        my @f = split(/\s+/, $line);
        next unless @f >= 6;
        next if $f[0] =~ /^0{31}1$/;          # ::1
        next if $f[0] =~ /^fe80/i;            # link local
        next unless hex($f[3]) == 0;          # scope: 0 is global
        next if ($f[5] // '') eq 'lo';
        close($fh);
        return 1;
    }
    close($fh);
    return 0;
}

# The directories a firewall binary may live in, and the file checks applied to
# one, both come from HGConfig now.
#
# There were two implementations: this module's, which checked ownership, mode
# and every parent directory, and HGConfig::find_bin's, which checked only that
# the path was executable - and curl, wget, sendmail, systemctl and ip are all
# found through that one and all run as root. Two standards for the same act.
# HGConfig holds the definition; this delegates to it.
our @BIN_DIRS = @HGConfig::BIN_DIRS;

sub _find_bin {
    my ($name) = @_;
    return HGConfig::find_bin($name);
}

# Where a firewall binary may live, and what it must look like.
#
# These three paths are exec'd as root on every operation, and all three can be
# named in hostguard.conf. Only root can write that file today - the WHM plugin
# is gated on Whostmgr::ACLS::hasroot() and RESTRICT_UI defaults to 1 - so this
# is not a privilege boundary being crossed now. It is the boundary itself:
# the safety rests entirely on who can edit one file, and the first time this
# plugin is given a narrower WHM ACL so that a reseller can manage blocks,
# these keys become root code execution with no other change.
#
# Checked here so that the guarantee is a property of the code rather than of a
# configuration decision made elsewhere.
sub _safe_bin {
    my ($path, $label) = @_;
    return '' unless defined $path && length $path;

    # The directory test below is a string prefix test, so it has to be given a
    # path that cannot walk out of what it matches. "/bin/../home/user/evil"
    # starts with "/bin/" and resolves somewhere else entirely; the ownership
    # checks caught every case an unprivileged account could plant a file on,
    # but a confinement that can be walked out of is not doing the job it is
    # there for.
    unless ($path =~ m{^(?:/[\w.+-]+)+$}) {
        HGLogger->error("Ignoring $label '$path': a path here must be "
                      . "absolute and free of '..' and unusual characters");
        return '';
    }

    unless (grep { index($path, "$_/") == 0 } @BIN_DIRS) {
        HGLogger->error("Ignoring $label '$path': a firewall binary must live "
                      . "in one of " . join(', ', @BIN_DIRS));
        return '';
    }
    return '' unless _exec_safe_file($path, $label);
    return $path;
}

# True when a path is a regular, executable, root-owned file that no other
# account can rewrite - including through a directory above it.
#
# The parent walk is the part worth having. A hook that is itself mode 0755
# root:root but sits in a directory a user can write to can be replaced by
# replacing the file, and the mode on the old inode says nothing about that.
sub _exec_safe_file {
    my ($path, $label) = @_;
    return HGConfig::safe_to_exec($path, $label);
}

# A configured hook script, or the empty string if it is not safe to run.
#
# PRE_SCRIPT, POST_SCRIPT and BLOCK_REPORT run as root exactly as the firewall
# binaries do; they are only allowed a wider choice of directory because a site
# hook has nowhere obvious to live.
sub safe_hook {
    my ($class, $path, $label) = @_;
    return '' unless defined $path && length $path;
    unless ($path =~ m{^(?:/[\w.+-]+)+$}) {
        HGLogger->error("Ignoring $label '$path': it must be an absolute path, "
                      . "free of '..' and unusual characters");
        return '';
    }
    return _exec_safe_file($path, $label) ? $path : '';
}

# Arguments that make iptables wait for the xtables lock, if it can.
#
# Since iptables 1.6 every invocation takes an exclusive kernel lock, and
# without -w a second one does not queue: it exits non-zero at once with
# "another app is currently holding the xtables lock". A rebuild issues about a
# hundred commands, so anything else on the host touching iptables during one -
# dockerd publishing a container port, firewalld reloading, fail2ban installing
# a ban, a cPanel maintenance script - wins the race for one of them.
#
# One lost command inside _build_rules becomes a build failure, and start()
# then correctly refuses to activate the slot. So the fail-closed design turns
# a transient, entirely recoverable conflict into a firewall that will not
# reload at all - on a Docker host, intermittently and for no visible reason.
# In _run_live the same contention makes an individual block or allow fail.
#
# The seconds are explicit. A bare -w waits forever, and _exec has no timeout
# of its own, so a bare -w would trade a spurious failure for a hung daemon.
my @IPT_WAIT;

sub _detect_ipt_wait {
    @IPT_WAIT = ();
    return unless $IPTABLES && -x $IPTABLES;

    # -w with a seconds argument arrived in 1.6.0; a bare -w in 1.4.20. Probe
    # for what is there rather than parsing a version string.
    my ($rc) = _exec_raw($IPTABLES, '-w', '5', '-L', 'INPUT', '-n');
    if (!$rc) {
        @IPT_WAIT = ('-w', '5');
    } else {
        ($rc) = _exec_raw($IPTABLES, '-w', '-L', 'INPUT', '-n');
        @IPT_WAIT = ('-w') if !$rc;
    }

    if (@IPT_WAIT) {
        HGLogger->debug("iptables lock wait: " . join(' ', @IPT_WAIT));
    } else {
        HGLogger->log_warn("This iptables does not support -w, so a rebuild "
                         . "that collides with another program writing rules "
                         . "will fail rather than wait. Expect occasional "
                         . "reload failures on a host also running Docker, "
                         . "firewalld or fail2ban.");
    }
    return;
}

###############################################################################
# High-level operations
###############################################################################

sub start {
    my ($class, $config) = @_;

    $class->init($config);

    # Waits rather than failing: a runtime block that arrived a moment
    # earlier holds this for milliseconds, and that is no reason to
    # refuse a rebuild.
    my $lock = HGConfig->get_lock_wait('firewall', 60);

    HGLogger->info("Starting HostGuard Pro firewall...");

    # Run pre-script if configured
    my $pre = HGFirewall->safe_hook($config->get('PRE_SCRIPT'), 'PRE_SCRIPT');
    if ($pre) {
        HGLogger->info("Running pre-script: $pre");
        system { $pre } $pre;
    }

    _reset_blocklists();
    _reset_geo();
    _reset_failures();

    # Assemble into the idle slot so the live one keeps filtering throughout.
    #
    # Which slot is idle is decided against the kernel, not against the record
    # alone. Trusting a record that is missing or stale would send this into
    # "_A", and the teardown two lines below would then dismantle _A while it
    # was the slot serving traffic - leaving the host unfiltered for the length
    # of a rebuild, which is the one thing the two slots exist to prevent.
    my $old = _live_slot();

    my $new = (defined $old && $old eq '_A') ? '_B' : '_A';
    _use_slot($new);

    # Ensure the target slot is empty before building into it.
    $class->_teardown_slot($new);

    # Create ipsets
    $class->_setup_ipsets() if $USE_IPSET;
    $class->_setup_blocklist_sets($config);
    $class->_setup_geo_sets($config);

    # Create and populate the chains. They are not yet reachable from
    # INPUT/OUTPUT.
    $class->_build_rules($config);
    $class->_build_rules6($config) if $IPV6;

    # Both families are built by now, so a country allowlist that reached one
    # and not the other can be seen for what it is.
    $class->_check_geo_symmetry($config);

    # Populate the allow, deny and temporary block entries. This must finish
    # before the slot is activated: a live chain with an empty allowlist would
    # drop the very addresses the allowlist exists to protect.
    $class->_load_allowlist($config);
    $class->_load_denylist($config);
    $class->_load_tempblocks();
    $class->_load_tempallows();
    $class->_load_blocklists($config) if $USE_IPSET;
    $class->_load_bogon($config);
    $class->_load_bogon6($config);
    $class->_load_geo($config);

    # Refuse to put an incomplete ruleset in front of the host.
    #
    # Up to here nothing has been activated, so the slot already serving
    # traffic is untouched and stays that way. Activating a slot whose
    # allowlist match, deny match or port rules failed to load would either
    # let through what should be blocked or block what should be let through,
    # and the only trace would be lines in the log while the CLI reported
    # success.
    #
    # On a first start there is no previous slot to fall back to, so the host
    # is left unfiltered. That is the lesser harm: a firewall nobody can
    # reason about is worse than a reported failure, and the log names every
    # command that failed.
    my @failed = _build_failures();
    if (@failed) {
        HGLogger->error("Refusing to activate slot $new: " . scalar(@failed)
                      . " rule(s) failed to load.");
        HGLogger->error("  failed: $_->{cmd}") for @failed;

        $class->_teardown_slot($new);
        _use_slot($old // '_A');

        if (defined $old) {
            HGLogger->error("The previously loaded ruleset (slot $old) is "
                          . "still in force.");
        } else {
            HGLogger->error("No previous ruleset was loaded, so the host is "
                          . "NOT being filtered.");
        }

        close($lock);
        die "Firewall not started: " . scalar(@failed)
          . " rule(s) failed to load. See "
          . ($config->get('LOG_FILE') // '/var/log/hostguard/daemon.log')
          . " for each one.
";
    }

    # Activate. From here this slot is the one filtering traffic.
    #
    # If it could not be attached, nothing of it remains attached either, so
    # the slot that was already serving is still doing so. Stop before the
    # teardown below, which would otherwise dismantle the only working rules
    # on the host.
    unless ($class->_activate_slot()) {
        HGLogger->error("Refusing to complete the swap to slot $new: the "
                      . "chains could not be attached.");

        $class->_teardown_slot($new);
        _use_slot($old // '_A');

        if (defined $old) {
            HGLogger->error("The previously loaded ruleset (slot $old) is "
                          . "still in force.");
        } else {
            HGLogger->error("No previous ruleset was loaded, so the host is "
                          . "NOT being filtered.");
        }

        close($lock);
        die "Firewall not started: the ruleset was built but could not be "
          . "attached to INPUT and OUTPUT. See "
          . ($config->get('LOG_FILE') // '/var/log/hostguard/daemon.log')
          . " for the command that failed.
";
    }

    # Recording the live slot is part of the swap, not a note about it. If it
    # cannot be written the swap is undone: the new jumps come out, the new slot
    # is torn down, and the ruleset that was already in force - still built and
    # still attached below the jumps just removed - governs traffic again, which
    # is what the unchanged record already says.
    unless (_write_slot($new)) {
        HGLogger->error("Refusing to complete the swap to slot $new: the "
                      . "active slot could not be recorded, and a slot nothing "
                      . "records is one the next rebuild would tear down while "
                      . "it was serving traffic.");

        $class->_deactivate_slot();
        $class->_teardown_slot($new);
        _use_slot($old // '_A');

        if (defined $old) {
            HGLogger->error("The previously loaded ruleset (slot $old) is "
                          . "still in force.");
        } else {
            HGLogger->error("No previous ruleset was loaded, so the host is "
                          . "NOT being filtered.");
        }

        close($lock);
        die "Firewall not started: the ruleset was built and attached but the "
          . "active slot could not be recorded, so the swap was undone. See "
          . ($config->get('LOG_FILE') // '/var/log/hostguard/daemon.log')
          . " for the reason.\n";
    }

    # The notice redirect lives in the nat table, outside the slot mechanism,
    # so it is applied once the new slot's temporary block set is the live one.
    $class->_apply_notice_redirect($config);

    # The replaced slot is unreachable now, so dismantle it. Unsuffixed chains
    # and sets are cleared at the same time.
    if (defined $old && $old ne $new) {
        $class->_teardown_slot($old);
    }
    $class->_teardown_slot('');
    _use_slot($new);

    # Run post-script if configured
    my $post = HGFirewall->safe_hook($config->get('POST_SCRIPT'), 'POST_SCRIPT');
    if ($post) {
        HGLogger->info("Running post-script: $post");
        system { $post } $post;
    }

    # Record start time
    _write_file("$HGConfig::DATA_DIR/firewall.started", time());

    HGLogger->info("HostGuard Pro firewall started successfully (slot $new).");
    close($lock);
    return 1;
}

sub stop {
    my ($class) = @_;
    HGLogger->info("Stopping HostGuard Pro firewall...");

    # Waits rather than failing: a runtime block that arrived a moment
    # earlier holds this for milliseconds, and that is no reason to
    # refuse a rebuild.
    my $lock = HGConfig->get_lock_wait('firewall', 60);

    # The notice redirect is in the nat table and belongs to no slot, so it is
    # removed explicitly. Left behind, it would send traffic to a responder
    # that is no longer listening.
    $class->_clear_notice_redirect();

    # Remove every slot, along with any unsuffixed chains and sets.
    for my $slot (@SLOTS, '') {
        $class->_teardown_slot($slot);
    }
    _use_slot('_A');

    # Put back the default policies HostGuard Pro changed - which is the IPv4
    # FORWARD policy, and only when it was recorded. Everything else is left
    # as it is: see the policy section below for why setting them all to
    # ACCEPT was reaching into another firewall's configuration.
    _restore_policies();

    unlink("$HGConfig::DATA_DIR/firewall.started");
    unlink("$HGConfig::DATA_DIR/active_slot");
    HGLogger->info("HostGuard Pro firewall stopped.");
    close($lock);
    return 1;
}

# A reload is a start: it assembles the idle slot and swaps to it. It does not
# stop the firewall first, so the host stays filtered for the whole operation.
sub reload {
    my ($class, $config) = @_;
    HGLogger->info("Reloading HostGuard Pro firewall rules...");
    $class->start($config);
    return 1;
}

sub status {
    my ($class) = @_;
    my $started_file = "$HGConfig::DATA_DIR/firewall.started";
    if (-f $started_file) {
        open(my $fh, '<', $started_file);
        my $ts = <$fh>;
        close($fh);
        chomp $ts if $ts;
        return { running => 1, since => $ts };
    }
    return { running => 0 };
}

###############################################################################
# ipset management
###############################################################################

sub _setup_ipsets {
    # Any set left from an earlier run is destroyed before being recreated.
    #
    # The temporary block sets hold entries with per-entry timeouts, which
    # ipset only accepts on a set created with the timeout option, so those two
    # are created with "timeout 0" - no default expiry, per-entry expiry
    # allowed.
    my %needs_timeout = (
        $SET_TEMP4   => 1, $SET_TEMP6   => 1,
        $SET_TALLOW4 => 1, $SET_TALLOW6 => 1,
    );

    for my $set ($SET_ALLOW4, $SET_DENY4, $SET_TEMP4, $SET_TALLOW4, $SET_BOGON4) {
        _run_quiet($IPSET, 'destroy', $set);
        _run($IPSET, 'create', $set, 'hash:net', 'family', 'inet',
             'hashsize', '4096', 'maxelem', '1000000',
             ($needs_timeout{$set} ? ('timeout', '0') : ()));
    }
    if ($IPV6) {
        for my $set ($SET_ALLOW6, $SET_DENY6, $SET_TEMP6, $SET_TALLOW6, $SET_BOGON6) {
            _run_quiet($IPSET, 'destroy', $set);
            _run($IPSET, 'create', $set, 'hash:net', 'family', 'inet6',
                 'hashsize', '4096', 'maxelem', '1000000',
                 ($needs_timeout{$set} ? ('timeout', '0') : ()));
        }
    }
}

# Destroy the current slot's sets, leaving its chains in place.
sub _destroy_ipsets {
    for my $set ($SET_ALLOW4, $SET_DENY4, $SET_TEMP4, $SET_TALLOW4, $SET_BOGON4,
                 $SET_ALLOW6, $SET_DENY6, $SET_TEMP6, $SET_TALLOW6, $SET_BOGON6) {
        _run_quiet($IPSET, 'destroy', $set);
    }
}

###############################################################################
# Bogon ranges
###############################################################################

# Source addresses that cannot legitimately arrive from the internet.
#
# A packet claiming one of these as its source on a public interface is
# forged; nothing routable can be behind such an address. They are held in
# their own set so the check costs one lookup rather than a rule per range.
our @BOGON_RANGES = (
    '0.0.0.0/8',          # this network
    '127.0.0.0/8',        # loopback
    '169.254.0.0/16',     # link local
    '192.0.0.0/24',       # IETF protocol assignments
    '192.0.2.0/24',       # documentation
    '198.18.0.0/15',      # benchmarking
    '198.51.100.0/24',    # documentation
    '203.0.113.0/24',     # documentation
    '224.0.0.0/4',        # multicast, never a unicast source
    '240.0.0.0/4',        # reserved
);

# Ranges that are unroutable on the internet but entirely normal on a private
# network. Filtered only when BOGON_PRIVATE is on, because a host with an
# internal interface, a VPN or a container bridge legitimately receives them.
our @BOGON_PRIVATE = (
    '10.0.0.0/8',
    '100.64.0.0/10',      # carrier-grade NAT
    '172.16.0.0/12',
    '192.168.0.0/16',
);

# Fill the bogon set from the tables above.
# Source addresses that cannot legitimately arrive from the internet over IPv6.
#
# BOGON_ENABLE covers both address families, so there is a list for each.
#
# Deliberately shorter than the IPv4 list. IPv6 has no address exhaustion to
# have produced the same accretion of special ranges, and the ones that matter
# are the ones a forged packet actually uses: unspecified, loopback, the
# documentation and benchmarking prefixes, and - the important one - anything
# outside the currently allocated global unicast space. Link-local is not
# listed: it is legitimate on a local segment and is what neighbour discovery
# runs over, so dropping it would break IPv6 itself.
our @BOGON_RANGES6 = (
    '::/128',               # unspecified
    '::1/128',              # loopback
    '::ffff:0:0/96',        # IPv4-mapped, never valid on the wire
    '64:ff9b::/96',         # NAT64, not a routable source here
    '100::/64',             # discard-only
    '2001:db8::/32',        # documentation
    '2001:2::/48',          # benchmarking
    '3fff::/20',            # documentation (RFC 9637)
    '5f00::/16',            # reserved
    'ff00::/8',             # multicast, never a unicast source
);

# Held back behind BOGON_PRIVATE, exactly as the IPv4 list holds back RFC1918.
#
# fc00::/7 was in the default list, which is not what the v4 side does and is
# wrong for the same reason: a host using unique local addressing internally
# has legitimate traffic from this range, and dropping it by default would cut
# a management network off from the thing meant to be protecting it.
our @BOGON_PRIVATE6 = (
    'fc00::/7',             # unique local
    'fe80::/10',            # link local - never a source from off-link
);

sub _load_bogon6 {
    my ($class, $config) = @_;
    return unless $USE_IPSET && $IPV6;
    return unless ($config->get('BOGON_ENABLE') // '0') eq '1';

    my @ranges = @BOGON_RANGES6;
    push @ranges, @BOGON_PRIVATE6 if ($config->get('BOGON_PRIVATE') // '0') eq '1';

    unless (_ipset_fill($SET_BOGON6, \@ranges)) {
        _note_load_failure('IPv6 bogon ranges', scalar(@ranges),
                           scalar(@ranges), $ranges[0]);
        return;
    }
    HGLogger->info("IPv6 bogon ranges loaded: " . scalar(@ranges));
}

sub _load_bogon {
    my ($class, $config) = @_;
    return unless $USE_IPSET;
    return unless ($config->get('BOGON_ENABLE') // '0') eq '1';

    my @ranges = @BOGON_RANGES;
    push @ranges, @BOGON_PRIVATE if ($config->get('BOGON_PRIVATE') // '0') eq '1';

    unless (_ipset_fill($SET_BOGON4, \@ranges)) {
        _note_load_failure('Bogon ranges', scalar(@ranges), scalar(@ranges), undef);
        return;
    }

    HGLogger->info("Bogon filtering active with " . scalar(@ranges) . " ranges");
}

###############################################################################
# Country ranges
###############################################################################

# Create one set per configured country, per family.
sub _setup_geo_sets {
    my ($class, $config) = @_;
    return unless $USE_IPSET;

    my ($mode, @codes) = _geo($config);
    return unless $mode && @codes;

    for my $cc (@codes) {
        my $set = _geo_set($cc, 'inet');
        _run_quiet($IPSET, 'destroy', $set);
        _run($IPSET, 'create', $set, 'hash:net', 'family', 'inet',
             'hashsize', '8192', 'maxelem', '1000000');

        next unless $IPV6;
        my $set6 = _geo_set($cc, 'inet6');
        _run_quiet($IPSET, 'destroy', $set6);
        _run($IPSET, 'create', $set6, 'hash:net', 'family', 'inet6',
             'hashsize', '4096', 'maxelem', '1000000');
    }
}

# Fill each country's sets from its cached zone file.
sub _load_geo {
    my ($class, $config) = @_;
    return unless $USE_IPSET;

    my ($mode, @codes) = _geo($config);
    return unless $mode && @codes;

    # The rules were emitted from what is on disk, before this ran. If the
    # ranges then fail to reach the set, the rules stay and the set is empty -
    # and in allow mode that is not a country filter that does nothing, it is
    # a chain that returns for nobody and drops everything. The guard against
    # applying GEO_ALLOW with no ranges checks the files; this is the same
    # check against what actually loaded.
    my $failed = 0;
    my $example;

    for my $cc (@codes) {
        my @v4 = HGGeo->cached_ranges($cc, 'inet');
        if (@v4 && !_ipset_fill(_geo_set($cc, 'inet'), \@v4)) {
            $failed++;
            $example //= "$cc (inet)";
        }

        if ($IPV6) {
            my @v6 = HGGeo->cached_ranges($cc, 'inet6');
            if (@v6 && !_ipset_fill(_geo_set($cc, 'inet6'), \@v6)) {
                $failed++;
                $example //= "$cc (inet6)";
            }
        }

        HGLogger->info("Country $cc: " . scalar(@v4) . " IPv4 range(s) loaded");
    }

    return _note_load_failure("Country ranges ($mode mode)", $failed,
                              scalar(@codes), $example)
        if $failed;
}

# Emit the country match rules for one family.
#
# In deny mode each country is sent to the drop chain. In allow mode the
# countries are accepted and everything else falls through to a final drop,
# which is emitted by the caller so it lands after the port rules.
#
# An allow mode whose sets are all empty is refused outright. Applying it
# would drop every packet from everywhere, including the administrator's, on
# the strength of a zone file that failed to download.
sub _apply_geo_rules {
    my ($class, $config, $family) = @_;
    return 0 unless $USE_IPSET;

    my ($mode, @codes) = _geo($config);
    return 0 unless $mode && @codes;

    my $v6    = ($family eq 'inet6');
    return 0 if $v6 && !$IPV6;
    my $cmd   = $v6 ? $IP6TABLES : $IPTABLES;
    my $chain = $v6 ? $CHAIN6_IN : $CHAIN_IN;
    my $drop  = $v6 ? 'DROP'     : $CHAIN_LOGDROP;
    return 0 unless $cmd;

    my $loaded = 0;
    for my $cc (@codes) {
        $loaded += scalar(HGGeo->cached_ranges($cc, $family));
    }

    if ($mode eq 'allow' && !$loaded) {
        HGLogger->error("GEO_ALLOW is set but no $family ranges have been "
                      . "downloaded; not applying it, because it would drop "
                      . "all traffic. Run 'hostguard -c force' first.");

        # Applying a country allowlist to one address family and not the other
        # is worse than applying it to neither. Each family is built by its own
        # call, and a call that decided this alone would leave a host with IPv6
        # enabled but no v6 zone files downloaded with IPv4 fenced to the
        # permitted countries and IPv6 reachable from everywhere - an intact
        # policy on paper and a way around it in practice.
        #
        # If the other family did get the policy, this is a divergence, and a
        # divergence is a build failure: start() will not activate the slot and
        # the ruleset already in force carries on. If neither family has data the
        # policy is simply not in force anywhere, which is visible, symmetric
        # and what the message above already describes.
        if (%GEO_ALLOW_APPLIED) {
            my $msg = "GEO_ALLOW is in force for one address family and cannot "
                    . "be applied to $family, which would leave $family "
                    . "reachable from every country while the other family is "
                    . "restricted. Refusing the ruleset. Run "
                    . "'hostguard -c force', or set IPV6=0 if this host does "
                    . "not serve IPv6.";
            HGLogger->error($msg);
            push @BUILD_FAILURES, { cmd => $msg, rc => -1, out => '' };
        }
        return 0;
    }
    return 0 unless $loaded;

    if ($mode eq 'deny') {
        # One rule per country, sending its traffic to the drop chain.
        for my $cc (@codes) {
            next unless HGGeo->cached_ranges($cc, $family);
            _run($cmd, '-A', $chain, '-m', 'set',
                 '--match-set', _geo_set($cc, $family), 'src', '-j', $drop);
        }
        return 0;
    }

    # Allow mode runs in its own chain, which returns for an address in one of
    # the allowed countries and drops everything else.
    #
    # The distinction matters: accepting here instead of returning would accept
    # the packet outright, on any port, before the port rules have been
    # consulted. That would turn a country allowlist into an instruction to
    # open the whole host to those countries.
    my $geo_chain = $v6 ? $CHAIN6_GEO : $CHAIN_GEO;
    _run($cmd, '-N', $geo_chain);
    $GEO_ALLOW_APPLIED{$family} = 1;

    for my $cc (@codes) {
        next unless HGGeo->cached_ranges($cc, $family);
        _run($cmd, '-A', $geo_chain, '-m', 'set',
             '--match-set', _geo_set($cc, $family), 'src', '-j', 'RETURN');
    }
    _run($cmd, '-A', $geo_chain, '-j', $drop);
    _run($cmd, '-A', $chain, '-j', $geo_chain);

    return 0;
}

# Destroy every country set belonging to a slot.
#
# The live sets are discovered from ipset rather than from the configuration,
# so a country removed from the configuration still has its set cleaned up.
sub _destroy_geo_sets {
    my ($slot) = @_;
    return unless $IPSET;

    my $suffix = lc($slot);
    my (undef, $out) = _exec($IPSET, 'list', '-n');
    for my $name (split(/\n/, ($out // ''))) {
        $name =~ s/^\s+//;
        $name =~ s/\s+$//;
        next unless length $name;
        next unless $name =~ /^hgc6?_.*\Q$suffix\E$/;
        _run_quiet($IPSET, 'destroy', $name);
    }
}

# Replace a live country set's contents without a firewall reload, using the
# same atomic swap the block lists use.
#
# Taken under the firewall lock, like every other operation on the running
# ruleset. Without it this is a check followed by an act on a slot that the
# check said was live: a reload landing in between destroys that slot, and the
# swap then either fails or lands in a set nothing matches. See _with_lock.
sub refresh_geo_set {
    my ($class, $cc, $family) = @_;
    return 0 unless $USE_IPSET;
    $family //= 'inet';
    return 0 if $family eq 'inet6' && !$IPV6;

    return HGFirewall->_with_lock('refresh_geo_set', sub {
        return _refresh_geo_set_locked($class, $cc, $family);
    });
}

sub _refresh_geo_set_locked {
    my ($class, $cc, $family) = @_;

    # The slot was re-read on the way in, so this is the set the live ruleset
    # matches on. If it is not there the country is not part of that ruleset
    # and a set created here would be one no rule refers to.
    my $live = _geo_set($cc, $family);
    unless (_set_exists($live)) {
        HGLogger->log_warn("Country $cc ($family) was not refreshed: the running "
                         . "ruleset has no set for it. It takes effect on the "
                         . "next firewall reload.");
        return 0;
    }

    my @ranges = HGGeo->cached_ranges($cc, $family);
    return 0 unless @ranges;

    # Refuse a set that has collapsed against what the live one is holding.
    #
    # HGGeo now refuses a truncated download before it reaches the cache, so
    # this should never fire. It is here because the two checks protect
    # different things and are reached by different paths: that one protects
    # the file, this protects the running firewall, and a cache file edited by
    # hand, restored from a backup, or left behind by an older release does not
    # go through the other check at all.
    #
    # It matters most in allow mode, where a collapsed set does not weaken a
    # block - it drops the traffic the country is allowed to send.
    my $live_count = _set_count($live);
    if (defined $live_count && $live_count >= $HGGeo::SHRINK_FLOOR) {
        my $floor = int($live_count * 40 / 100);
        if (scalar(@ranges) < $floor) {
            HGLogger->error("Country $cc ($family) was not refreshed: the "
                          . "cached copy holds " . scalar(@ranges) . " ranges "
                          . "against $live_count in the running set, which is "
                          . "too large a fall to apply without being asked. "
                          . "The ranges already loaded are still in force. If "
                          . "the smaller list is correct, reload the firewall.");
            return 0;
        }
    }

    # Every step is checked, and a failure at any of them leaves the live set
    # exactly as it was.
    #
    # None of them was checked before, so the three ways this goes wrong all
    # ended in the same place: "Country XX refreshed: N ranges" in the log and
    # N returned to the caller, with the live set holding whatever it held
    # before. A create that fails leaves nothing to fill; a fill that fails
    # leaves the temporary set short or empty; and a swap that fails leaves the
    # two sets exactly where they started. The last is the one that matters,
    # because the swap is the only step that changes what the firewall matches
    # on - so its failure is the difference between a country being blocked
    # and not.
    #
    # The block list refresh beside this one has always checked; this is the
    # same sequence with the same failures, and now says so too.
    my $tmp = substr("hgt_" . lc($cc) . lc($SLOT) . ($family eq 'inet6' ? '6' : ''), 0, 31);
    _run_quiet($IPSET, 'destroy', $tmp);

    my ($create_rc) = _run($IPSET, 'create', $tmp, 'hash:net', 'family', $family,
                           'hashsize', '8192', 'maxelem', '1000000');
    if ($create_rc) {
        HGLogger->error("Country $cc ($family) was not refreshed: the staging "
                      . "set could not be created. The ranges already loaded "
                      . "are still in force.");
        return 0;
    }

    my $count = _ipset_fill($tmp, \@ranges);
    unless ($count) {
        _run_quiet($IPSET, 'destroy', $tmp);
        HGLogger->error("Country $cc ($family) was not refreshed: the ranges "
                      . "could not be loaded into the staging set. The ranges "
                      . "already loaded are still in force.");
        return 0;
    }

    my ($swap_rc) = _run($IPSET, 'swap', $tmp, $live);
    _run_quiet($IPSET, 'destroy', $tmp);

    if ($swap_rc) {
        HGLogger->error("Country $cc ($family) was not refreshed: the staged "
                      . "ranges could not be swapped into $live. The ranges "
                      . "already loaded are still in force.");
        return 0;
    }

    HGLogger->info("Country $cc ($family) refreshed: $count ranges");
    return $count;
}

# How many entries a live set holds, or undef if it cannot be read.
#
# "ipset list -t" prints the header only, so this costs nothing even on a set
# with hundreds of thousands of members.
sub _set_count {
    my ($set) = @_;
    return undef unless $IPSET && defined $set && length $set;
    my ($rc, $out) = _run_quiet($IPSET, 'list', '-t', $set);
    return undef if $rc || !defined $out;
    return $out =~ /^Number of entries:\s*(\d+)/m ? $1 : undef;
}

###############################################################################
# External block lists
###############################################################################

# Confirm a country allowlist covers every family this host filters.
#
# _apply_geo_rules can only see the family it is building, and the families are
# built in a fixed order, so the check it makes catches the divergence in one
# direction only. This runs once both are done and catches it in either.
sub _check_geo_symmetry {
    my ($class, $config) = @_;

    my ($mode) = _geo($config);
    return unless $mode && $mode eq 'allow';
    return unless %GEO_ALLOW_APPLIED;

    my @want = ('inet');
    push @want, 'inet6' if $IPV6 && $IP6TABLES;

    my @missing = grep { !$GEO_ALLOW_APPLIED{$_} } @want;
    return unless @missing;

    my $msg = "GEO_ALLOW is in force for "
            . join(', ', sort keys %GEO_ALLOW_APPLIED)
            . " but not for " . join(', ', @missing)
            . ", which would leave that family reachable from every country "
            . "while the other is restricted. Refusing the ruleset. Run "
            . "'hostguard -c force' to fetch the missing zone files, or set "
            . "IPV6=0 if this host does not serve IPv6.";
    HGLogger->error($msg);
    push @BUILD_FAILURES, { cmd => $msg, rc => -1, out => '' };
    return;
}

# Emit one match rule per configured block list for the given family.
#
# Traffic from an address in a list is sent to the logging drop chain on IPv4
# and dropped directly on IPv6, matching how the deny list is handled.
sub _apply_blocklist_rules {
    my ($class, $config, $family) = @_;
    return unless $USE_IPSET;
    return unless ($config->get('BLOCKLIST_ENABLE') // 1);

    my $v6 = ($family eq 'inet6');
    return if $v6 && !($IPV6 && $IP6TABLES);

    my $cmd    = $v6 ? $IP6TABLES : $IPTABLES;
    my $chain  = $v6 ? $CHAIN6_IN : $CHAIN_IN;
    my $target = $v6 ? _valid_target($config->get('DROP_ACTION') // 'DROP')
                     : $CHAIN_LOGDROP;

    for my $entry (_blocklists()) {
        _run($cmd, '-A', $chain,
             '-m', 'set', '--match-set', _bl_set($entry->{name}, $family), 'src',
             '-j', $target);
    }
}


# Create one ipset per configured block list in the current slot.
#
# An IPv6 set is created only when the IPv6 firewall is active, since without
# it there are no ip6tables chains to match against.
sub _setup_blocklist_sets {
    my ($class, $config) = @_;
    return unless ($config->get('BLOCKLIST_ENABLE') // 1);

    # Block lists are held in ipsets, so they need LF_IPSET and a usable ipset
    # binary. Without those the lists are reported rather than silently absent.
    unless ($USE_IPSET) {
        my @lists = _blocklists();
        HGLogger->log_warn("Block lists are configured but ipset is unavailable; "
                         . scalar(@lists) . " list(s) will not be applied")
            if @lists;
        return;
    }

    for my $entry (_blocklists()) {
        _run($IPSET, 'create', _bl_set($entry->{name}, 'inet'),
             'hash:net', 'family', 'inet',
             'hashsize', '4096', 'maxelem', '1000000');
        if ($IPV6) {
            _run($IPSET, 'create', _bl_set($entry->{name}, 'inet6'),
                 'hash:net', 'family', 'inet6',
                 'hashsize', '4096', 'maxelem', '1000000');
        }
    }
}

# Fill each block list's sets from its cached copy.
#
# Entries are applied with "ipset restore", which loads the whole list in one
# call. Adding them individually would fork once per address, which for lists
# running to tens of thousands of entries dominates the time a reload takes.
sub _load_blocklists {
    my ($class, $config) = @_;
    return unless $USE_IPSET;
    return unless ($config->get('BLOCKLIST_ENABLE') // 1);

    for my $entry (_blocklists()) {
        my ($v4, $v6) = HGBlocklist->cached_entries($entry->{name});

        unless (@$v4 || @$v6) {
            HGLogger->log_warn("Blocklist $entry->{name} has no cached data yet; "
                             . "it will apply once downloaded");
            next;
        }

        # A fill that fails leaves the set empty, and an empty set matches
        # nothing: the rules for this list are in the ruleset either way, so
        # the slot would be activated as complete while the list it names
        # blocks no one.
        my $loaded = 0;
        my $failed = 0;

        if (@$v4) {
            my $n = _ipset_fill(_bl_set($entry->{name}, 'inet'), $v4);
            $n ? ($loaded += $n) : $failed++;
        }
        if ($IPV6 && @$v6) {
            my $n = _ipset_fill(_bl_set($entry->{name}, 'inet6'), $v6);
            $n ? ($loaded += $n) : $failed++;
        }

        if ($failed) {
            _note_load_failure("Blocklist $entry->{name}", $failed,
                               $failed + ($loaded ? 1 : 0), undef);
            next;
        }

        HGLogger->info("Blocklist $entry->{name} loaded: $loaded entries");
    }
}

# Replace the contents of a live block list set without a firewall reload.
#
# A temporary set is filled and then exchanged with the live one. "ipset swap"
# is atomic, so the rules matching this set never see it empty or partly
# populated.
sub refresh_blocklist_set {
    my ($class, $name) = @_;
    return 0 unless $USE_IPSET;

    return HGFirewall->_with_lock('refresh_blocklist_set', sub {
        return _refresh_blocklist_set_locked($class, $name);
    });
}

# Returns the number of entries now live, or 0 if the running firewall was
# not changed.
#
# 0 means the data already loaded is still what the firewall is matching on.
# That matters more here than for most operations, because the new copy is already
# on disk by the time this runs: "hostguard -b" and the WHM page both read the
# cache, so a failure here leaves them reporting a list as up to date while the
# kernel still has the old one. Nothing about that is visible unless it is
# said, so every path out of here that leaves the old data in place says so.
sub _refresh_blocklist_set_locked {
    my ($class, $name) = @_;

    my %stats;
    my ($v4, $v6) = HGBlocklist->cached_entries($name, \%stats);

    if ($stats{unreadable}) {
        HGLogger->error("Blocklist $name was not applied: its cached copy "
                      . "could not be read. The running firewall still has the "
                      . "previous data for it.");
        return 0;
    }
    if ($stats{missing}) {
        HGLogger->log_warn("Blocklist $name has no cached copy to apply yet.");
        return 0;
    }
    unless (@$v4 || @$v6) {
        HGLogger->error("Blocklist $name was not applied: its cached copy has "
                      . "no usable addresses. The running firewall still has "
                      . "the previous data for it.");
        return 0;
    }

    my $total  = 0;
    my $failed = 0;

    my @work = (['inet', $v4]);
    push @work, ['inet6', $v6] if $IPV6;

    for my $pair (@work) {
        my ($family, $entries) = @$pair;

        # A list with no addresses of this family is not a failure: plenty of
        # providers publish IPv4 only.
        next unless @$entries;

        # As with the country sets: the slot was re-read while the lock was
        # taken, so this name belongs to the ruleset serving traffic.
        my $live = _bl_set($name, $family);
        unless (_set_exists($live)) {
            HGLogger->log_warn("Blocklist $name ($family) was not applied: the "
                             . "running ruleset has no set for it. It takes "
                             . "effect on the next firewall reload.");
            $failed++;
            next;
        }

        my $tmp = 'hgb_swap' . lc($SLOT);

        _run_quiet($IPSET, 'destroy', $tmp);
        my ($rc) = _run($IPSET, 'create', $tmp, 'hash:net', 'family', $family,
                        'hashsize', '4096', 'maxelem', '1000000');
        if ($rc) {
            $failed++;
            next;
        }

        my $count = _ipset_fill($tmp, $entries);
        unless ($count) {
            _run_quiet($IPSET, 'destroy', $tmp);
            $failed++;
            next;
        }

        # The live set is deliberately not created here, so that a list
        # added to blocklists.conf since the last reload would "take effect" -
        # but the rules that match a list are emitted when the ruleset is
        # built, so a set created now is one nothing refers to. All that
        # produced was an orphaned set and a log line claiming the list had
        # been applied. It is reported as needing a reload instead, which is
        # what it needs.
        my ($swap_rc) = _run($IPSET, 'swap', $tmp, $live);
        _run_quiet($IPSET, 'destroy', $tmp);

        if ($swap_rc) {
            $failed++;
            next;
        }
        $total += $count;
    }

    # A partial apply is reported as a failure, not as the part that worked.
    # One family swapped and the other not leaves the firewall matching the
    # new list for one and the old list for the other, and returning the count
    # of the half that succeeded described that as an update.
    if ($failed) {
        HGLogger->error("Blocklist $name was not fully applied: $failed of "
                      . scalar(@work) . " set(s) could not be replaced, so the "
                      . "running firewall still has the previous data for "
                      . "them. Run 'hostguard -r' to rebuild from the cached "
                      . "copy.");
        return 0;
    }

    HGLogger->info("Blocklist $name applied to the running firewall: $total entries");
    return $total;
}

# Whether a set of this name exists on the host right now.
#
# Only meaningful while the firewall lock is held: without it the answer can
# stop being true between being read and being acted on, which is the whole of
# the stale-slot problem.
sub _set_exists {
    my ($set) = @_;
    return 0 unless $USE_IPSET && defined $set && length $set;
    my (undef, $out) = _exec($IPSET, 'list', '-n');
    return (($out // '') =~ /^\Q$set\E$/m) ? 1 : 0;
}

# Add every entry to a set in a single "ipset restore" call.
#
# restore reads its directives from a file, which keeps the address data off
# any command line. The file is written with the same atomic helper as the rest
# of the runtime state and removed once loaded.
sub _ipset_fill {
    my ($set, $entries) = @_;
    return 0 unless $entries && @$entries;

    # Streamed to the file, not assembled as one string first.
    #
    # Building the whole restore script with join() would hold it in memory
    # alongside the entry list it came from, and both are large. At the shipped
    # BLOCKLIST_MAX_SIZE of 20 MB a list is about 1.75 million addresses, where
    # the entry array and its de-duplication hash cost around 390 MB and the
    # script would add 270 MB on top - against the MemoryMax in
    # hostguardd.service. Exceeding that is a SIGKILL mid-refresh, which leaves
    # no log line of its own, so the symptom would be a daemon that restarts on
    # a timer for no visible reason.
    #
    # Writing line by line removes the larger of the two allocations. The entry
    # list is still the caller's, and BLOCKLIST_MAX_SIZE and a list's MAX are
    # what bound that.
    #
    # No atomic rename: this is a scratch file nothing else reads, so the
    # temporary-plus-rename dance would only mean writing it twice. O_EXCL so a
    # stale file from a killed run cannot be appended to.
    my $script = "$HGConfig::DATA_DIR/ipset-restore.$$";
    unlink($script);

    # Declared outside the test: a "my" inside the unless() condition is scoped
    # to the condition, not to the block after it.
    my $fh;
    unless (sysopen($fh, $script, O_WRONLY | O_CREAT | O_EXCL, 0600)) {
        HGLogger->error("Cannot stage ipset data for $set: $!");
        return 0;
    }

    my $wrote = 1;
    my $count = 0;
    for my $entry (@$entries) {
        unless (print $fh "add $set $entry\n") {
            $wrote = 0;
            last;
        }
        $count++;
    }
    my $err = $wrote ? '' : "$!";
    unless (close($fh)) {
        $err ||= "$!";
        $wrote = 0;
    }
    unless ($wrote) {
        unlink($script);
        HGLogger->error("Cannot stage ipset data for $set: $err (wrote $count "
                      . "of " . scalar(@$entries) . " entries)");
        return 0;
    }

    # -exist keeps a duplicate address in a provider's list from aborting the
    # whole restore.
    my ($rc, $out) = _run_quiet($IPSET, 'restore', '-exist', '-file', $script);
    unlink($script);

    if ($rc) {
        HGLogger->error("Loading $set failed (rc=$rc): $out");
        return 0;
    }
    return scalar(@$entries);
}

# Destroy every block list set belonging to a slot.
#
# The live sets are discovered from ipset rather than from the configuration,
# so a list removed from blocklists.conf still has its sets cleaned up.
sub _destroy_blocklist_sets {
    my ($slot) = @_;
    return unless $IPSET;
    $slot = defined $slot ? lc($slot) : '';

    my ($rc, $out) = _run_quiet($IPSET, 'list', '-n');
    return if $rc || !defined $out;

    for my $set (split(/\n/, $out)) {
        $set =~ s/^\s+//;
        $set =~ s/\s+$//;
        next unless $set =~ /^hgb6?_/;

        if ($slot eq '') {
            # Unsuffixed sets only; a set belonging to a slot is left alone.
            next if $set =~ /_[ab]$/;
        } else {
            next unless $set =~ /\Q$slot\E$/;
        }
        _run_quiet($IPSET, 'destroy', $set);
    }
}

###############################################################################
# Default policies
###############################################################################
#
# HostGuard Pro changes exactly one default policy: the IPv4 FORWARD policy,
# set from FORWARD_POLICY when a ruleset is built. INPUT and OUTPUT are
# filtered by jumping into our own chains from the top of each, and those
# chains end in an explicit drop, so their policies are never load-bearing
# here and never set here.
#
# stop() therefore restores that one policy and touches no other. Setting all
# six - INPUT, OUTPUT and FORWARD, for both families - to ACCEPT on the way out
# would not be undoing our own work: it would be deciding a question for
# whoever else is on the host. A server running CSF, firewalld, ufw, shorewall
# or a hand-written policy alongside HostGuard Pro would find its default
# policies opened by a HostGuard stop, and left that way until that other
# firewall happened to reload. Docker is the same story from a different
# direction: it owns FORWARD, and a stray ACCEPT there removes the isolation
# between its networks.
#
# So a policy is put back only where HostGuard Pro can show it changed it. The
# value it replaced is recorded the first time it is changed and restored on
# stop; anything not in that record is left exactly as it is.
sub _policy_file { return "$HGConfig::DATA_DIR/saved_policies"; }

sub _policy_cmd {
    my ($family) = @_;
    return ($family eq 'inet6') ? $IP6TABLES : $IPTABLES;
}

# A chain's current default policy, or undef if it cannot be read.
sub _read_policy {
    my ($family, $chain) = @_;

    my $cmd = _policy_cmd($family);
    return undef unless $cmd && -x $cmd;

    my ($rc, $out) = _exec($cmd, '-S', $chain);
    return undef if $rc;
    return ($out // '') =~ /^-P\s+\Q$chain\E\s+(\S+)/m ? $1 : undef;
}

# What the record holds, as "family|chain" => policy.
sub _saved_policies {
    my %saved;
    my $file = _policy_file();
    return %saved unless -f $file;

    open(my $fh, '<', $file) or return %saved;
    while (my $line = <$fh>) {
        chomp $line;
        my ($family, $chain, $policy) = split(/\|/, $line, 3);
        next unless defined $policy;
        next unless $family =~ /^inet6?$/ && $chain =~ /^[A-Z]+$/;
        next unless $policy =~ /^(ACCEPT|DROP|REJECT|QUEUE|RETURN)$/;
        $saved{"$family|$chain"} = $policy;
    }
    close($fh);
    return %saved;
}

# Record what a policy was, before changing it for the first time.
#
# Only the first value is kept. A reload calls this again, and by then the
# policy is the one HostGuard Pro set, so overwriting would replace the
# administrator's value with our own and restore the wrong thing on stop.
sub _remember_policy {
    my ($family, $chain) = @_;

    my %saved = _saved_policies();
    return 1 if exists $saved{"$family|$chain"};

    my $policy = _read_policy($family, $chain);
    unless (defined $policy) {
        HGLogger->log_warn("Cannot read the current $chain policy, so it will "
                         . "not be restored when HostGuard Pro stops");
        return 0;
    }

    my $file = _policy_file();
    open(my $fh, '>>', $file) or do {
        HGLogger->error("Cannot record the $chain policy in $file: $!");
        return 0;
    };
    flock($fh, LOCK_EX);
    my $ok = print $fh "$family|$chain|$policy\n";
    $ok = 0 unless close($fh);
    unless ($ok) {
        HGLogger->error("Cannot record the $chain policy in $file: $!");
        return 0;
    }
    chmod(0600, $file);

    HGLogger->info("Default $chain policy was $policy; recorded so it can be "
                 . "put back when HostGuard Pro stops");
    return 1;
}

# Put back the policies HostGuard Pro changed, and only those.
sub _restore_policies {
    my %saved = _saved_policies();

    unless (%saved) {
        HGLogger->info("No default policy is recorded as changed by HostGuard "
                     . "Pro, so none is being changed back. Any policy in "
                     . "force belongs to something else on this host and is "
                     . "left alone.");
        return;
    }

    for my $key (sort keys %saved) {
        my ($family, $chain) = split(/\|/, $key, 2);
        my $cmd = _policy_cmd($family);
        next unless $cmd && -x $cmd;

        my ($rc) = _run($cmd, '-P', $chain, $saved{$key});
        HGLogger->info("Default $chain policy restored to $saved{$key}")
            unless $rc;
    }

    unlink(_policy_file());
}

###############################################################################
# Chain creation and flushing
###############################################################################

# Remove one slot completely: unhook its chains from INPUT/OUTPUT, flush and
# delete them, then destroy its ipsets.
#
# Default policies are left alone. Relaxing a policy here would open the host
# for as long as the rebuild takes.
sub _teardown_slot {
    my ($class, $slot) = @_;

    my $saved = $SLOT;
    _use_slot($slot);

    for my $chain ($CHAIN_IN, $CHAIN_OUT, $CHAIN_DENY, $CHAIN_ALLOW,
                   $CHAIN_LOGDROP, $CHAIN_SYNFLOOD, $CHAIN_SCAN,
                   $CHAIN_GEO, $CHAIN_AALLOW_IN, $CHAIN_AALLOW_OUT,
                   $CHAIN_ADENY_IN, $CHAIN_ADENY_OUT) {
        # An interrupted run can leave a chain hooked in more than once, so
        # delete until no jump remains.
        for my $builtin ('INPUT', 'OUTPUT') {
            for (1 .. 10) {
                my ($rc) = _run_quiet($IPTABLES, '-D', $builtin, '-j', $chain);
                last if $rc;
            }
        }
        _run_quiet($IPTABLES, '-F', $chain);
        _run_quiet($IPTABLES, '-X', $chain);
    }

    if ($IP6TABLES) {
        for my $chain ($CHAIN6_IN, $CHAIN6_OUT, $CHAIN6_DENY, $CHAIN6_ALLOW,
                       $CHAIN6_GEO, $CHAIN6_LOGDROP, $CHAIN6_SYNFLOOD,
                       $CHAIN6_SCAN) {
            for my $builtin ('INPUT', 'OUTPUT') {
                for (1 .. 10) {
                    my ($rc) = _run_quiet($IP6TABLES, '-D', $builtin, '-j', $chain);
                    last if $rc;
                }
            }
            _run_quiet($IP6TABLES, '-F', $chain);
            _run_quiet($IP6TABLES, '-X', $chain);
        }
    }

    if ($IPSET) {
        for my $set ($SET_ALLOW4, $SET_DENY4, $SET_TEMP4, $SET_TALLOW4,
                     $SET_BOGON4, $SET_BOGON6, $SET_ALLOW6, $SET_DENY6, $SET_TEMP6,
                     $SET_TALLOW6) {
            _run_quiet($IPSET, 'destroy', $set);
        }
        _destroy_blocklist_sets($slot);
        _destroy_geo_sets($slot);
    }

    _use_slot($saved);
    return 1;
}

# Hook the current slot's chains into INPUT/OUTPUT.
#
# The jumps are inserted at the head of the built-in chains, so this slot takes
# precedence over any other the moment the first rule lands.
# Attach the slot's chains to the built-in ones.
#
# This is two commands, or four with IPv6, and iptables offers no way to issue
# them as one. What can be guaranteed is that either all of them take effect or
# none do: a jump that fails to insert causes the ones already inserted to be
# removed again, so the slot never ends up half attached.
#
# That matters because of what the caller does next. It records the new slot as
# live and dismantles the old one. Half an activation followed by that teardown
# would leave a direction with no rules at all: inbound filtered by the new
# slot, outbound by nothing, and a successful start reported.
#
# The order is deliberate. Inbound is attached first, so the brief moment
# between the two commands has the new slot filtering what arrives while the
# previous rules, or on a first start no rules, still govern what leaves. The
# reverse order would cut outbound traffic while inbound was still open.
#
# Returns 1 when the slot is attached, 0 when nothing was left attached.
# Detach the current slot's jumps, leaving its chains in place.
#
# The counterpart to _activate_slot, for undoing a swap that cannot be
# completed. Whatever was attached before this slot is still attached below it,
# so removing these jumps hands traffic back to it.
sub _deactivate_slot {
    my ($class) = @_;

    my @steps = (
        [$IPTABLES, 'INPUT',  $CHAIN_IN],
        [$IPTABLES, 'OUTPUT', $CHAIN_OUT],
    );
    if ($IPV6 && $IP6TABLES) {
        push @steps,
            [$IP6TABLES, 'INPUT',  $CHAIN6_IN],
            [$IP6TABLES, 'OUTPUT', $CHAIN6_OUT];
    }

    for my $step (@steps) {
        my ($cmd, $builtin, $chain) = @$step;
        # An interrupted run can leave a jump in more than once.
        for (1 .. 10) {
            my ($rc) = _run_quiet($cmd, '-D', $builtin, '-j', $chain);
            last if $rc;
        }
    }

    HGLogger->info("Firewall slot $SLOT detached.");
    return 1;
}

sub _activate_slot {
    my ($class) = @_;

    my @steps = (
        [$IPTABLES, 'INPUT',  $CHAIN_IN,  'IPv4 inbound'],
        [$IPTABLES, 'OUTPUT', $CHAIN_OUT, 'IPv4 outbound'],
    );
    if ($IPV6 && $IP6TABLES) {
        push @steps,
            [$IP6TABLES, 'INPUT',  $CHAIN6_IN,  'IPv6 inbound'],
            [$IP6TABLES, 'OUTPUT', $CHAIN6_OUT, 'IPv6 outbound'];
    }

    my @attached;
    for my $step (@steps) {
        my ($cmd, $builtin, $chain, $label) = @$step;

        my ($rc) = _run($cmd, '-I', $builtin, '-j', $chain);
        if ($rc) {
            HGLogger->error("Could not attach $label ($chain to $builtin); "
                          . "undoing the jumps already inserted so the slot is "
                          . "not left half active.");

            for my $done (reverse @attached) {
                my ($dcmd, $dbuiltin, $dchain) = @$done;
                _run_quiet($dcmd, '-D', $dbuiltin, '-j', $dchain);
            }
            return 0;
        }

        push @attached, $step;
    }

    HGLogger->info("Firewall slot $SLOT is now live ("
                 . scalar(@attached) . " jumps attached).");
    return 1;
}

###############################################################################
# Rule building - IPv4
###############################################################################

sub _build_rules {
    my ($class, $config) = @_;
    my $spi        = $config->get('LF_SPI') // 1;
    my $drop       = $config->get('DROP_ACTION') // 'DROP';
    my $drop_log   = $config->get('DROP_LOGGING') // 1;
    my $conntrack  = $config->get('USE_CONNTRACK') // 1;
    my $state_mod  = $conntrack ? "conntrack --ctstate" : "state --state";
    my $icmp_in    = $config->get('ICMP_IN') // 1;
    my $icmp_out   = $config->get('ICMP_OUT') // 1;
    my $icmp_rate  = $config->get('ICMP_IN_RATE') // '1/s';
    my $eth        = $config->get('ETH_DEVICE') // '';
    my $eth_skip   = $config->get('ETH_DEVICE_SKIP') // '';

    $drop = _valid_target($drop);
    my @state  = $conntrack ? ('-m', 'conntrack', '--ctstate')
                            : ('-m', 'state',     '--state');
    if (length $eth && !_valid_device($eth)) {
        HGLogger->error("Ignoring invalid ETH_DEVICE '$eth'; rules will not be "
                      . "restricted to a single interface.");
        $eth = '';
    }

    # The name has to belong to an interface that exists.
    #
    # _valid_device checks the shape of the name, not whether anything answers
    # to it, so "eth0" on a host whose interface is "ens192" passed, built
    # cleanly and activated. Every rule that carries -i eth0 then matches
    # nothing, traffic falls through to the unconditional drop at the end of
    # the chain, and because the ESTABLISHED,RELATED accept is interface-scoped
    # too, that includes the administrator's own live session. The firewall
    # comes up perfectly and the host goes silent.
    #
    # Refused rather than ignored: building for an interface that is not there
    # produces a working ruleset for an imaginary host, which is worse than
    # not building one.
    # /sys/class/net is the authority only where it is there to be consulted.
    # In a container or a namespace without sysfs mounted, every device reads as
    # missing, and refusing the ruleset on that basis would stop the firewall
    # starting on a host where it would otherwise have worked.
    if (length $eth && !-d '/sys/class/net') {
        HGLogger->log_warn("Cannot check whether ETH_DEVICE '$eth' exists: "
                         . "/sys/class/net is not present. Continuing, but "
                         . "confirm the interface name by hand - a wrong one "
                         . "silently drops every connection.");
    }
    elsif (length $eth && !-d "/sys/class/net/$eth") {
        my $msg = "ETH_DEVICE names '$eth', which is not an interface on this "
                . "host. Rules restricted to it would match nothing and every "
                . "connection, including the one you are reading this over, "
                . "would fall through to the default drop.";
        HGLogger->error($msg);
        push @BUILD_FAILURES, { cmd => $msg, rc => -1, out => '' };
        $eth = '';
    }
    my @iface  = length $eth ? ('-i', $eth) : ();
    my @oface  = length $eth ? ('-o', $eth) : ();

    # Create chains
    _run($IPTABLES, '-N', $CHAIN_IN);
    _run($IPTABLES, '-N', $CHAIN_OUT);
    _run($IPTABLES, '-N', $CHAIN_ALLOW);
    _run($IPTABLES, '-N', $CHAIN_DENY);
    _run($IPTABLES, '-N', $CHAIN_LOGDROP);
    _run($IPTABLES, '-N', $CHAIN_AALLOW_IN);
    _run($IPTABLES, '-N', $CHAIN_AALLOW_OUT);
    _run($IPTABLES, '-N', $CHAIN_ADENY_IN);
    _run($IPTABLES, '-N', $CHAIN_ADENY_OUT);

    # Log+drop chain
    if ($drop_log) {
        # The drop below is what protects the host; this only records it.
        _run_opt($IPTABLES, '-A', $CHAIN_LOGDROP, '-m', 'limit',
                 '--limit', '5/min', '--limit-burst', '10',
                 '-j', 'LOG', '--log-prefix', 'HG_DROP: ', '--log-level', '4');
    }
    _run($IPTABLES, '-A', $CHAIN_LOGDROP, '-j', $drop);

    # Loopback - always allow
    _run($IPTABLES, '-A', $CHAIN_IN,  '-i', 'lo', '-j', 'ACCEPT');
    _run($IPTABLES, '-A', $CHAIN_OUT, '-o', 'lo', '-j', 'ACCEPT');

    # Skip interfaces
    if ($eth_skip) {
        for my $dev (split(/,/, $eth_skip)) {
            $dev =~ s/\s//g;
            next unless $dev;
            unless (_valid_device($dev)) {
                HGLogger->error("Ignoring invalid ETH_DEVICE_SKIP entry: $dev");
                next;
            }
            # A "+" wildcard names a family of interfaces rather than one that
            # has to exist now, so only concrete names are checked.
            if ($dev !~ /\+$/ && -d '/sys/class/net'
                && !-d "/sys/class/net/$dev") {
                HGLogger->log_warn("ETH_DEVICE_SKIP names '$dev', which is not "
                                 . "an interface on this host; skipping it.");
                next;
            }
            _run($IPTABLES, '-A', $CHAIN_IN,  '-i', $dev, '-j', 'ACCEPT');
            _run($IPTABLES, '-A', $CHAIN_OUT, '-o', $dev, '-j', 'ACCEPT');
        }
    }

    # Stateful rules
    if ($spi) {
        _run($IPTABLES, '-A', $CHAIN_IN,  @iface, @state, 'ESTABLISHED,RELATED', '-j', 'ACCEPT');
        _run($IPTABLES, '-A', $CHAIN_OUT, @oface, @state, 'ESTABLISHED,RELATED', '-j', 'ACCEPT');
        # Drop invalid
        _run($IPTABLES, '-A', $CHAIN_IN,  @iface, @state, 'INVALID', '-j', $drop);
    }

    # Outbound advanced filters, allow before deny, and both after the state
    # match so an established conversation is not cut by a rule about new
    # ones. There is no allow or deny set for outbound traffic, so this is the
    # whole of the outbound list handling.
    _run($IPTABLES, '-A', $CHAIN_OUT, '-j', $CHAIN_AALLOW_OUT);
    _run($IPTABLES, '-A', $CHAIN_OUT, '-j', $CHAIN_ADENY_OUT);

    # Allowlist (checked before deny)
    if ($USE_IPSET) {
        _run($IPTABLES, '-A', $CHAIN_IN, @iface,
             '-m', 'set', '--match-set', $SET_ALLOW4, 'src', '-j', 'ACCEPT');
        # Temporary allows sit beside the permanent ones and are equally
        # final: an address allowed for an afternoon is not then examined by
        # the deny list, the block lists or the country rules.
        _run($IPTABLES, '-A', $CHAIN_IN, @iface,
             '-m', 'set', '--match-set', $SET_TALLOW4, 'src', '-j', 'ACCEPT');
    }
    _run($IPTABLES, '-A', $CHAIN_IN, '-j', $CHAIN_ALLOW);

    # Inbound advanced allows sit with the rest of the allowlist, above every
    # deny path, because that is what the allowlist means.
    _run($IPTABLES, '-A', $CHAIN_IN, '-j', $CHAIN_AALLOW_IN);

    # Forged source addresses. Placed after the allowlist so that an
    # administrator who has deliberately allowed a private range - a
    # management network, a VPN - is never cut off by this check.
    if ($USE_IPSET && ($config->get('BOGON_ENABLE') // '0') eq '1') {
        _run($IPTABLES, '-A', $CHAIN_IN, @iface,
             '-m', 'set', '--match-set', $SET_BOGON4, 'src', '-j', $CHAIN_LOGDROP);
    }

    # Denylist
    if ($USE_IPSET) {
        _run($IPTABLES, '-A', $CHAIN_IN, @iface,
             '-m', 'set', '--match-set', $SET_DENY4, 'src', '-j', $CHAIN_LOGDROP);
        _run($IPTABLES, '-A', $CHAIN_IN, @iface,
             '-m', 'set', '--match-set', $SET_TEMP4, 'src', '-j', $CHAIN_LOGDROP);
    }
    _run($IPTABLES, '-A', $CHAIN_IN, '-j', $CHAIN_DENY);

    # Inbound advanced denies sit with the rest of the denylist: below every
    # allow, above every port rule.
    _run($IPTABLES, '-A', $CHAIN_IN, '-j', $CHAIN_ADENY_IN);

    # External block lists. These sit below the allowlist, so an address the
    # administrator has allowed is never blocked by a third-party list.
    $class->_apply_blocklist_rules($config, 'inet');

    # Country filtering. Allow mode builds its own chain, so nothing further
    # is owed here.
    $class->_apply_geo_rules($config, 'inet');

    # Flood protection sits after the allow and deny checks. Rate limits
    # therefore never apply to loopback or to allowlisted addresses, and
    # traffic that is already blocked is not counted against them.
    $class->_apply_synflood($config, 'inet');
    $class->_apply_connlimits($config, 'inet');
    $class->_apply_portflood($config, 'inet');

    # ICMP
    if ($icmp_in) {
        if ($icmp_rate && $icmp_rate ne '0') {
            _run_opt($IPTABLES, '-A', $CHAIN_IN, @iface, '-p', 'icmp',
                 '--icmp-type', 'echo-request', '-m', 'limit',
                 '--limit', $icmp_rate, '-j', 'ACCEPT');
            _run($IPTABLES, '-A', $CHAIN_IN, @iface, '-p', 'icmp',
                 '--icmp-type', 'echo-request', '-j', $drop);
        } else {
            _run($IPTABLES, '-A', $CHAIN_IN, @iface, '-p', 'icmp',
                 '--icmp-type', 'echo-request', '-j', 'ACCEPT');
        }
    }

    # Open TCP incoming ports
    my $tcp_in = $config->get('TCP_IN') // '';
    for my $port (_parse_ports($tcp_in)) {
        _run($IPTABLES, '-A', $CHAIN_IN, @iface, '-p', 'tcp',
             @state, 'NEW', '--dport', $port, '-j', 'ACCEPT');
    }

    # The SSH port is opened even when it is absent from TCP_IN, so that an
    # edit to the port list cannot cut off remote administration.
    my $ssh_port = $config->get('SSH_PORT') // '';
    if (length $ssh_port && _valid_single_port($ssh_port)) {
        my %open_tcp = map { $_ => 1 } _parse_ports($tcp_in);
        unless ($open_tcp{$ssh_port}) {
            _run($IPTABLES, '-A', $CHAIN_IN, @iface, '-p', 'tcp',
                 @state, 'NEW', '--dport', $ssh_port, '-j', 'ACCEPT');
            HGLogger->info("SSH port $ssh_port opened; it is not listed in TCP_IN");
        }
    } elsif (length $ssh_port) {
        HGLogger->error("Ignoring invalid SSH_PORT: $ssh_port");
    }

    # Open UDP incoming ports
    my $udp_in = $config->get('UDP_IN') // '';
    for my $port (_parse_ports($udp_in)) {
        _run($IPTABLES, '-A', $CHAIN_IN, @iface, '-p', 'udp',
             '--dport', $port, '-j', 'ACCEPT');
    }

    # Traffic to addresses the host serves nothing on.
    $class->_apply_unused_ips($config, 'inet');

    # Port scan tracking. Placed last among the accepting rules so it only
    # ever sees traffic that matched no open port, which is what a scan
    # produces and an ordinary client does not.
    $class->_apply_portscan($config, 'inet');

    # Default drop inbound
    _run($IPTABLES, '-A', $CHAIN_IN, '-j', $CHAIN_LOGDROP);

    # Outbound rules
    if ($spi) {
        # Open TCP outgoing ports
        my $tcp_out = $config->get('TCP_OUT') // '';
        for my $port (_parse_ports($tcp_out)) {
            _run($IPTABLES, '-A', $CHAIN_OUT, @oface, '-p', 'tcp',
                 @state, 'NEW', '--dport', $port, '-j', 'ACCEPT');
        }

        # Open UDP outgoing ports
        my $udp_out = $config->get('UDP_OUT') // '';
        for my $port (_parse_ports($udp_out)) {
            _run($IPTABLES, '-A', $CHAIN_OUT, @oface, '-p', 'udp',
                 '--dport', $port, '-j', 'ACCEPT');
        }

        # ICMP outbound
        if ($icmp_out) {
            _run($IPTABLES, '-A', $CHAIN_OUT, @oface, '-p', 'icmp', '-j', 'ACCEPT');
        }

        # Default drop outbound
        _run($IPTABLES, '-A', $CHAIN_OUT, '-j', $CHAIN_LOGDROP);
    } else {
        # Non-SPI: allow all outbound
        _run($IPTABLES, '-A', $CHAIN_OUT, '-j', 'ACCEPT');
    }

    # FORWARD policy. DROP suits a standalone server; a host that routes for
    # containers, a VPN or a NAT gateway sets FORWARD_POLICY to ACCEPT so that
    # forwarded traffic survives.
    my $forward = uc($config->get('FORWARD_POLICY') // 'DROP');
    $forward = 'DROP' unless $forward eq 'ACCEPT' || $forward eq 'DROP';

    # Recorded before it is changed, so stop() can put back what was here
    # rather than assuming ACCEPT. On a host running Docker, a router or a
    # second firewall, what was here is not ours to guess at.
    #
    # The record is a precondition, not a courtesy, so its failure stops the
    # change. This is the one setting on the host that outlives the firewall:
    # a policy changed without being recorded cannot be put back by stop(),
    # by an uninstall, or by anything else, because nothing anywhere still
    # knows what it was. On a host that forwards - containers, a VPN, a NAT
    # gateway - that is forwarding switched off permanently by a firewall the
    # administrator had already removed.
    #
    # A policy that is already what we want is left alone and needs no record:
    # nothing is being changed, so there is nothing to put back.
    my $current = _read_policy('inet', 'FORWARD');
    if (defined $current && $current eq $forward) {
        HGLogger->debug("FORWARD policy is already $forward; left as it is.");
    } elsif (_remember_policy('inet', 'FORWARD')) {
        _run($IPTABLES, '-P', 'FORWARD', $forward);
    } else {
        # Counted as a build failure so start() refuses to activate, for the
        # same reason it refuses when a rule fails: this ruleset is not the
        # one that was asked for. Nothing has been changed, so the slot already
        # in force carries on and the FORWARD policy is still the host's own.
        my $msg = "FORWARD policy was NOT set to $forward: the policy in force"
                . " could not be recorded, and changing it without a record"
                . " would leave it changed for good.";
        HGLogger->error($msg);
        push @BUILD_FAILURES, { cmd => $msg, rc => -1, out => '' };
    }

    # _activate_slot() attaches this chain to INPUT/OUTPUT once the ipsets are
    # populated, so it never receives traffic with an empty allowlist.

    HGLogger->info("IPv4 firewall rules applied.");
}

###############################################################################
# Rule building - IPv6
###############################################################################

sub _build_rules6 {
    my ($class, $config) = @_;

    return unless $IPV6 && $IP6TABLES;

    my $spi       = $config->get('IPV6_SPI') // 1;
    my $drop      = _valid_target($config->get('DROP_ACTION') // 'DROP');
    my $conntrack = $config->get('USE_CONNTRACK') // 1;
    my @state     = $conntrack ? ('-m', 'conntrack', '--ctstate')
                               : ('-m', 'state',     '--state');

    my $drop_log = $config->get('DROP_LOGGING') // 1;
    my $icmp_rate = $config->get('ICMP_IN_RATE') // '1/s';

    # Create chains
    _run($IP6TABLES, '-N', $CHAIN6_IN);
    _run($IP6TABLES, '-N', $CHAIN6_OUT);
    _run($IP6TABLES, '-N', $CHAIN6_ALLOW);
    _run($IP6TABLES, '-N', $CHAIN6_DENY);
    _run($IP6TABLES, '-N', $CHAIN6_LOGDROP);

    # Log-and-drop, as on the IPv4 side.
    #
    # Without it DROP_LOGGING would apply to one address family and not the
    # other, and an operator asking "why can this host not reach us over IPv6"
    # would have no HG_DROP line to find.
    if ($drop_log) {
        _run_opt($IP6TABLES, '-A', $CHAIN6_LOGDROP, '-m', 'limit',
                 '--limit', '5/min', '--limit-burst', '10',
                 '-j', 'LOG', '--log-prefix', 'HG_DROP6: ', '--log-level', '4');
    }
    _run($IP6TABLES, '-A', $CHAIN6_LOGDROP, '-j', $drop);
    my $logdrop = $drop_log ? $CHAIN6_LOGDROP : $drop;

    # Loopback
    _run($IP6TABLES, '-A', $CHAIN6_IN,  '-i', 'lo', '-j', 'ACCEPT');
    _run($IP6TABLES, '-A', $CHAIN6_OUT, '-o', 'lo', '-j', 'ACCEPT');

    # Neighbour discovery, and only from where it can legitimately come.
    #
    # This has to be above the allow and deny matches, because IPv6 does not
    # work without it: without ND the host cannot resolve a link-layer address
    # for anything, including the router. It is also the one part of ICMPv6
    # that must be accepted before any policy, so it is narrowed instead.
    #
    # RFC 4861 requires these types to carry hop limit 255, which is what makes
    # them safe to accept ahead of policy: a router decrements the hop limit, so
    # a packet from off-link cannot satisfy the test. Accepting all of ICMPv6
    # here instead would mean a blocked address could still send router
    # advertisements to this host.
    # Sources are per type, because RFC 4861 does not treat them alike, and
    # getting this wrong breaks address resolution rather than weakening it.
    #
    #   133 router solicitation    link-local, or unspecified
    #   134 router advertisement   link-local
    #   135 neighbour solicitation link-local, GLOBAL, or unspecified
    #   136 neighbour advertisement link-local or GLOBAL
    #   137 redirect               link-local
    #
    # Restricting all five to fe80::/10 would be wrong: neighbour solicitations
    # and advertisements may legitimately be sent from a global address, and are
    # when a host resolves a global neighbour. IPv6 would work in most
    # configurations and not in some, in a way that looks like a network fault
    # rather than a firewall rule.
    #
    # The hop limit is the check that actually carries the security here. All
    # five types must arrive with hop limit 255, and a router decrements it, so
    # an off-link attacker cannot produce one. That is why 135 and 136 are safe
    # to accept from any source.
    my %nd_source = (
        133 => ['fe80::/10', '::/128'],
        134 => ['fe80::/10'],
        135 => [undef],                 # any source
        136 => [undef],
        137 => ['fe80::/10'],
    );

    my $hl_works = 1;
    for my $type (133, 134, 135, 136, 137) {
        for my $src (@{ $nd_source{$type} }) {
            my @from = defined $src ? ('-s', $src) : ();
            my ($rc) = _run_opt($IP6TABLES, '-A', $CHAIN6_IN, '-p', 'icmpv6',
                                '--icmpv6-type', $type,
                                '-m', 'hl', '--hl-eq', '255',
                                @from, '-j', 'ACCEPT');
            $hl_works = 0 if $rc;
        }
    }

    # Without xt_hl there is no hop-limit match, and neighbour discovery is not
    # optional: a host that cannot resolve its router's link-layer address has
    # no IPv6 at all. _run_opt continues on failure, which is right for a rate
    # limit and wrong for this - so the fallback emits the same rules without
    # the hop-limit test rather than leaving the host with no ND.
    #
    # The fallback is weaker and says so. Restricting 135 and 136 to link-local
    # would be the wrong trade in exchange: it would break the same resolution
    # this exists to protect.
    unless ($hl_works) {
        HGLogger->log_warn("The ip6tables 'hl' match is unavailable, so "
                         . "neighbour discovery cannot be restricted by hop "
                         . "limit. Accepting it without that check, because "
                         . "IPv6 does not work without ND. Load the xt_hl "
                         . "kernel module to close this: an off-link attacker "
                         . "can otherwise send discovery messages to this "
                         . "host.");
        for my $type (133, 134, 135, 136, 137) {
            _run($IP6TABLES, '-A', $CHAIN6_IN, '-p', 'icmpv6',
                 '--icmpv6-type', $type, '-j', 'ACCEPT');
        }
    }
    _run($IP6TABLES, '-A', $CHAIN6_OUT, '-p', 'icmpv6', '-j', 'ACCEPT');

    # Stateful
    if ($spi) {
        _run($IP6TABLES, '-A', $CHAIN6_IN,  @state, 'ESTABLISHED,RELATED', '-j', 'ACCEPT');
        _run($IP6TABLES, '-A', $CHAIN6_OUT, @state, 'ESTABLISHED,RELATED', '-j', 'ACCEPT');
        _run($IP6TABLES, '-A', $CHAIN6_IN,  @state, 'INVALID', '-j', $logdrop);
    }

    # Allowlist
    if ($USE_IPSET) {
        _run($IP6TABLES, '-A', $CHAIN6_IN,
             '-m', 'set', '--match-set', $SET_ALLOW6, 'src', '-j', 'ACCEPT');
        _run($IP6TABLES, '-A', $CHAIN6_IN,
             '-m', 'set', '--match-set', $SET_TALLOW6, 'src', '-j', 'ACCEPT');
    }
    _run($IP6TABLES, '-A', $CHAIN6_IN, '-j', $CHAIN6_ALLOW);

    # Forged source addresses, after the allowlist for the same reason as on
    # the IPv4 side: an administrator who has deliberately allowed a unique
    # local range is never cut off by this check.
    if ($USE_IPSET && ($config->get('BOGON_ENABLE') // '0') eq '1') {
        _run($IP6TABLES, '-A', $CHAIN6_IN,
             '-m', 'set', '--match-set', $SET_BOGON6, 'src', '-j', $logdrop);
    }

    # Denylist
    if ($USE_IPSET) {
        _run($IP6TABLES, '-A', $CHAIN6_IN,
             '-m', 'set', '--match-set', $SET_DENY6, 'src', '-j', $logdrop);
        _run($IP6TABLES, '-A', $CHAIN6_IN,
             '-m', 'set', '--match-set', $SET_TEMP6, 'src', '-j', $logdrop);
    }
    _run($IP6TABLES, '-A', $CHAIN6_IN, '-j', $CHAIN6_DENY);

    # External block lists, below the allowlist as on the IPv4 side.
    $class->_apply_blocklist_rules($config, 'inet6');

    # Country filtering, applied to the v6 chains from the v6 zone files.
    $class->_apply_geo_rules($config, 'inet6');

    # The flood and scan protections, which existed on the IPv4 side only.
    # Placed after the allow and deny checks, as they are there: a rate limit
    # never applies to loopback or to an allowlisted address, and traffic
    # already blocked is not counted against one.
    $class->_apply_synflood($config, 'inet6');
    $class->_apply_connlimits($config, 'inet6');
    $class->_apply_portflood($config, 'inet6');

    # The rest of ICMPv6, now that policy has been consulted.
    #
    # Types 1 to 4 are error messages the protocol depends on - destination
    # unreachable, packet too big, time exceeded, parameter problem - and
    # packet-too-big in particular is what makes path MTU discovery work, so
    # dropping it breaks large transfers in a way that is very hard to
    # diagnose. Echo is rate limited from the same setting the IPv4 side uses.
    for my $type (1, 2, 3, 4) {
        _run_opt($IP6TABLES, '-A', $CHAIN6_IN, '-p', 'icmpv6',
                 '--icmpv6-type', $type, '-j', 'ACCEPT');
    }
    if (($config->get('ICMP_IN') // 1)) {
        if ($icmp_rate && $icmp_rate ne '0') {
            _run_opt($IP6TABLES, '-A', $CHAIN6_IN, '-p', 'icmpv6',
                     '--icmpv6-type', 'echo-request',
                     '-m', 'limit', '--limit', $icmp_rate, '-j', 'ACCEPT');
            _run($IP6TABLES, '-A', $CHAIN6_IN, '-p', 'icmpv6',
                 '--icmpv6-type', 'echo-request', '-j', $logdrop);
        } else {
            _run($IP6TABLES, '-A', $CHAIN6_IN, '-p', 'icmpv6',
                 '--icmpv6-type', 'echo-request', '-j', 'ACCEPT');
        }
    }

    # TCP6 incoming
    my $tcp6_in = $config->get('TCP6_IN') // '';
    for my $port (_parse_ports($tcp6_in)) {
        _run($IP6TABLES, '-A', $CHAIN6_IN, '-p', 'tcp',
             @state, 'NEW', '--dport', $port, '-j', 'ACCEPT');
    }

    # The SSH port is opened even when it is absent from TCP6_IN, exactly as on
    # the IPv4 side. The v6 chain had no such safeguard, so on a host reached
    # over IPv6 an edit to TCP6_IN could cut off remote administration with
    # nothing to catch it.
    my $ssh_port = $config->get('SSH_PORT') // '';
    if (length $ssh_port && _valid_single_port($ssh_port)) {
        my %open_tcp6 = map { $_ => 1 } _parse_ports($tcp6_in);
        unless ($open_tcp6{$ssh_port}) {
            _run($IP6TABLES, '-A', $CHAIN6_IN, '-p', 'tcp',
                 @state, 'NEW', '--dport', $ssh_port, '-j', 'ACCEPT');
            HGLogger->info("SSH port $ssh_port opened for IPv6; it is not "
                         . "listed in TCP6_IN");
        }
    }

    # UDP6 incoming
    my $udp6_in = $config->get('UDP6_IN') // '';
    for my $port (_parse_ports($udp6_in)) {
        _run($IP6TABLES, '-A', $CHAIN6_IN, '-p', 'udp',
             '--dport', $port, '-j', 'ACCEPT');
    }

    # Addresses the host serves nothing on, and scan detection.
    $class->_apply_unused_ips($config, 'inet6');
    $class->_apply_portscan($config, 'inet6');

    # Default drop inbound
    _run($IP6TABLES, '-A', $CHAIN6_IN, '-j', $logdrop);

    # Outbound
    if ($spi) {
        my $tcp6_out = $config->get('TCP6_OUT') // '';
        for my $port (_parse_ports($tcp6_out)) {
            _run($IP6TABLES, '-A', $CHAIN6_OUT, '-p', 'tcp',
                 @state, 'NEW', '--dport', $port, '-j', 'ACCEPT');
        }
        my $udp6_out = $config->get('UDP6_OUT') // '';
        for my $port (_parse_ports($udp6_out)) {
            _run($IP6TABLES, '-A', $CHAIN6_OUT, '-p', 'udp',
                 '--dport', $port, '-j', 'ACCEPT');
        }
        _run($IP6TABLES, '-A', $CHAIN6_OUT, '-j', $logdrop);
    } else {
        _run($IP6TABLES, '-A', $CHAIN6_OUT, '-j', 'ACCEPT');
    }

    # _activate_slot() attaches these chains once the ipsets are populated.

    HGLogger->info("IPv6 firewall rules applied.");
}

###############################################################################
# Allowlist / Denylist loading
###############################################################################

# Add one address to a set, saying whether the kernel took it.
#
# "-exist" so that a duplicate is not a failure: the same address twice in
# allow.conf, or one that is both permanently and temporarily blocked, is a
# configuration untidiness and not a reason to refuse to start. It also
# refreshes the timeout of an entry that is already there, which is what the
# restore paths want.
#
# What is left after that is a genuine refusal - a full set, a family mismatch,
# a set that is not there - and the caller counts every one of them, because a
# slot activated with a partly loaded allowlist or block list would be
# presented as complete. An allowlist missing entries is the sharp end of that:
# the addresses it exists to protect are the ones that get dropped.
sub _set_add {
    my ($set, $ip, @extra) = @_;
    my ($rc) = _run_quiet($IPSET, 'add', $set, $ip, @extra, '-exist');
    return $rc ? 0 : 1;
}

# Record that part of a file could not be loaded, as one build failure.
#
# One entry rather than one per address: a set that has filled up refuses
# every remaining add, and start() prints each build failure it is given.
#
# "Could not be loaded" covers both halves of the same outcome - an address
# the kernel refused, and an advanced filter line this module rejected before
# it reached the kernel. The distinction matters to whoever fixes it and not
# at all to the ruleset, which is missing the entry either way, so the log
# line names an example and the per-entry reason is logged where it was found.
sub _note_load_failure {
    my ($what, $failed, $total, $example) = @_;

    my $msg = "$what: $failed of $total entries could not be loaded";
    $msg .= " (for example $example)" if defined $example && length $example;

    HGLogger->error($msg);
    push @BUILD_FAILURES, { cmd => $msg, rc => -1, out => '' };
    return 0;
}

sub _load_allowlist {
    my ($class, $config) = @_;
    my @entries = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/allow.conf");

    my $failed = 0;
    my $example;

    for my $entry (@entries) {
        my $ip = $entry->{ip};

        # Advanced filter lines (tcp|in|d=port|s=ip) become chain rules, not
        # ipset members.
        if ($ip =~ /\|/) {
            unless ($class->_apply_advanced_filter($ip, 'ACCEPT', 'allow')) {
                $failed++;
                $example //= $ip;
            }
            next;
        }

        if (HGConfig->valid_ipv4($ip)) {
            if ($USE_IPSET) {
                unless (_set_add($SET_ALLOW4, $ip)) { $failed++; $example //= $ip }
            } else {
                _run($IPTABLES, '-A', $CHAIN_ALLOW, '-s', $ip, '-j', 'ACCEPT');
            }
        } elsif ($IPV6 && HGConfig->valid_ipv6($ip)) {
            if ($USE_IPSET) {
                unless (_set_add($SET_ALLOW6, $ip)) { $failed++; $example //= $ip }
            } else {
                _run($IP6TABLES, '-A', $CHAIN6_ALLOW, '-s', $ip, '-j', 'ACCEPT') if $IP6TABLES;
            }
        }
    }

    return _note_load_failure('Allowlist', $failed, scalar(@entries), $example)
        if $failed;

    HGLogger->info("Allowlist loaded: " . scalar(@entries) . " entries.");
}

sub _load_denylist {
    my ($class, $config) = @_;
    my @entries = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/deny.conf");
    my $drop    = _valid_target($config->get('DROP_ACTION') // 'DROP');
    my $limit   = $config->get('DENY_IP_LIMIT') // 0;

    my $count   = 0;
    my $failed  = 0;
    my $skipped = 0;
    my $example;
    my $skipped_example;

    for my $entry (@entries) {
        if ($limit > 0 && $count >= $limit) {
            # Check for "do not delete" entries
            unless (($entry->{comment} // '') =~ /do not delete/i) {
                $skipped++;
                $skipped_example //= $entry->{ip};
                next;
            }
        }

        my $ip = $entry->{ip};

        # Advanced filter lines (tcp|in|d=port|s=ip) become chain rules, not
        # ipset members.
        if ($ip =~ /\|/) {
            unless ($class->_apply_advanced_filter($ip, $CHAIN_LOGDROP, 'deny')) {
                $failed++;
                $example //= $ip;
            }
            $count++;
            next;
        }

        if (HGConfig->valid_ipv4($ip)) {
            if ($USE_IPSET) {
                unless (_set_add($SET_DENY4, $ip)) { $failed++; $example //= $ip }
            } else {
                _run($IPTABLES, '-A', $CHAIN_DENY, '-s', $ip, '-j', $CHAIN_LOGDROP);
            }
        } elsif ($IPV6 && HGConfig->valid_ipv6($ip)) {
            if ($USE_IPSET) {
                unless (_set_add($SET_DENY6, $ip)) { $failed++; $example //= $ip }
            } else {
                _run($IP6TABLES, '-A', $CHAIN6_DENY, '-s', $ip, '-j', $drop) if $IP6TABLES;
            }
        }

        $count++;
    }

    # Everything DENY_IP_LIMIT dropped, said out loud.
    #
    # The skip was silent, and the line printed afterwards counted only what
    # had been loaded - which by construction can never exceed the limit. So a
    # deny.conf of four thousand addresses logged "Denylist loaded: 500
    # entries" and looked healthy, while every entry past the five hundredth
    # was simply not in the firewall.
    #
    # That is not a rare state. permblock appends and never prunes, and the
    # daemon promotes a repeat offender automatically after
    # LF_PERM_BLOCK_AFTER, so any host with real traffic passes the limit
    # within weeks. Each new permanent block still succeeds live - the ipset
    # add is made - so the CLI and the WHM page both report it applied; the
    # next reload is where it disappears. The addresses that disappear are the
    # ones at the end of the file, which are the most recently identified
    # attackers.
    #
    # An ERROR rather than a warning: the difference between what deny.conf
    # says and what the kernel holds is exactly the kind of thing this module
    # refuses to be quiet about everywhere else.
    if ($skipped) {
        HGLogger->error("Denylist: $skipped of " . scalar(@entries) . " entries "
                      . "were NOT loaded because DENY_IP_LIMIT is $limit"
                      . (defined $skipped_example ? " (for example $skipped_example)" : '')
                      . ". Those addresses are in deny.conf and are not being "
                      . "blocked. Raise DENY_IP_LIMIT, prune deny.conf, or mark "
                      . "the entries that must survive with a 'do not delete' "
                      . "comment.");
    }

    return _note_load_failure('Denylist', $failed, $count, $example) if $failed;

    HGLogger->info("Denylist loaded: $count entries"
                 . ($skipped ? ", $skipped SKIPPED by DENY_IP_LIMIT" : '') . ".");
}

# How many deny.conf entries the limit is currently discarding, for the CLI
# and the WHM page. Zero when nothing is being dropped.
sub denylist_overflow {
    my ($class, $config) = @_;
    my $limit = $config->get('DENY_IP_LIMIT') // 0;
    return 0 unless $limit =~ /^\d+$/ && $limit > 0;

    my @entries = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/deny.conf");
    my $over = scalar(@entries) - $limit;
    return $over > 0 ? $over : 0;
}

# Put the temporary blocks back into the slot being built.
#
# These are as much a part of the ruleset as the deny list is. An address in
# tempblock.dat is one the CLI and the WHM page both report as held, so a
# rebuild that quietly failed to restore it produced a ruleset that claimed to
# be holding addresses it had let go - and activated it as complete.
sub _load_tempblocks {
    my ($class) = @_;
    my $tempfile = "$HGConfig::DATA_DIR/tempblock.dat";
    return unless -e $tempfile;

    # As with the allows: a path that exists but is not a record file is a
    # ruleset that cannot be completed, not an empty one.
    unless (-f $tempfile) {
        HGLogger->error("$tempfile is not a regular file, so no temporary "
                      . "blocks could be read from it");
        push @BUILD_FAILURES,
            { cmd => "read $tempfile", rc => -1, out => 'not a regular file' };
        return;
    }

    open(my $fh, '<', $tempfile) or do {
        HGLogger->error("Cannot read $tempfile: $!");
        push @BUILD_FAILURES, { cmd => "read $tempfile", rc => -1, out => "$!" };
        return;
    };
    flock($fh, LOCK_SH);

    my $now     = time();
    my $loaded  = 0;
    my $failed  = 0;
    my $skipped = 0;
    my $example;

    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;

        my ($ip, $expires, $reason) = split(/\|/, $line, 3);

        # A line that does not parse is damage, not a block. It is skipped
        # rather than counted as a failure: refusing to start over a corrupt
        # line would make one bad record permanent.
        unless (defined $ip && defined $expires && $expires =~ /^\d+$/) {
            $skipped++;
            next;
        }
        next if $expires <= $now;    # expired

        # Clamped for the same reason ipset itself is: an expiry further off
        # than a timeout can express - a record written before the duration
        # was checked, or a clock that jumped - would be refused by the
        # kernel, and one such record would then stop the firewall starting.
        my $ttl = $expires - $now;
        $ttl = $MAX_TIMEOUT if $ttl > $MAX_TIMEOUT;

        if (HGConfig->valid_ipv4($ip)) {
            if ($USE_IPSET) {
                if (_set_add($SET_TEMP4, $ip, 'timeout', $ttl)) { $loaded++ }
                else { $failed++; $example //= $ip }
            } else {
                my ($rc) = _run($IPTABLES, '-A', $CHAIN_DENY, '-s', $ip, '-j', $CHAIN_LOGDROP);
                $rc ? $failed++ : $loaded++;
            }
        } elsif (HGConfig->valid_ipv6($ip)) {
            if ($IPV6 && $USE_IPSET) {
                if (_set_add($SET_TEMP6, $ip, 'timeout', $ttl)) { $loaded++ }
                else { $failed++; $example //= $ip }
            } else {
                # IPv6 is off, so this block cannot be applied and is not
                # claimed to have been.
                $skipped++;
            }
        } else {
            $skipped++;
        }
    }
    close($fh);

    HGLogger->log_warn("$tempfile has $skipped line(s) that could not be "
                     . "applied; they were skipped")
        if $skipped;

    return _note_load_failure('Temporary blocks', $failed, $failed + $loaded, $example)
        if $failed;

    HGLogger->info("Temporary blocks loaded: $loaded active.");
}

# Restore temporary allows into the new slot's sets, each with the time it has
# left rather than a fresh full duration, so a reload does not extend one.
sub _load_tempallows {
    my ($class) = @_;

    my $file = "$HGConfig::DATA_DIR/tempallow.dat";

    # Temporary allows are held in an ipset and have no other implementation, so
    # with LF_IPSET=0 they cannot be applied at all. Records made while it was
    # enabled would then be dropped from every rebuild in silence, while
    # "hostguard -la" went on listing them as access that is in force - so the
    # situation is reported rather than passed over.
    unless ($USE_IPSET) {
        my @records = _read_records($file);
        HGLogger->log_warn("LF_IPSET is 0, so the " . scalar(@records)
                         . " temporary allow(s) in $file cannot be applied and "
                         . "are not in this ruleset. Set LF_IPSET=1, or remove "
                         . "them with: hostguard -tar <ip>")
            if @records;
        return;
    }

    my %stats;
    my @records = _read_records($file, \%stats);

    # A file that is there and will not open is not "no temporary allows". It
    # is a ruleset that cannot be completed, and completing it is the whole
    # point of this pass.
    if ($stats{unreadable}) {
        push @BUILD_FAILURES,
            { cmd => "read $file", rc => -1, out => 'temporary allows could not be read' };
        return;
    }

    HGLogger->log_warn("$file has $stats{damaged} line(s) that could not be "
                     . "read; they were skipped")
        if $stats{damaged};

    return unless @records;

    # A temporary allow that fails to restore is the dangerous direction of
    # this: the address is no longer allowed, the list still says it is, and
    # what it was being allowed past is a firewall that will now drop it.
    my $loaded  = 0;
    my $failed  = 0;
    my $skipped = 0;
    my $example;

    for my $r (@records) {
        my $ttl = $r->{ttl};
        $ttl = $MAX_TIMEOUT if $ttl > $MAX_TIMEOUT;

        if (HGConfig->valid_ipv4($r->{ip})) {
            if (_set_add($SET_TALLOW4, $r->{ip}, 'timeout', $ttl)) { $loaded++ }
            else { $failed++; $example //= $r->{ip} }
        } elsif (HGConfig->valid_ipv6($r->{ip})) {
            if (!$IPV6) {
                $skipped++;
            } elsif (_set_add($SET_TALLOW6, $r->{ip}, 'timeout', $ttl)) {
                $loaded++;
            } else {
                $failed++;
                $example //= $r->{ip};
            }
        } else {
            $skipped++;
        }
    }

    HGLogger->log_warn("tempallow.dat has $skipped entry(s) that could not be "
                     . "applied; they were skipped")
        if $skipped;

    return _note_load_failure('Temporary allows', $failed, $failed + $loaded, $example)
        if $failed;

    HGLogger->info("Temporary allows loaded: $loaded active.");
}

###############################################################################
# Advanced filter support (tcp|in|d=port|s=ip)
###############################################################################

# Whether a line is a filter this engine will actually install.
#
# Public because the WHM list editor needs the same answer, and had its own
# copy: the two agreed on the malformed forms by luck rather than by
# construction, and the copy in the CGI was the stricter of the two - so the
# browser rejected lines that the file accepted and turned into a match-all
# rule. One definition, called from both.
#
# Returns 1, or 0 and the reason.
sub valid_filter {
    my ($class, $line) = @_;
    return (0, 'empty') unless defined $line && length $line;

    my @parts = split(/\|/, $line);
    return (0, 'expected at least protocol|direction|selector')
        unless scalar(@parts) >= 3;
    return (0, "unsupported protocol '$parts[0]', expected tcp or udp")
        unless lc($parts[0]) =~ /^(tcp|udp)$/;
    return (0, "unsupported direction '$parts[1]', expected in or out")
        unless lc($parts[1]) =~ /^(in|out)$/;

    my $selectors = 0;
    for my $i (2 .. $#parts) {
        my $tok = $parts[$i];
        $tok =~ s/^\s+//;
        $tok =~ s/\s+$//;
        next unless length $tok;

        return (0, "unrecognised field '$tok', expected d=<port> or s=<port|address>")
            unless $tok =~ /^([ds])=(\S+)$/;
        my ($key, $val) = ($1, $2);

        if ($key eq 's' && ($val =~ /\./ || $val =~ /:.*:/)) {
            # Checked before the IPv4 test, or an IPv6 source would be reported
            # as "not an address" - which is both wrong and unhelpful, since it
            # is a perfectly good address in the wrong family.
            return (0, "'$val' is an IPv6 source; advanced filters apply to "
                     . "the IPv4 chains only")
                if $val =~ /:/;
            return (0, "'$val' is not an address or range")
                unless HGConfig->valid_ipv4($val);
        } else {
            return (0, "'$val' is not a port or port range")
                unless _valid_single_port($val);
        }
        $selectors++;
    }

    return (0, 'it selects nothing: add d=<port>, s=<port> or s=<address>, or '
              . 'it would match all traffic in that direction')
        unless $selectors;

    return (1, '');
}

# Turn one "tcp|in|d=port|s=ip" line into a chain rule.
#
# Returns true when the rule was handed to iptables, false when the line was
# rejected before that. The caller needs that distinction: a rejected line is
# an allowlist or denylist entry that is not in the ruleset, and every other
# way of failing to load one - a full ipset, a refused command - already stops
# start() from activating the slot. A rejection that were merely logged would
# mean a mistyped port in allow.conf producing a ruleset missing a rule the
# administrator had written, reported as started.
#
# Every rejection below therefore both logs its reason and returns false,
# including the three structural ones: a line that is neither tcp nor udp,
# neither in nor out, or too short to be a filter at all.
sub _apply_advanced_filter {
    my ($class, $filter, $target, $kind) = @_;
    $kind = ($target eq 'ACCEPT') ? 'allow' : 'deny' unless defined $kind;
    my @parts = split(/\|/, $filter);
    unless (scalar(@parts) >= 3) {
        HGLogger->error("Ignoring advanced filter with too few fields, "
                      . "expected protocol|direction|option...: $filter");
        return 0;
    }

    my $proto     = lc($parts[0]); # tcp or udp
    my $direction = lc($parts[1]); # in or out

    unless ($proto =~ /^(tcp|udp)$/) {
        HGLogger->error("Ignoring advanced filter with unsupported protocol "
                      . "'$parts[0]', expected tcp or udp: $filter");
        return 0;
    }
    unless ($direction =~ /^(in|out)$/) {
        HGLogger->error("Ignoring advanced filter with unsupported direction "
                      . "'$parts[1]', expected in or out: $filter");
        return 0;
    }

    my ($dport, $sport, $sip);
    for my $i (2 .. $#parts) {
        my $tok = $parts[$i];
        $tok =~ s/^\s+//;
        $tok =~ s/\s+$//;
        next unless length $tok;

        # Every field after the direction has to be a selector this understands.
        #
        # The two matches below were unanchored and had no else, so anything
        # that was not "d=" or "s=" was skipped in silence - and a line whose
        # only remaining field was skipped left every selector undefined. What
        # was then emitted is in the comment on the selector check further
        # down; the short version is that "tcp|in|d22" became a rule matching
        # all TCP traffic in that direction.
        unless ($tok =~ /^([ds])=(\S+)$/) {
            HGLogger->error("Ignoring advanced filter with an unrecognised "
                          . "field '$tok'; each field after the direction must "
                          . "be d=<port> or s=<port|address>: $filter");
            return 0;
        }
        my ($key, $val) = ($1, $2);

        if ($key eq 'd') {
            $dport = $val;
        } else {
            # "s=" is overloaded: it carries either a source address or a
            # source port. An address contains a dot (IPv4) or at least two
            # colons (IPv6); a port range has at most one colon and no dot.
            if ($val =~ /\./ || $val =~ /:.*:/) { $sip = $val; }
            else { $sport = $val; }
        }
    }

    # A filter has to select something.
    #
    # Nothing checked this, and it is the difference between a rule and a
    # catastrophe. With no port and no source, the command assembled below is
    # just the protocol and the target:
    #
    #   tcp|in|d22   ->  -A ...ADENY_IN -p tcp -j LOGDROP
    #
    # which in deny.conf drops every inbound TCP connection from any address
    # not in the allowlist, and in allow.conf accepts every address the
    # firewall has blocked, on every TCP port, because the advanced allow
    # chain sits above the deny set, the temporary block set, the block lists
    # and the country rules. One missing "=" either took the host off the
    # network or removed all IP blocking, and the build reported success.
    unless (defined $dport || defined $sport || defined $sip) {
        HGLogger->error("Ignoring advanced filter that selects nothing: "
                      . "$filter. Without a port or a source it would match "
                      . "all $proto traffic $direction" . "bound, which is "
                      . "almost certainly not what was meant. Use "
                      . "d=<port>, s=<port> or s=<address>.");
        return 0;
    }

    # The address and port come from allow.conf or deny.conf and are passed
    # straight to iptables as arguments. Anything that is not a plain IP or
    # port specification is rejected and logged.
    if (defined $sip && !HGConfig->valid_ipv4($sip)) {
        # Advanced filters apply to the IPv4 chains, so an IPv6 source has
        # nowhere valid to go.
        HGLogger->error("Ignoring advanced filter with unsupported source IP: $filter");
        return 0;
    }
    if (defined $dport && !_valid_single_port($dport)) {
        HGLogger->error("Ignoring advanced filter with invalid destination port: $filter");
        return 0;
    }
    if (defined $sport && !_valid_single_port($sport)) {
        HGLogger->error("Ignoring advanced filter with invalid source port: $filter");
        return 0;
    }

    # Appended to the chain the jump for this direction and verdict already
    # points at, rather than inserted at the head of the input or output chain.
    # The placement of that jump is the ordering decision, and it is made in
    # _build_rules with every other one; see the comment on $CHAIN_AALLOW_IN
    # for why inserting here instead would be wrong.
    my $chain = ($kind eq 'allow')
              ? ($direction eq 'in' ? $CHAIN_AALLOW_IN : $CHAIN_AALLOW_OUT)
              : ($direction eq 'in' ? $CHAIN_ADENY_IN  : $CHAIN_ADENY_OUT);

    my @cmd = ($IPTABLES, '-A', $chain, '-p', $proto);
    push @cmd, '-s',      $sip   if $sip;
    push @cmd, '--sport', $sport if $sport;
    push @cmd, '--dport', $dport if $dport;
    push @cmd, '-j',      $target;

    # _run records a refused command as a build failure itself, so this
    # reports success either way: the caller counts what was rejected here,
    # not what the kernel rejected, and counting both would report one
    # bad line twice.
    _run(@cmd);
    return 1;
}

###############################################################################
# Connection limits and flood protection
###############################################################################
#
# Every protection below is applied to both address families.
#
# Applying them to one family only would leave the configuration file
# describing protections that covered half the host: a machine reachable over
# IPv6 could be port-scanned without being detected, flooded without a rate
# limit, and would have no equivalent of the rule that keeps SSH reachable when
# TCP_IN is edited badly.
#
# The matches all exist under ip6tables - set, limit, connlimit, recent - so
# each function resolves the family's chain and set names and emits the same
# rules, which is how _apply_blocklist_rules and _apply_geo_rules handle both.

# Command, chains and sets for one address family.
sub _family_parts {
    my ($family) = @_;
    my $v6 = (defined $family && $family eq 'inet6') ? 1 : 0;
    return {
        v6       => $v6,
        family   => $v6 ? 'inet6' : 'inet',
        cmd      => $v6 ? $IP6TABLES       : $IPTABLES,
        in       => $v6 ? $CHAIN6_IN       : $CHAIN_IN,
        out      => $v6 ? $CHAIN6_OUT      : $CHAIN_OUT,
        logdrop  => $v6 ? $CHAIN6_LOGDROP  : $CHAIN_LOGDROP,
        synflood => $v6 ? $CHAIN6_SYNFLOOD : $CHAIN_SYNFLOOD,
        scan     => $v6 ? $CHAIN6_SCAN     : $CHAIN_SCAN,
        temp     => $v6 ? $SET_TEMP6       : $SET_TEMP4,
        bogon    => $v6 ? $SET_BOGON6      : $SET_BOGON4,
        # The recent module's lists are global to the kernel, so the two
        # families must not share one: a v4 source and a v6 source counting
        # into the same list would evict each other.
        suffix   => $v6 ? '6' : '',
        label    => $v6 ? 'IPv6' : 'IPv4',
    };
}

sub _apply_connlimits {
    my ($class, $config, $family) = @_;
    my $connlimit = $config->get('CONNLIMIT') // '';
    return unless $connlimit;

    my $f = _family_parts($family);
    return unless $f->{cmd};

    for my $rule (split(/,/, $connlimit)) {
        my ($port, $limit) = split(/;/, $rule, 2);
        next unless $port && $limit;
        $port =~ s/\s//g;
        $limit =~ s/\s//g;
        next unless $port =~ /^\d+$/ && $limit =~ /^\d+$/;
        next unless _valid_single_port($port);

        # --connlimit-mask defaults to 32, which is meaningless for IPv6; 128
        # counts per address, matching what the v4 default does.
        my @mask = $f->{v6} ? ('--connlimit-mask', '128') : ();

        _run_opt($f->{cmd}, '-A', $f->{in}, '-p', 'tcp', '--syn', '--dport', $port,
             '-m', 'connlimit', '--connlimit-above', $limit, @mask, '-j', 'DROP');
        HGLogger->info("$f->{label} connection limit: port $port max $limit "
                     . "connections/address");
    }
}

# Limit how many new connections one source may make to a port within a
# window, as "port;hits;interval;protocol".
#
# Implemented with the recent module, which counts events per source address
# over an arbitrary number of seconds. Each rule becomes a pair: the first
# records the source, the second drops it once the count inside the window
# passes the limit. The hit count is one higher than the configured limit
# because the recording rule has already counted the current packet.
sub _apply_portflood {
    my ($class, $config, $family) = @_;
    my $portflood = $config->get('PORTFLOOD') // '';
    return unless $portflood;

    my $f = _family_parts($family);
    return unless $f->{cmd};

    my $conntrack = $config->get('USE_CONNTRACK') // 1;
    my @state = $conntrack ? ('-m', 'conntrack', '--ctstate')
                           : ('-m', 'state',     '--state');

    # The recent module keeps a bounded number of timestamps per address,
    # ip_pkt_list_tot, which is 20 by default. A hit count above that can never
    # be reached, so such a rule is reported rather than installed.
    my $max_hits = 19;

    for my $rule (split(/,/, $portflood)) {
        my ($port, $hits, $interval, $proto) = split(/;/, $rule, 4);
        next unless defined $port && defined $hits && defined $interval;
        $proto = 'tcp' unless defined $proto && length $proto;
        for ($port, $hits, $interval, $proto) { s/\s//g }
        $proto = lc($proto);

        unless ($proto eq 'tcp' || $proto eq 'udp') {
            HGLogger->error("Ignoring PORTFLOOD rule with unsupported protocol: $rule");
            next;
        }
        unless (_valid_single_port($port) && $hits =~ /^\d+$/ && $interval =~ /^\d+$/) {
            HGLogger->error("Ignoring malformed PORTFLOOD rule: $rule");
            next;
        }
        unless ($hits > 0 && $interval > 0) {
            HGLogger->error("Ignoring PORTFLOOD rule with a zero hit count or "
                          . "interval: $rule");
            next;
        }
        if ($hits > $max_hits) {
            HGLogger->error("Ignoring PORTFLOOD rule for $proto/$port: a hit "
                          . "count above $max_hits exceeds what the recent "
                          . "module tracks per address");
            next;
        }

        # One tracking list per protocol and port. A port range contains a
        # colon, which is replaced so the name stays a plain identifier.
        my $name = "hgf$f->{suffix}_${proto}_${port}";
        $name =~ s/:/_/g;

        _run_opt($f->{cmd}, '-A', $f->{in}, '-p', $proto, '--dport', $port,
             @state, 'NEW',
             '-m', 'recent', '--set', '--name', $name, '--rsource');
        _run_opt($f->{cmd}, '-A', $f->{in}, '-p', $proto, '--dport', $port,
             @state, 'NEW',
             '-m', 'recent', '--update',
             '--seconds', $interval, '--hitcount', $hits + 1,
             '--name', $name, '--rsource',
             '-j', 'DROP');

        HGLogger->info("$f->{label} port flood protection: $proto/$port max "
                     . "$hits new connections per ${interval}s per source");
    }
}

sub _apply_synflood {
    my ($class, $config, $family) = @_;
    my $synflood = $config->get('SYNFLOOD') // 0;
    return unless $synflood;

    my $f = _family_parts($family);
    return unless $f->{cmd};

    my $rate  = $config->get('SYNFLOOD_RATE')  // '100/s';
    my $burst = $config->get('SYNFLOOD_BURST') // '150';

    unless ($rate =~ m{^\d+/(?:s|sec|second|m|min|minute|h|hour|d|day)$}) {
        HGLogger->error("Ignoring SYN flood protection: invalid SYNFLOOD_RATE '$rate'");
        return;
    }
    unless ($burst =~ /^\d+$/) {
        HGLogger->error("Ignoring SYN flood protection: invalid SYNFLOOD_BURST '$burst'");
        return;
    }

    # SYN flood protection drops; it never accepts.
    #
    # SYNs are diverted to a dedicated chain which RETURNs those inside the
    # rate limit, so they continue to the TCP_IN port checks, and drops the
    # rest. A rate-limited ACCEPT placed directly in the input chain would
    # instead terminate rule evaluation for every SYN under the limit and let
    # traffic in without any port check at all.
    _run_opt($f->{cmd}, '-N', $f->{synflood});
    _run_opt($f->{cmd}, '-A', $f->{synflood}, '-m', 'limit',
         '--limit', $rate, '--limit-burst', $burst, '-j', 'RETURN');
    _run_opt($f->{cmd}, '-A', $f->{synflood}, '-j', 'DROP');
    _run_opt($f->{cmd}, '-A', $f->{in}, '-p', 'tcp', '--syn', '-j', $f->{synflood});

    HGLogger->info("$f->{label} SYN flood protection enabled: rate=$rate "
                 . "burst=$burst");
}

###############################################################################
# Port scan tracking
###############################################################################

# Detect and block a source touching many closed ports in a short window.
#
# A scan is distinguished from ordinary traffic by where it lands: a real
# client connects to a port something is listening on, while a scan sweeps
# ports that are closed. The rules below sit at the end of the input chain,
# after every accept, so only traffic that matched nothing reaches them - and
# that is precisely the traffic a scan generates.
#
# The recent module counts those arrivals per source. Passing SCAN_LIMIT of
# them inside SCAN_INTERVAL seconds adds the source to the temporary block
# set, so the block expires on its own exactly as a login-failure block does.
#
# Two kernel limits bound this, both parameters of the xt_recent module:
# ip_pkt_list_tot caps the timestamps kept per address at 20, which caps
# SCAN_LIMIT at 19; and ip_list_tot caps the addresses tracked at 100, past
# which the least recently seen are evicted. A scan from more than a hundred
# sources at once will therefore lose some of them. Raise both with module
# parameters on a host that needs it.
sub _apply_portscan {
    my ($class, $config, $family) = @_;

    return unless ($config->get('SCAN_ENABLE') // '0') eq '1';
    return unless $USE_IPSET;

    my $f = _family_parts($family);
    return unless $f->{cmd};

    my $limit    = $config->get('SCAN_LIMIT')    // 10;
    my $interval = $config->get('SCAN_INTERVAL') // 60;
    my $duration = $config->get('SCAN_BLOCK_TIME') // 3600;

    unless ($limit =~ /^\d+$/ && $limit > 0) {
        HGLogger->error("Ignoring invalid SCAN_LIMIT: $limit");
        return;
    }

    # The recent module keeps ip_pkt_list_tot timestamps per address, 20 by
    # default. The rule below tests for one more than SCAN_LIMIT, so a limit of
    # 19 is the highest that can ever match; above that the rule would install
    # cleanly and then never fire, which is worse than refusing it.
    if ($limit > 19) {
        HGLogger->error("SCAN_LIMIT of $limit exceeds what the recent module "
                      . "tracks per address (19); port scan detection is not "
                      . "being applied. Lower SCAN_LIMIT, or raise the "
                      . "ip_pkt_list_tot parameter of the xt_recent module.");
        return;
    }
    unless ($interval =~ /^\d+$/ && $interval > 0) {
        HGLogger->error("Ignoring invalid SCAN_INTERVAL: $interval");
        return;
    }
    unless ($duration =~ /^\d+$/ && $duration > 0) {
        HGLogger->error("Ignoring invalid SCAN_BLOCK_TIME: $duration");
        return;
    }

    _run_opt($f->{cmd}, '-N', $f->{scan});

    # An address already held is not counted again, so a block does not keep
    # renewing itself from the same burst of packets.
    _run_opt($f->{cmd}, '-A', $f->{scan},
         '-m', 'set', '--match-set', $f->{temp}, 'src', '-j', 'RETURN');

    # Record the arrival, then test the count over the window. The limit is
    # one higher than configured because the recording rule has already
    # counted the packet being tested.
    my $list = "hgscan$f->{suffix}";
    _run_opt($f->{cmd}, '-A', $f->{scan},
         '-m', 'recent', '--name', $list, '--set');
    _run_opt($f->{cmd}, '-A', $f->{scan},
         '-m', 'recent', '--name', $list, '--update',
         '--seconds', $interval, '--hitcount', $limit + 1,
         '-j', 'SET', '--add-set', $f->{temp}, 'src',
         '--timeout', $duration, '--exist');

    if (($config->get('DROP_LOGGING') // 1)) {
        _run_opt($f->{cmd}, '-A', $f->{scan},
             '-m', 'recent', '--name', $list, '--rcheck',
             '--seconds', $interval, '--hitcount', $limit + 1,
             '-m', 'limit', '--limit', '2/min',
             '-j', 'LOG', '--log-prefix', 'HG_SCAN: ', '--log-level', '4');
    }

    # New connections only. Counting every packet of an ongoing conversation
    # would block a client whose connection simply outlived a rule change.
    _run_opt($f->{cmd}, '-A', $f->{in}, '-p', 'tcp', '--syn', '-j', $f->{scan});
    _run_opt($f->{cmd}, '-A', $f->{in}, '-p', 'udp', '-j', $f->{scan});

    HGLogger->info("$f->{label} port scan detection active: $limit closed "
                 . "ports in ${interval}s blocks for ${duration}s");
}

###############################################################################
# Unused addresses
###############################################################################

# Drop traffic to addresses the host holds but serves nothing on.
#
# An address that is configured but unused is a free listening post: anything
# arriving on it is either a scan or a misconfiguration, and neither wants
# answering. The addresses to protect are named explicitly rather than
# discovered, because guessing which of a host's addresses are unused would
# eventually guess wrong and take a live site offline.
sub _apply_unused_ips {
    my ($class, $config, $family) = @_;

    my $value = $config->get('UNUSED_IPS') // '';
    return unless length $value;

    my $f = _family_parts($family);
    return unless $f->{cmd};

    my $drop = ($config->get('DROP_LOGGING') // 1) ? $f->{logdrop} : 'DROP';
    my $count = 0;
    my $other = 0;

    # One list, both families. An entry belonging to the other family is
    # skipped silently here and handled by that family's own pass; only an
    # entry that is neither is an error. Treating the setting as IPv4 only would
    # mean a listed v6 address logging an error and protecting nothing.
    for my $ip (split(/,/, $value)) {
        $ip =~ s/\s//g;
        next unless length $ip;

        my $is4 = HGConfig->valid_ipv4($ip) && $ip !~ /:/;
        my $is6 = HGConfig->valid_ipv6($ip);

        unless ($is4 || $is6) {
            HGLogger->error("Ignoring UNUSED_IPS entry that is not an address: $ip")
                unless $f->{v6};      # reported once, on the first pass
            next;
        }
        if ($f->{v6} ? !$is6 : !$is4) {
            # An entry for the other family is that family's business - unless
            # that family is not being filtered at all, in which case saying
            # "it belongs to the other pass" would be describing a pass that
            # never runs.
            if (!$f->{v6} && $is6 && !$IPV6) {
                HGLogger->error("UNUSED_IPS lists $ip, but IPV6 is 0 so no "
                              . "IPv6 rules are built and nothing is filtering "
                              . "traffic to it. Set IPV6=1 or remove the "
                              . "entry.");
            }
            $other++;
            next;
        }

        # Inserted at the head of the input chain, ahead of every accept, so
        # no port rule can let traffic through to an address listed here.
        _run($f->{cmd}, '-I', $f->{in}, '-d', $ip, '-j', $drop);
        $count++;
    }

    HGLogger->info("$f->{label}: blocking all traffic to $count unused "
                 . "address(es)" . ($other ? " ($other belong to the other "
                                           . "family)" : '')) if $count;
}

###############################################################################
# Block notice redirection
###############################################################################

# Send blocked addresses to the notice responder instead of dropping them.
#
# The redirect lives in the nat table's PREROUTING chain, which is reached
# before the filter rules that would otherwise drop the packet. It applies
# only to addresses in the temporary block set: a permanently denied address
# stays dropped, because a permanent block is a decision that does not want
# a conversation.
sub _apply_notice_redirect {
    my ($class, $config) = @_;

    my %flat = $config->config();
    return unless HGNotice->enabled(\%flat);
    return unless $USE_IPSET;

    my @ports = HGNotice->redirect_ports(\%flat);
    return unless @ports;

    my $to = HGNotice->port(\%flat);

    # Clear any rule left by an earlier run before adding this one, since nat
    # rules are not part of the slot that gets torn down.
    $class->_clear_notice_redirect($config);

    for my $port (@ports) {
        _run_opt($IPTABLES, '-t', 'nat', '-A', 'PREROUTING',
             '-p', 'tcp', '--dport', $port,
             '-m', 'set', '--match-set', $SET_TEMP4, 'src',
             '-m', 'comment', '--comment', 'hostguard-notice',
             '-j', 'REDIRECT', '--to-port', $to);
    }

    HGLogger->info("Block notice redirect active on port(s) "
                 . join(',', @ports) . " to $to");
}

# Remove the redirect rules.
#
# They are matched by their comment rather than by rebuilding the argument
# list, so a rule left by a previous configuration - a different port, say -
# is still found and removed.
sub _clear_notice_redirect {
    my ($class, $config) = @_;
    return unless $IPTABLES;

    my (undef, $out) = _exec($IPTABLES, '-t', 'nat', '-S', 'PREROUTING');
    for my $line (split(/\n/, ($out // ''))) {
        next unless $line =~ /hostguard-notice/;
        next unless $line =~ s/^-A\s+//;
        my @args = split(/\s+/, $line);
        # Rebuild the rule as a delete. Every value came from iptables' own
        # output, so nothing here originates with a user.
        _run_quiet($IPTABLES, '-t', 'nat', '-D', @args);
    }
}

###############################################################################
# Runtime block/unblock operations
###############################################################################
#
# Everything below changes the ruleset that is already live, and every one of
# them takes the same lock start() and stop() hold. Two races make that
# necessary.
#
# Against a rebuild: a block added while a slot swap is under way would go into
# whichever set the process last knew about. If that were the outgoing slot, the
# teardown would destroy it moments later, leaving the address recorded in
# tempblock.dat and listed by the CLI while nothing was blocking it.
#
# Against each other: appending to tempblock.dat rewrites the file to drop any
# existing entry for the address first, so two operations at once could lose
# one another's work in the ordinary read-modify-write way.
#
# Both are closed by that lock, and by re-reading which slot is live once it is
# held. The wait is what makes it usable: a block that arrives during a reload
# waits for it rather than being
# dropped.
#
# The rule is the whole of the discipline, so it holds for the two operations
# that live higher up this file for want of a better home: refresh_geo_set and
# refresh_blocklist_set swap the contents of a live set, and go through
# _with_lock for the same reason everything here does.

# Held while an operation runs, with a depth count because these call each
# other: allow() removes any temporary block for the same address.
my $LOCK_FH;
my $LOCK_DEPTH = 0;

sub _with_lock {
    my ($class, $what, $code) = @_;

    if ($LOCK_DEPTH) {
        # Already held further up this call chain.
        $LOCK_DEPTH++;
        my @r = eval { $code->() };
        my $err = $@;
        $LOCK_DEPTH--;
        die $err if $err;
        return wantarray ? @r : $r[0];
    }

    my $fh = eval { HGConfig->get_lock_wait('firewall', 30) };
    unless ($fh) {
        my $err = $@ || 'unknown error';
        chomp $err;
        HGLogger->error("$what: could not take the firewall lock: $err");
        return 0;
    }

    $LOCK_FH    = $fh;
    $LOCK_DEPTH = 1;

    # Another process may have swapped slots since this one last looked. The
    # chain and set names are read again here so the operation acts on the slot
    # that is actually serving traffic rather than one that has been destroyed.
    _use_slot(_read_slot() // $SLOT);

    my @r = eval { $code->() };
    my $err = $@;

    $LOCK_DEPTH = 0;
    close($LOCK_FH);
    $LOCK_FH = undef;

    die $err if $err;
    return wantarray ? @r : $r[0];
}


# Check a temporary duration, returning the seconds to use or undef.
#
# Shared by tempblock and tempallow so the two cannot drift apart. What an
# unchecked duration would let through is worth naming, because none of it
# announces itself:
#
#   0            means "no timeout" to ipset, so a temporary block became a
#                permanent one, logged and reported as expiring. Its record
#                expired at once, so the next sweep dropped the line and left
#                the address blocked with nothing recording it.
#   negative     an expiry already in the past, so the record was swept on the
#                next pass while the ipset add failed - or, with LF_IPSET=0,
#                while the iptables rule stayed in place unrecorded.
#   "1h", "3600" the ipset add fails, so nothing is blocked; the address is
#   with spaces  recorded as blocked all the same on the paths that record
#                first.
#   enormous     past what ipset accepts, so the add fails and nothing is
#                blocked, from a value that reads as "block for a long time".
#
# A duration is a number of seconds greater than zero. Everything else is a
# mistake, and a mistake here is silent, which is why it is refused here rather
# than turned into a kernel error further down.
sub _valid_duration {
    my ($what, $duration) = @_;

    unless (defined $duration && $duration =~ /^\d+$/ && $duration > 0) {
        HGLogger->error("$what: invalid duration: "
                      . (defined $duration && length $duration ? $duration : '(empty)')
                      . " - it must be a whole number of seconds above zero");
        return undef;
    }

    if ($duration > $MAX_TIMEOUT) {
        HGLogger->log_warn("$what: duration ${duration}s is longer than ipset "
                         . "can hold; using ${MAX_TIMEOUT}s. Use a permanent "
                         . "block for anything longer.");
        return $MAX_TIMEOUT;
    }

    return $duration;
}

# Temporarily block an IP with a TTL
sub tempblock {
    my ($class, $ip, $duration, $reason) = @_;
    return HGFirewall->_with_lock('tempblock', sub {
        return _tempblock_locked($class, $ip, $duration, $reason);
    });
}

sub _tempblock_locked {
    my ($class, $ip, $duration, $reason) = @_;

    my $config = HGConfig->loadconfig();

    # Validate
    unless (HGConfig->valid_ip($ip)) {
        HGLogger->error("tempblock: Invalid IP: $ip");
        return 0;
    }

    # Check allowlist first
    my @allow = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/allow.conf");
    if (HGConfig->ip_in_list($ip, @allow)) {
        HGLogger->info("tempblock: Skipping allowed IP $ip");
        return 0;
    }

    # Check ignore list
    my @ignore = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/ignore.conf");
    if (HGConfig->ip_in_list($ip, @ignore)) {
        HGLogger->info("tempblock: Skipping ignored IP $ip");
        return 0;
    }

    $duration //= 3600;
    $duration = _valid_duration('tempblock', $duration);
    return 0 unless defined $duration;

    $reason //= "Manual block";
    my $expires = time() + $duration;

    # Add to ipset with timeout.
    #
    # This is the step that actually blocks the address. If the kernel refuses
    # it there is nothing blocking anything, so the block is not recorded and
    # not announced: a line in tempblock.dat is a claim that an address is
    # being held, and the CLI and the WHM page both present it as one.
    my $rc = 0;
    if ($USE_IPSET) {
        if (HGConfig->valid_ipv4($ip)) {
            ($rc) = _run_live($IPSET, 'add', $SET_TEMP4, $ip, 'timeout', $duration, '-exist');
        } elsif (HGConfig->valid_ipv6($ip)) {
            ($rc) = _run_live($IPSET, 'add', $SET_TEMP6, $ip, 'timeout', $duration, '-exist');
        }
    } else {
        if (HGConfig->valid_ipv4($ip)) {
            ($rc) = _run_live($IPTABLES, '-I', $CHAIN_DENY, '-s', $ip, '-j', $CHAIN_LOGDROP);
        }
    }

    if ($rc) {
        HGLogger->error("tempblock: $ip was NOT blocked; the kernel refused "
                      . "the command above. Is the firewall started?");
        return 0;
    }

    # Keep the number of active temporary blocks within DENY_TEMP_IP_LIMIT,
    # discarding those closest to expiry to make room.
    $class->_enforce_tempblock_limit($config->get('DENY_TEMP_IP_LIMIT'), $ip);

    # Record the block. A block that cannot be recorded is undone rather
    # than kept, and the choice is between two bad outcomes.
    #
    # Undoing it leaves an attacker unblocked because a filesystem is
    # full. Keeping it leaves an address blocked that nothing knows
    # about: absent from "hostguard -t" and from the WHM page, so nobody
    # can find it to remove it, and with LF_IPSET=0 carrying no timeout
    # either, which makes it permanent. The first is bad and visible;
    # the second is bad and silent, and it accumulates.
    #
    # Either way the caller is told the truth, which is the part that
    # was missing: the helper died instead of reporting, so the
    # exception unwound past a kernel change that had already been made.
    unless (_append_tempblock($ip, $expires, $reason)) {
        HGLogger->error("tempblock: $ip was blocked but the block could not be "
                      . "recorded; undoing it rather than holding an address "
                      . "nothing can show or remove");
        unless (_unblock_kernel($ip)) {
            HGLogger->error("tempblock: $ip could not be unblocked either, so "
                          . "it is in force and unrecorded. Remove it with: "
                          . "hostguard -tr $ip");
        }
        return 0;
    }

    HGLogger->info("Temporary block: $ip for ${duration}s - $reason");

    # Call block report hook if configured
    my $hook = HGFirewall->safe_hook($config->get('BLOCK_REPORT'), 'BLOCK_REPORT');
    if ($hook) {
        # Sanitize arguments - only pass validated IP
        system($hook, $ip, $reason, $duration);
    }

    return 1;
}

# Permanently block an IP (add to deny list)
sub permblock {
    my ($class, $ip, $reason) = @_;
    return HGFirewall->_with_lock('permblock', sub {
        return _permblock_locked($class, $ip, $reason);
    });
}

sub _permblock_locked {
    my ($class, $ip, $reason) = @_;

    unless (HGConfig->valid_ip($ip)) {
        HGLogger->error("permblock: Invalid IP: $ip");
        return 0;
    }

    my @allow = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/allow.conf");
    if (HGConfig->ip_in_list($ip, @allow)) {
        HGLogger->info("permblock: Skipping allowed IP $ip");
        return 0;
    }

    # Ignored addresses are never blocked, including by the daemon's
    # repeat-offender promotion.
    my @ignore = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/ignore.conf");
    if (HGConfig->ip_in_list($ip, @ignore)) {
        HGLogger->info("permblock: Skipping ignored IP $ip");
        return 0;
    }

    $reason //= "Permanent block";

    # Add to deny.conf, before anything is changed in the kernel.
    #
    # deny.conf is what a permanent block is: the kernel entry is rebuilt from
    # this file on every reload, so an address blocked only in the kernel is
    # blocked until the next reload and no longer. Writing first means a
    # failure here costs nothing - there is no kernel change to undo - and
    # reporting it means the caller is not told an address is permanently
    # blocked when the record of it never landed.
    #
    # print and close are both checked, as well as open. A short write on a full
    # filesystem reports itself at one or the other and at neither reliably, so
    # asking only about open would let exactly the failure that happens in
    # practice through unnoticed.
    my $denyfile = "$HGConfig::CONFIG_DIR/deny.conf";
    my $reason_line = $reason;
    $reason_line =~ s/[\r\n]/ /g;

    open(my $fh, '>>', $denyfile) or do {
        HGLogger->error("permblock: cannot append to $denyfile: $!; $ip was "
                      . "not blocked");
        return 0;
    };
    flock($fh, LOCK_EX);
    my $wrote = print $fh "$ip # $reason_line - " . localtime() . "\n";
    my $werr  = $wrote ? '' : "$!";
    unless (close($fh)) {
        $werr ||= "$!";
        $wrote = 0;
    }
    unless ($wrote) {
        HGLogger->error("permblock: cannot append to $denyfile: $werr; $ip was "
                      . "not blocked");
        return 0;
    }

    # Add to ipset/iptables immediately.
    #
    # The entry in deny.conf above is the persistent record and is kept either
    # way, because a reload will apply it. What can still fail is putting it
    # into the running firewall, and until that succeeds the address is not
    # actually blocked, so this reports failure rather than implying it is.
    my $rc = 0;
    if ($USE_IPSET && HGConfig->valid_ipv4($ip)) {
        ($rc) = _run_live($IPSET, 'add', $SET_DENY4, $ip, '-exist');
    } elsif ($USE_IPSET && HGConfig->valid_ipv6($ip)) {
        ($rc) = _run_live($IPSET, 'add', $SET_DENY6, $ip, '-exist');
    } elsif (HGConfig->valid_ipv4($ip)) {
        ($rc) = _run_live($IPTABLES, '-I', $CHAIN_DENY, '-s', $ip, '-j', $CHAIN_LOGDROP);
    }

    if ($rc) {
        HGLogger->error("permblock: $ip is in deny.conf but was NOT applied to "
                      . "the running firewall. Run 'hostguard -r' to apply it.");
        return 0;
    }

    HGLogger->info("Permanent block: $ip - $reason");
    return 1;
}

# Allow an IP (add to allow list)
sub allow {
    my ($class, $ip, $comment) = @_;
    return HGFirewall->_with_lock('allow', sub {
        return _allow_locked($class, $ip, $comment);
    });
}

sub _allow_locked {
    my ($class, $ip, $comment) = @_;

    unless (HGConfig->valid_ip($ip)) {
        HGLogger->error("allow: Invalid IP: $ip");
        return 0;
    }

    $comment //= "Manual allow";

    # Add to allow.conf, before anything is changed in the kernel.
    #
    # The order is the point. This file is what a reload rebuilds from, so an
    # allow that is only in the kernel lasts until the next reload and then
    # vanishes - and an administrator who allowed their own address before
    # switching off testing mode is relying on it being there. Writing first
    # means a failure here costs nothing: no kernel change has been made yet,
    # and there is nothing to undo.
    # The comment is stripped of line breaks before it is written.
    #
    # A newline in it would write a second line into allow.conf, and a second
    # line is a second allowlist entry - in the one file that decides who
    # bypasses every block. A comment of "office\n0.0.0.0/0\n" would append a
    # bare 0.0.0.0/0, and the next reload would allowlist the entire internet
    # ahead of every deny check, from a text box labelled "comment".
    #
    # permblock and _append_record strip the same way, for the same reason.
    my $comment_line = $comment;
    $comment_line =~ s/[\r\n]/ /g;

    my $allowfile = "$HGConfig::CONFIG_DIR/allow.conf";
    open(my $fh, '>>', $allowfile) or do {
        HGLogger->error("allow: cannot append to $allowfile: $!; $ip was not "
                      . "allowed");
        return 0;
    };
    flock($fh, LOCK_EX);
    my $wrote = print $fh "$ip # $comment_line - " . localtime() . "\n";
    my $werr  = $wrote ? '' : "$!";
    unless (close($fh)) {
        $werr ||= "$!";
        $wrote = 0;
    }
    unless ($wrote) {
        HGLogger->error("allow: cannot append to $allowfile: $werr; $ip was "
                      . "not allowed");
        return 0;
    }

    # Add to ipset/iptables immediately.
    #
    # allow.conf keeps the entry either way, as with the deny list. Reporting
    # failure matters more here than anywhere else: an administrator allowing
    # their own address before switching off testing mode is relying on this
    # having worked, and finding out otherwise means being locked out.
    my $rc = 0;
    if ($USE_IPSET && HGConfig->valid_ipv4($ip)) {
        ($rc) = _run_live($IPSET, 'add', $SET_ALLOW4, $ip, '-exist');
    } elsif ($USE_IPSET && HGConfig->valid_ipv6($ip)) {
        ($rc) = _run_live($IPSET, 'add', $SET_ALLOW6, $ip, '-exist');
    } elsif (HGConfig->valid_ipv4($ip)) {
        ($rc) = _run_live($IPTABLES, '-I', $CHAIN_ALLOW, '-s', $ip, '-j', 'ACCEPT');
    }

    # Also remove from temp blocks if present.
    #
    # This is the one nested operation here, and its failure is neither
    # ignored nor fatal, because it is not the same kind of failure as the
    # ones above. The allow itself has already landed, and the allowlist is
    # matched before every deny path in the ruleset - the permanent list, the
    # temporary set, the block lists, the country rules - so a temporary block
    # left behind does not keep the address out. What is left is the record:
    # tempblock.dat still lists the address, so the CLI and the WHM page both
    # show it as blocked when it is not.
    #
    # Reporting that as a failed allow would send an administrator to run
    # 'hostguard -r' over an allow that is working, and swallowing it would
    # leave a listing nobody can explain. So it is said plainly, and the
    # allow is still reported as the success it is.
    unless ($class->tempunblock($ip)) {
        HGLogger->log_warn("allow: $ip is allowed, and the allowlist is "
                         . "matched before every block, so it is not being "
                         . "denied. Its temporary block could not be cleared "
                         . "though, so it will still be listed as blocked "
                         . "until that record is removed with: "
                         . "hostguard -tr $ip");
    }

    if ($rc) {
        HGLogger->error("allow: $ip is in allow.conf but was NOT applied to the "
                      . "running firewall. Run 'hostguard -r' to apply it, and "
                      . "do not rely on this address being allowed until you "
                      . "have.");
        return 0;
    }

    HGLogger->info("Allowed IP: $ip - $comment");
    return 1;
}

# Allow an IP for a bounded period.
#
# Held in its own set with a per-entry timeout, so it disappears on its own
# and never touches allow.conf. This is what a dynamic address, a contractor
# who needs access for an afternoon, or a one-off migration wants: access that
# stops without anyone having to remember to remove it.
sub tempallow {
    my ($class, $ip, $duration, $comment) = @_;
    return HGFirewall->_with_lock('tempallow', sub {
        return _tempallow_locked($class, $ip, $duration, $comment);
    });
}

sub _tempallow_locked {
    my ($class, $ip, $duration, $comment) = @_;

    unless (HGConfig->valid_ip($ip)) {
        HGLogger->error("tempallow: Invalid IP: $ip");
        return 0;
    }

    $duration //= 3600;
    $duration = _valid_duration('tempallow', $duration);
    return 0 unless defined $duration;

    $comment //= "Temporary allow";

    unless ($USE_IPSET) {
        HGLogger->error("tempallow needs ipset; set LF_IPSET=1 to use it");
        return 0;
    }

    my $expires = time() + $duration;

    # The set entry is the allow. Without it nothing is allowed, so a failure
    # here is not recorded: an entry in tempallow.dat is shown by the CLI and
    # the WHM page as access that is currently in force.
    my $rc = 0;
    if (HGConfig->valid_ipv4($ip)) {
        ($rc) = _run_live($IPSET, 'add', $SET_TALLOW4, $ip, 'timeout', $duration, '-exist');
    } elsif ($IPV6) {
        ($rc) = _run_live($IPSET, 'add', $SET_TALLOW6, $ip, 'timeout', $duration, '-exist');
    } else {
        HGLogger->error("tempallow: IPv6 address given but IPV6 is 0");
        return 0;
    }

    if ($rc) {
        HGLogger->error("tempallow: $ip was NOT allowed; the kernel refused the "
                      . "command above. Is the firewall started?");
        return 0;
    }

    # An address being allowed should not stay blocked by an earlier failure.
    # As in allow(), a failure to clear it costs the listing rather than the
    # access: the temporary allow set is matched before the temporary block
    # set, so the address is through either way.
    unless ($class->tempunblock($ip)) {
        HGLogger->log_warn("tempallow: $ip is allowed, and the allowlist is "
                         . "matched before every block, so it is not being "
                         . "denied. Its temporary block could not be cleared "
                         . "though, so it will still be listed as blocked "
                         . "until that record is removed with: "
                         . "hostguard -tr $ip");
    }

    # As with a block, and for a sharper reason: an allow that nothing records
    # is a hole in the firewall that no listing shows and that survives until
    # its timeout, which nobody can look up either.
    unless (_append_record("$HGConfig::DATA_DIR/tempallow.dat", $ip, $expires, $comment)) {
        HGLogger->error("tempallow: $ip was allowed but the allow could not be "
                      . "recorded; undoing it rather than leaving access "
                      . "nothing can show or remove");
        unless (_unallow_kernel($ip)) {
            HGLogger->error("tempallow: $ip could not have its allow removed "
                          . "either, so it is in force and unrecorded. Remove "
                          . "it with: hostguard -tar $ip");
        }
        return 0;
    }

    HGLogger->info("Temporary allow: $ip for ${duration}s - $comment");
    return 1;
}

# Remove a temporary allow before it expires.
sub tempallow_remove {
    my ($class, $ip) = @_;
    return HGFirewall->_with_lock('tempallow_remove', sub {
        return _tempallow_remove_locked($class, $ip);
    });
}

sub _tempallow_remove_locked {
    my ($class, $ip) = @_;

    unless (HGConfig->valid_ip($ip)) {
        HGLogger->error("tempallow_remove: Invalid IP: $ip");
        return 0;
    }

    if ($USE_IPSET) {
        if (HGConfig->valid_ipv4($ip)) {
            _run_quiet($IPSET, 'del', $SET_TALLOW4, $ip);
        } else {
            _run_quiet($IPSET, 'del', $SET_TALLOW6, $ip);
        }
    }

    unless (_remove_record("$HGConfig::DATA_DIR/tempallow.dat", $ip)) {
        HGLogger->error("tempallow_remove: $ip is no longer allowed but its "
                      . "record could not be removed, so it will still be listed");
        return 0;
    }

    HGLogger->info("Temporary allow removed: $ip");
    return 1;
}

# Active temporary allows, as the CLI and WHM page show them.
sub list_tempallows {
    my ($class) = @_;
    return _read_records("$HGConfig::DATA_DIR/tempallow.dat");
}

# Remove a temporary block.
#
# Returns true when the address is left neither blocked nor recorded as
# blocked, which includes the case where it was never temp-blocked at all.
# That case is silent: this is called by allow() and tempallow() for every
# address they touch, and logging an unblock for each of them filled the log
# with events that never happened.
sub tempunblock {
    my ($class, $ip) = @_;
    return HGFirewall->_with_lock('tempunblock', sub {
        return _tempunblock_locked($class, $ip);
    });
}

sub _tempunblock_locked {
    my ($class, $ip) = @_;

    unless (HGConfig->valid_ip($ip)) {
        HGLogger->error("tempunblock: Invalid IP: $ip");
        return 0;
    }

    # Remove from ipset
    if ($USE_IPSET) {
        if (HGConfig->valid_ipv4($ip)) {
            _run_quiet($IPSET, 'del', $SET_TEMP4, $ip);
        } elsif (HGConfig->valid_ipv6($ip)) {
            _run_quiet($IPSET, 'del', $SET_TEMP6, $ip);
        }
    } else {
        _run_quiet($IPTABLES, '-D', $CHAIN_DENY, '-s', $ip, '-j', $CHAIN_LOGDROP) if HGConfig->valid_ipv4($ip);
    }

    # The entry has gone from the kernel, so a record still claiming it is
    # held is wrong in the other direction: it over-reports. Less dangerous
    # than an unrecorded block and still not success.
    my $removed = 0;
    unless (_remove_tempblock($ip, \$removed)) {
        HGLogger->error("tempunblock: $ip is no longer blocked but its record "
                      . "could not be removed, so it will still be listed");
        return 0;
    }

    HGLogger->info("Temporary unblock: $ip") if $removed;
    return 1;
}

# Search for an IP in all rules and lists
sub grep_ip {
    my ($class, $ip) = @_;
    my @results;

    # Check allow.conf
    my @allow = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/allow.conf");
    for my $e (@allow) {
        if ($e->{ip} eq $ip || HGConfig->ip_in_cidr($ip, $e->{ip})) {
            push @results, "ALLOW: $e->{ip}" . ($e->{comment} ? " # $e->{comment}" : "");
        }
    }

    # Check deny.conf
    my @deny = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/deny.conf");
    for my $e (@deny) {
        if ($e->{ip} eq $ip || HGConfig->ip_in_cidr($ip, $e->{ip})) {
            push @results, "DENY: $e->{ip}" . ($e->{comment} ? " # $e->{comment}" : "");
        }
    }

    # Check ignore.conf
    my @ignore = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/ignore.conf");
    for my $e (@ignore) {
        if ($e->{ip} eq $ip || HGConfig->ip_in_cidr($ip, $e->{ip})) {
            push @results, "IGNORE: $e->{ip}" . ($e->{comment} ? " # $e->{comment}" : "");
        }
    }

    # Check temp blocks
    my @temp = $class->list_tempblocks();
    for my $t (@temp) {
        if ($t->{ip} eq $ip) {
            push @results, "TEMPBLOCK: $t->{ip} expires=$t->{expires} reason=$t->{reason}";
        }
    }

    # Check the live iptables rules. The listing is filtered in Perl so the
    # search term never forms part of a command line.
    my ($rc, $ipt_out) = _run_quiet($IPTABLES, '-L', '-n');
    if (!$rc && $ipt_out) {
        for my $line (split(/\n/, $ipt_out)) {
            push @results, "IPTABLES: $line" if $line =~ /\b\Q$ip\E\b/;
        }
    }

    return @results;
}

# List all temporary blocks
sub list_tempblocks {
    my ($class) = @_;
    my @blocks;
    my $tempfile = "$HGConfig::DATA_DIR/tempblock.dat";
    return @blocks unless -f $tempfile;

    open(my $fh, '<', $tempfile) or return @blocks;
    flock($fh, LOCK_SH);
    my $now = time();
    while (my $line = <$fh>) {
        chomp $line;
        my ($ip, $expires, $reason) = split(/\|/, $line, 3);
        next unless $ip && $expires;
        push @blocks, {
            ip      => $ip,
            expires => $expires,
            reason  => $reason // "",
            active  => ($expires > $now ? 1 : 0),
            ttl     => ($expires > $now ? $expires - $now : 0),
        };
    }
    close($fh);
    return @blocks;
}

###############################################################################
# Temp block file management
###############################################################################

# Drop the soonest-expiring temporary blocks until one slot remains below the
# configured ceiling. A limit of 0 leaves the number of blocks unbounded.
# How fast the ceiling may release blocks, and how many at once.
#
# The ceiling itself is right: an unbounded set is its own problem. What was
# wrong was that it could be driven. Every new block released the entry closest
# to expiry, and the check ran against tempblock.dat before the new entry was
# written, so anyone able to produce DENY_TEMP_IP_LIMIT blocks - a botnet
# larger than the limit, or one host forging failures into a log - pushed every
# existing block out of the table, including the one placed on themselves a
# moment earlier. Blocking was defeatable at a fixed and quite low cost.
#
# Two changes close that. Releasing is rate limited, so filling the table
# faster than $EVICT_MAX_PER_WINDOW blocks per $EVICT_WINDOW seconds stops
# evicting rather than evicting faster; and once the rate is reached the new
# block is still applied, leaving the set briefly over its ceiling. That is the
# cheaper mistake by a wide margin - these sets are created with maxelem
# 1000000, so the ceiling is an operator preference, while an emptied table is
# an attacker walking back in.
#
# The remaining ordering is unchanged and was never the defect: with a shared
# LF_TEMP_BLOCK_DURATION, closest-to-expiry is also least-recently-blocked, and
# an address that keeps attacking keeps having its expiry pushed out, so it is
# never the candidate.
our $EVICT_WINDOW         = 300;
our $EVICT_MAX_PER_WINDOW = 10;

# Where the eviction times live.
#
# They were held in a package variable, which meant a short-lived process
# started with an empty history and was never rate limited: only the daemon was
# covered. That is where a flood arrives, so the control worked where it
# mattered - but a limit that any CLI or WHM invocation resets is not a limit.
# Held in the state directory instead, read and written under the firewall lock
# this is already called with.
sub _evict_log_file { return "$HGConfig::DATA_DIR/evictions.dat" }

sub _read_evictions {
    my ($window) = @_;
    my $now = time();
    my @times;
    open(my $fh, '<', _evict_log_file()) or return @times;
    while (my $l = <$fh>) {
        chomp $l;
        next unless $l =~ /^(\d+)$/;
        push @times, $1 if $1 > $now - $window;
    }
    close($fh);
    return @times;
}

sub _write_evictions {
    my (@times) = @_;
    eval { HGConfig::_write_atomic(_evict_log_file(),
                                  join('', map { "$_\n" } @times)); 1 }
        or HGLogger->debug("Cannot record the eviction time: $@");
    return;
}

sub _enforce_tempblock_limit {
    my ($class, $limit, $incoming) = @_;
    return unless defined $limit && $limit =~ /^\d+$/ && $limit > 0;

    my @active = grep { $_->{active} } $class->list_tempblocks();

    # An address already in the table needs no room made for it: the record is
    # replaced rather than added. Treating it as a newcomer released one entry
    # more than necessary every time a repeat offender was blocked again.
    return if defined $incoming && grep { $_->{ip} eq $incoming } @active;

    return if @active < $limit;

    my $now = time();
    my @evictions = _read_evictions($EVICT_WINDOW);

    if (@evictions >= $EVICT_MAX_PER_WINDOW) {
        HGLogger->log_warn("Temporary block limit of $limit is reached, but "
                         . scalar(@evictions) . " blocks have already been "
                         . "released in the last ${EVICT_WINDOW}s, so no more "
                         . "are being released. The new block is still applied "
                         . "and the set is over its ceiling: that is deliberate, "
                         . "because a flood able to empty this table would let "
                         . "everything already in it back in. Raise "
                         . "DENY_TEMP_IP_LIMIT.");
        return;
    }

    # One at a time. Room is only ever needed for the single block being made,
    # and a call that could release hundreds is the mechanism the flood used.
    my ($oldest) = sort { $a->{expires} <=> $b->{expires} } @active;
    return unless $oldest;

    HGLogger->log_warn("Temporary block limit of $limit reached; releasing "
                     . "$oldest->{ip}, which had " . ($oldest->{expires} - $now)
                     . "s left to run, to make room for a new block");
    push @evictions, $now;
    _write_evictions(@evictions);
    $class->tempunblock($oldest->{ip});
}

# Generic "ip|expires|note" record helpers.
#
# The temporary block file predates these and keeps its own pair above; the
# temporary allow file uses the same shape, so one implementation serves both
# and the two files stay readable by the same eye.
# Record-file helpers.
#
# Each of these reports whether it did what it was asked, rather than dying or
# returning regardless. The state directory is small - a runaway log or an
# oversized block list is all it takes to fill it - and a short write accepted
# in silence would leave the caller returning success after it had already made
# the kernel change. The address would then be blocked with nothing recording
# it: absent from "hostguard -t", absent from the WHM page, and with LF_IPSET=0
# absent from anything that would ever take it out again.
#
# A record that cannot be written is therefore a failure of the operation, not
# a detail of it, and the operation is undone rather than half-kept.

sub _append_record {
    my ($file, $ip, $expires, $note) = @_;

    $note = '' unless defined $note;
    $note =~ s/[|\r\n]/ /g;
    my $line = "$ip|$expires|$note\n";

    # Read what is there, so that replacing an entry can be one write.
    my @kept;
    my $present = 0;
    my $ends_cleanly = 1;

    if (-f $file) {
        open(my $fh, '<', $file) or do {
            HGLogger->error("Cannot read $file: $!");
            return 0;
        };
        flock($fh, LOCK_SH);
        while (my $l = <$fh>) {
            $ends_cleanly = ($l =~ /\n\z/) ? 1 : 0;
            chomp $l;
            next unless length $l;
            my ($lip) = split(/\|/, $l, 2);
            next unless defined $lip;
            if ($lip eq $ip) { $present++; next }
            push @kept, "$l\n";
        }
        close($fh);
    }

    # Replacing an entry is a single atomic write, not a removal followed by
    # an append.
    #
    # In two steps there is a moment when the address is in neither the old
    # line nor the new one. A failure in that moment - a full filesystem is the
    # ordinary cause - left the address recorded nowhere while it was still
    # blocked, or still allowed, in the kernel; and a crash there left the same
    # gap with nothing to report it. Writing the whole file once means it holds
    # either the entry as it was or the entry as it now is, and never neither.
    if ($present) {
        unless (eval { HGConfig::_write_atomic($file, join('', @kept) . $line); 1 }) {
            my $err = $@ || 'unknown error';
            chomp $err;
            HGLogger->error("Cannot rewrite $file: $err");
            return 0;
        }
        chmod(0600, $file);
        return 1;
    }

    # A new address is appended instead of rewriting the file around it. That
    # is not laziness about the transaction above - there is nothing to lose
    # here, since the address is in no line yet - and it is what keeps the cost
    # of recording a block from growing with the number of blocks already
    # recorded, which is the wrong way round during the flood that produces
    # them.
    open(my $fh, '>>', $file) or do {
        HGLogger->error("Cannot append to $file: $!");
        return 0;
    };
    flock($fh, LOCK_EX);

    # A previous write that ran out of disk can leave a line without its
    # newline. Appending to that would join two records into one.
    my $ok = 1;
    $ok = print $fh "\n" unless $ends_cleanly;

    # print reports a full filesystem here; close reports one that was only
    # discovered when the buffer was flushed. Both have to be asked.
    $ok &&= print $fh $line;
    my $err = $ok ? '' : "$!";
    unless (close($fh)) {
        $err ||= "$!";
        $ok = 0;
    }

    unless ($ok) {
        HGLogger->error("Cannot append to $file: $err");
        return 0;
    }

    chmod(0600, $file);
    return 1;
}

# Returns true when the file no longer holds an entry for the address, which
# includes there being no file at all.
# Remove every record for an address, reporting success.
#
# $removed_ref, when given, comes back true only if a record was actually
# there. "Nothing to remove" and "removed" are both success - the address is
# not recorded either way - but they are not the same event, and a caller that
# announces an unblock it did not perform is telling the log something untrue.
sub _remove_record {
    my ($file, $ip, $removed_ref) = @_;
    $$removed_ref = 0 if $removed_ref;
    return 1 unless -f $file;

    open(my $fh, '<', $file) or do {
        HGLogger->error("Cannot read $file: $!");
        return 0;
    };
    flock($fh, LOCK_SH);
    my @lines = <$fh>;
    close($fh);

    my $out     = '';
    my $removed = 0;
    for my $line (@lines) {
        my ($lip) = split(/\|/, $line, 2);
        next unless defined $lip;
        if ($lip eq $ip) { $removed++; next }
        $out .= $line;
    }
    return 1 unless $removed;

    unless (eval { HGConfig::_write_atomic($file, $out); 1 }) {
        my $err = $@ || 'unknown error';
        chomp $err;
        HGLogger->error("Cannot rewrite $file: $err");
        return 0;
    }
    $$removed_ref = $removed if $removed_ref;
    return 1;
}

# Read a record file, dropping entries that have expired.
#
# Expiry is decided from the timestamp rather than from the set, so the list
# an administrator is shown matches what is actually still in force even if
# the kernel dropped an entry a moment earlier.
# Read a record file, optionally reporting what could not be read.
#
# The stats hashref, when given, comes back with 'unreadable' set if the file
# is there but would not open, and 'damaged' counting lines that did not parse.
# Neither must be allowed to look like "there are no records": an unreadable
# tempallow.dat would otherwise mean every temporary allow being dropped from a
# rebuilt ruleset without a word.
sub _read_records {
    my ($file, $stats) = @_;
    $stats ||= {};
    $stats->{unreadable} = 0;
    $stats->{damaged}    = 0;

    my @records;
    return @records unless -e $file;

    # Something at the path that is not a regular file - a directory left by a
    # botched restore, a stale mount point - is not "no records". Treating it as
    # absent would silently empty this part of the ruleset.
    unless (-f $file) {
        HGLogger->error("$file is not a regular file, so no records could be "
                      . "read from it");
        $stats->{unreadable} = 1;
        return @records;
    }

    open(my $fh, '<', $file) or do {
        HGLogger->error("Cannot read $file: $!");
        $stats->{unreadable} = 1;
        return @records;
    };
    flock($fh, LOCK_SH);
    my $now = time();
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;
        my ($ip, $expires, $note) = split(/\|/, $line, 3);
        unless (defined $ip && defined $expires && $expires =~ /^\d+$/) {
            $stats->{damaged}++;
            next;
        }
        next if $expires <= $now;
        push @records, {
            ip      => $ip,
            expires => $expires,
            ttl     => $expires - $now,
            note    => defined $note ? $note : '',
        };
    }
    close($fh);

    return @records;
}

# The temporary block file is a record file like any other, so it is written by
# the same code rather than by a copy of it. One implementation is what keeps
# the reason sanitising in force here: a reason is assembled from log text,
# including names an attacker chooses, so a newline in one would write a second
# line into the file and a "|" would move the field boundaries of the line it
# was in.
sub _append_tempblock {
    my ($ip, $expires, $reason) = @_;
    return _append_record("$HGConfig::DATA_DIR/tempblock.dat", $ip, $expires, $reason);
}

# Add several records in one read-modify-write.
#
# Takes ip => expires. Existing lines for those addresses are replaced, as
# _append_record does for one, so calling this with an address already present
# is safe. Returns how many were added, or 0 if the write failed - in which
# case nothing was written and the caller reports the whole batch as
# unrecorded, which is true.
sub _append_tempblocks {
    my ($records) = @_;
    return 0 unless $records && %$records;

    my $file = "$HGConfig::DATA_DIR/tempblock.dat";
    my $note = 'Blocked by the kernel (port scan or SET rule)';

    my @kept;
    if (-f $file) {
        open(my $fh, '<', $file) or do {
            HGLogger->error("Cannot read $file: $!");
            return 0;
        };
        flock($fh, LOCK_SH);
        while (my $l = <$fh>) {
            chomp $l;
            next unless length $l;
            my ($lip) = split(/\|/, $l, 2);
            next unless defined $lip;
            next if exists $records->{$lip};
            push @kept, "$l\n";
        }
        close($fh);
    }

    for my $ip (sort keys %$records) {
        push @kept, "$ip|$records->{$ip}|$note\n";
    }

    unless (eval { HGConfig::_write_atomic($file, join('', @kept)); 1 }) {
        my $err = $@ || 'unknown error';
        chomp $err;
        HGLogger->error("Cannot write $file: $err");
        return 0;
    }
    return scalar(keys %$records);
}

sub _remove_tempblock {
    my ($ip, $removed_ref) = @_;
    return _remove_record("$HGConfig::DATA_DIR/tempblock.dat", $ip, $removed_ref);
}

# Undo a block in the kernel, touching no files.
#
# Separate from tempunblock because it is called when a file could not be
# written: a rollback that needs to write a file to undo a failed write is no
# rollback at all.
sub _unblock_kernel {
    my ($ip) = @_;
    my $rc = 0;

    if ($USE_IPSET) {
        if (HGConfig->valid_ipv4($ip)) {
            ($rc) = _run_quiet($IPSET, 'del', $SET_TEMP4, $ip);
        } elsif (HGConfig->valid_ipv6($ip)) {
            ($rc) = _run_quiet($IPSET, 'del', $SET_TEMP6, $ip);
        }
    } elsif (HGConfig->valid_ipv4($ip)) {
        ($rc) = _run_quiet($IPTABLES, '-D', $CHAIN_DENY, '-s', $ip, '-j', $CHAIN_LOGDROP);
    }

    return $rc ? 0 : 1;
}

# The same for a temporary allow.
sub _unallow_kernel {
    my ($ip) = @_;
    return 1 unless $USE_IPSET;

    my $rc = 0;
    if (HGConfig->valid_ipv4($ip)) {
        ($rc) = _run_quiet($IPSET, 'del', $SET_TALLOW4, $ip);
    } elsif (HGConfig->valid_ipv6($ip)) {
        ($rc) = _run_quiet($IPSET, 'del', $SET_TALLOW6, $ip);
    }
    return $rc ? 0 : 1;
}

# Record any temporary block that is in the kernel and in no file.
#
# Port scan detection blocks by way of an iptables SET target: the kernel adds
# the source to the temporary block set itself, with a timeout, and no code
# here ever runs. So the address was blocked and nothing recorded it - absent
# from "hostguard -l", absent from the WHM page, absent from "hostguard -g",
# so an administrator looking into why a customer could not reach the server
# had nothing to find. Worse, _load_tempblocks restores from the file alone, so
# every reload silently released every address the scan detector had caught,
# and _enforce_tempblock_limit counted a table that was not the real occupancy
# of the set.
#
# The kernel is the authority here, so this reconciles towards it rather than
# away: a member with no line gets one written, with the remaining timeout the
# set reports. Nothing is removed - that is cleanup_expired's job, and removing
# on the strength of a listing that failed to parse would be the same mistake
# in the other direction.
#
# Written generally rather than for scan detection specifically, so anything
# else that ever adds to these sets from the kernel side is covered too.
sub reconcile_tempblocks {
    my ($class) = @_;
    return 0 unless $USE_IPSET;

    return HGFirewall->_with_lock('reconcile_tempblocks', sub {
        return _reconcile_tempblocks_locked($class);
    });
}

# Most members recorded in one pass.
#
# The pass holds the firewall lock, so its duration is latency on every block,
# allow and reload that arrives meanwhile - and past the 30s _with_lock waits,
# latency becomes failure. Bounded here rather than trusted to stay small: the
# remainder is picked up on the next pass 180 seconds later, and an address
# stays blocked in the kernel throughout either way.
our $RECONCILE_MAX_PER_PASS = 500;

sub _reconcile_tempblocks_locked {
    my ($class) = @_;

    my %recorded = map { $_->{ip} => 1 } $class->list_tempblocks();
    my %missing;          # ip => expires
    my $capped = 0;

    for my $set (grep { defined && length } ($SET_TEMP4, ($IPV6 ? $SET_TEMP6 : ()))) {
        my ($rc, $out) = _run_quiet($IPSET, 'list', $set);
        next if $rc || !defined $out;

        my $in_members = 0;
        for my $line (split(/\n/, $out)) {
            if ($line =~ /^Members:/) { $in_members = 1; next }
            next unless $in_members;
            $line =~ s/^\s+//;
            $line =~ s/\s+$//;
            next unless length $line;

            my ($member, $timeout) = $line =~ /^(\S+)(?:\s+timeout\s+(\d+))?/;
            next unless defined $member;
            # The sets hold hash:net, so a single address lists as a bare
            # address; strip a /32 or /128 if the kernel writes one.
            $member =~ s{/(?:32|128)$}{};
            next unless HGConfig->valid_ip($member);
            next if $recorded{$member} || exists $missing{$member};

            if (scalar(keys %missing) >= $RECONCILE_MAX_PER_PASS) {
                $capped = 1;
                last;
            }

            # No timeout means the entry never expires, which a scan block
            # always has and a hand-made one may not. Recorded at the ceiling
            # rather than skipped, so it is at least visible and removable.
            my $ttl = (defined $timeout && $timeout > 0) ? $timeout : $MAX_TIMEOUT;
            $missing{$member} = time() + $ttl;
        }
        last if $capped;
    }

    return 0 unless %missing;

    # One write for the whole batch.
    #
    # This called _append_tempblock per member, and _append_record reads the
    # entire file on every call to decide whether the address is already there.
    # The writes were linear; the reads were not, so the pass was quadratic in
    # the number of members being recorded - 1.6s at a thousand, 12.6s at four
    # thousand, all of it with the firewall lock held. Past about eight thousand
    # a concurrent block exceeded the 30s lock wait and failed outright, and
    # past twelve thousand so did a reload.
    my $added = _append_tempblocks(\%missing);

    if ($added) {
        HGLogger->info("Recorded $added temporary block(s) that the kernel had "
                     . "made and nothing had written down"
                     . ($capped ? "; more remain and will be recorded on the "
                                . "next pass" : ''));
    } else {
        HGLogger->error("reconcile: " . scalar(keys %missing) . " address(es) "
                      . "are blocked in the kernel but their records could not "
                      . "be written, so they stay invisible to the CLI and the "
                      . "WHM page");
    }
    return $added;
}

# Clean up expired temp blocks from the data file
sub cleanup_expired {
    my ($class) = @_;
    return HGFirewall->_with_lock('cleanup_expired', sub {
        return _cleanup_expired_locked($class);
    });
}

sub _cleanup_expired_locked {
    my ($class) = @_;

    # Reconcile before sweeping, not after: an entry the kernel holds and the
    # file does not would otherwise be written down and then, on the same pass,
    # have nothing to sweep - harmless, but the order also means a scan block
    # becomes visible one cycle sooner.
    _reconcile_tempblocks_locked($class);

    my $tempfile = "$HGConfig::DATA_DIR/tempblock.dat";
    return unless -f $tempfile;

    open(my $fh, '<', $tempfile) or return;
    flock($fh, LOCK_SH);
    my @lines = <$fh>;
    close($fh);

    my $now = time();
    my @kept;
    for my $line (@lines) {
        chomp $line;
        next unless length $line;
        my ($ip, $expires) = split(/\|/, $line, 3);
        next unless defined $ip && defined $expires && $expires =~ /^\d+$/;
        if ($expires > $now) {
            push @kept, "$line\n";
        } else {
            HGLogger->info("Expired temp block removed: $ip");
        }
    }

    eval { HGConfig::_write_atomic($tempfile, join('', @kept)); 1 }
        or HGLogger->error("Cannot rewrite tempblock.dat: $@");
}

###############################################################################
# Helpers
###############################################################################

# Commands never reach a shell, but a configuration value that looks like an
# option - ETH_DEVICE="-j", say - would still be read by iptables as one. These
# checks keep such values out of the argument list.

# An iptables jump target: one of the built-ins, or one of our own chains.
sub _valid_target {
    my ($target) = @_;
    return 'DROP' unless defined $target && length $target;
    $target = uc($target) if $target =~ /^(?:drop|reject|accept)$/i;
    my %ok = map { $_ => 1 } (
        'DROP', 'REJECT', 'ACCEPT',
        $CHAIN_IN, $CHAIN_OUT, $CHAIN_DENY, $CHAIN_ALLOW, $CHAIN_LOGDROP,
        $CHAIN_SYNFLOOD,
        $CHAIN_AALLOW_IN, $CHAIN_AALLOW_OUT, $CHAIN_ADENY_IN, $CHAIN_ADENY_OUT,
        $CHAIN6_IN, $CHAIN6_OUT, $CHAIN6_DENY, $CHAIN6_ALLOW,
    );
    return $target if $ok{$target};
    return $target if defined $CHAIN6_LOGDROP && $target eq $CHAIN6_LOGDROP;
    return $target if defined $CHAIN6_SYNFLOOD && $target eq $CHAIN6_SYNFLOOD;
    return $target if defined $CHAIN6_SCAN && $target eq $CHAIN6_SCAN;
    HGLogger->error("Invalid firewall target '$target', falling back to DROP");
    return 'DROP';
}

# A network interface name. Rejects anything that could be read as an option.
sub _valid_device {
    my ($dev) = @_;
    return 0 unless defined $dev && length $dev;
    return 0 if $dev =~ /^-/;
    return $dev =~ /^[A-Za-z0-9_.:@+-]{1,15}$/ ? 1 : 0;
}

# A single port or a single "low:high" range, as accepted by a bare
# --dport/--sport. Comma lists would need -m multiport and are rejected here.
sub _valid_single_port {
    my ($port) = @_;
    return 0 unless defined $port;
    if ($port =~ /^(\d{1,5}):(\d{1,5})$/) {
        return 0 if $1 > 65535 || $2 > 65535 || $1 > $2;
        return 1;
    }
    return 0 unless $port =~ /^\d{1,5}$/;
    return $port <= 65535 ? 1 : 0;
}

sub _parse_ports {
    my ($portstr) = @_;
    return () unless $portstr;
    my @ports;
    for my $p (split(/,/, $portstr)) {
        $p =~ s/\s//g;
        next unless $p;
        # iptables writes ranges as low:high; accept a dash as an alias.
        $p =~ s/-/:/;
        unless (_valid_single_port($p)) {
            HGLogger->error("Ignoring invalid port specification: $p");
            next;
        }
        push @ports, $p;
    }
    return @ports;
}

# Execute a command as an argument list, capturing stdout and stderr.
#
# The command is exec'd directly with no shell involved, so values originating
# in hostguard.conf or the allow, deny and ignore lists cannot be interpreted
# as shell syntax. Callers pass a list, never a single pre-joined string.
sub _exec {
    my (@args) = @_;
    return (-1, "empty command") unless @args && defined $args[0] && length $args[0];

    # Wait for the xtables lock rather than failing the moment something else
    # holds it. See _detect_ipt_wait.
    if (@IPT_WAIT && defined $IPTABLES && defined $IP6TABLES
        && ($args[0] eq $IPTABLES || $args[0] eq $IP6TABLES)) {
        splice(@args, 1, 0, @IPT_WAIT);
    }

    return _exec_raw(@args);
}

# The exec itself, with nothing added.
#
# Separate from _exec so that the probe which decides what _exec adds can run
# without being handed the thing it is probing for.
sub _exec_raw {
    my (@args) = @_;
    return (-1, "empty command") unless @args && defined $args[0] && length $args[0];

    # SIGCHLD restored for the length of this call.
    #
    # close() on a '-|' handle reaps the child and puts its exit status in $?.
    # The daemon sets SIGCHLD to IGNORE so that its own short-lived children -
    # the mailer, a block report hook - are not left as zombies, and that is a
    # request to the kernel to discard exactly the status this needs: waitpid
    # inside close() then fails with ECHILD and $? comes back as -1.
    #
    # Shifted, -1 is a large positive number, so every caller would read every
    # command as having failed. In the daemon that means _run_live reporting
    # that the kernel refused an ipset add which in fact succeeded, tempblock
    # rolling the block back and declining to record it, and the same for
    # permblock, allow, tempallow and every action arriving from the cluster -
    # the firewall enforcing one thing while the daemon believes and reports
    # another. It is the exact inversion of what the rest of this file exists
    # to prevent.
    #
    # HGConfig::download_capped already restores the disposition for its own
    # fork, and the WHM CGI already guards the -1 case. This is the same fix
    # on the path every firewall operation takes.
    local $SIG{CHLD} = 'DEFAULT';

    my $pid = open(my $fh, '-|');
    unless (defined $pid) {
        return (-1, "fork failed: $!");
    }
    if ($pid == 0) {
        # Child: fold stderr into stdout so the parent captures both.
        open(STDERR, '>&', \*STDOUT);
        exec { $args[0] } @args;
        exit(127);    # only reached if exec itself failed
    }

    my $out = do { local $/; <$fh> };
    close($fh);

    # -1 means no status could be collected at all. That is not an exit code
    # and must not be shifted into one.
    my $rc = ($? == -1) ? -1 : ($? >> 8);
    return ($rc, defined $out ? $out : '');
}

# Run a command and log it if it fails.
# Commands that failed while assembling the current ruleset.
#
# Reset at the start of each build. Anything recorded here means the slot is
# incomplete, and _build_failures() is what start() consults before deciding
# whether the slot is fit to carry traffic.
sub _reset_failures { @BUILD_FAILURES = (); }
sub _build_failures { return @BUILD_FAILURES; }

# The commands that failed during the last build, for a caller that wants to
# show them rather than send the administrator to the log.
sub failures {
    my ($class) = @_;
    return map { $_->{cmd} } @BUILD_FAILURES;
}

# Run a command the ruleset depends on.
#
# A failure here changes what the firewall does - a missing allowlist match, a
# missing deny match, a port that never opens - so it is recorded and the slot
# it belongs to will not be activated.
sub _run {
    my (@args) = @_;
    HGLogger->debug("RUN: " . join(' ', @args));
    my ($rc, $out) = _exec(@args);
    if ($rc) {
        my $cmd = join(' ', @args);
        HGLogger->error("Command failed (rc=$rc): $cmd\n  Output: $out");
        push @BUILD_FAILURES, { cmd => $cmd, rc => $rc, out => $out };
    }
    return ($rc, $out);
}

# Run a command against the ruleset that is already live.
#
# Adding a block or an allow while the firewall is running is not part of
# building a slot, so a failure here must not be counted against the next
# build: the daemon runs for weeks between builds, and its failures would
# otherwise accumulate and be reported as though a rebuild had gone wrong.
#
# The caller is expected to check the return code. Every one of them records
# the address somewhere afterwards, and that record is a claim the firewall is
# enforcing something.
sub _run_live {
    my (@args) = @_;
    HGLogger->debug("RUN: " . join(' ', @args));
    my ($rc, $out) = _exec(@args);
    if ($rc) {
        HGLogger->error("Command failed (rc=$rc): " . join(' ', @args)
                      . "\n  Output: $out");
    }
    return ($rc, $out);
}

# Run a command that refines the ruleset without deciding what it permits.
#
# Flood mitigation, connection limits, ICMP rate limiting and the logging rules
# all sit here. The installer probes these matches and reports them as optional
# for the same reason: a host whose kernel lacks xt_recent should still get a
# working firewall, just without the feature that needs it. A failure is
# reported and the build continues.
sub _run_opt {
    my (@args) = @_;
    HGLogger->debug("RUN: " . join(' ', @args));
    my ($rc, $out) = _exec(@args);
    if ($rc) {
        HGLogger->log_warn("Optional rule not applied (rc=$rc): " . join(' ', @args)
                         . "\n  Output: $out");
    }
    return ($rc, $out);
}

# Run a command whose failure is expected and uninteresting, such as deleting
# a rule or destroying an ipset that may not exist.
sub _run_quiet {
    my (@args) = @_;
    HGLogger->debug("RUN: " . join(' ', @args));
    return _exec(@args);
}

sub _write_file {
    my ($file, $content) = @_;
    open(my $fh, '>', $file) or die "Cannot write $file: $!\n";
    print $fh $content;
    close($fh);
}

1;
