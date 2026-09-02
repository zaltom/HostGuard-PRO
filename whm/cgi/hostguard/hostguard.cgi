#!/usr/bin/perl
#WHMADDON:hostguard:HostGuard Pro
###############################################################################
# HostGuard Pro - WHM Plugin Interface
# /usr/local/cpanel/whostmgr/docroot/cgi/hostguard/hostguard.cgi
#
# Written to the shape cpsrvd expects of a WHM add-on CGI:
# - BEGIN block for lib paths
# - Cpanel::Form::parseform() for parameters
# - Whostmgr::ACLS for authentication
# - Raw print for HTTP header
# - NO CGI.pm, NO CGI::Carp
###############################################################################

BEGIN {
    unshift @INC, '/usr/local/hostguard/lib';
    unshift @INC, '/usr/local/cpanel';
}

use strict;
use Fcntl qw(:DEFAULT :flock);
use POSIX qw(strftime);

###############################################################################
# CRITICAL: Print header FIRST so cpsrvd never returns a bare 500.
# If anything below dies, the user sees the error in-page instead of
# a generic "Internal Server Error" from cpsrvd.
###############################################################################
print "Content-type: text/html\r\n\r\n";

# Wrap the entire CGI body in eval so any die/croak is caught
eval {
    _main();
};
if ($@) {
    # If _main() died, show the error in the page instead of a 500
    my $err = $@;
    $err =~ s/&/&amp;/g;
    $err =~ s/</&lt;/g;
    $err =~ s/>/&gt;/g;
    print "<html><body><h2>HostGuard Pro - Error</h2><pre>$err</pre>";
    print "<p>Check file permissions and Perl module paths.</p></body></html>";
}
exit;

###############################################################################
# Main entry point - everything runs inside this so the eval catches all errors
###############################################################################
sub _main {

    # --- WHM Authentication (cPanel native) ---
    # Authentication fails closed. This interface can stop the firewall and
    # rewrite the allow and deny lists as root, so if the ACL modules cannot be
    # loaded there is no way to establish who the caller is and the request is
    # refused.
    my $acl_error = '';
    eval {
        require Cpanel::Form;
        require Whostmgr::ACLS;
        Whostmgr::ACLS::init_acls();
        1;
    } or do {
        $acl_error = $@ || 'unknown error';
    };

    if ($acl_error) {
        print "<h2>Access Denied</h2>";
        print "<p>HostGuard Pro could not load the WHM access control modules, "
            . "so it cannot verify that you are authorised. Refusing to continue.</p>";
        print "<pre>" . _h($acl_error) . "</pre>";
        return;
    }

    if (!Whostmgr::ACLS::hasroot()) {
        print "<h2>Access Denied</h2><p>Root access required for HostGuard Pro.</p>";
        return;
    }

    # --- Parse form parameters ---
    my %FORM = Cpanel::Form::parseform();

    # --- Raise rlimits if available ---
    eval {
        require Cpanel::Rlimit;
        Cpanel::Rlimit::set_rlimit_to_infinity();
    };

    # --- Load HostGuard modules with error trapping ---
    my ($config, %conf);
    my $load_error = '';

    eval {
        require HGConfig;
        require HGLogger;
        require HGBlocklist;
        require HGGeo;
        require HGSystem;
        require HGCluster;
        require HGRelay;
        # For the shared advanced-filter validator, so this page and the
        # firewall engine cannot disagree about what a valid filter is.
        require HGFirewall;
    };
    if ($@) {
        print "<h2>HostGuard Pro - Module Load Error</h2><pre>" . _h($@) . "</pre>";
        print "<p>Check that /usr/local/hostguard/lib/ contains HGConfig.pm and HGLogger.pm</p>";
        return;
    }

    eval {
        $config = HGConfig->loadconfig();
        %conf = $config->config();
        HGLogger->init(
            file     => $conf{LOG_FILE}  || '/var/log/hostguard/daemon.log',
            level    => $conf{LOG_LEVEL} || 1,
            max_size => $conf{LOG_MAX_SIZE} || 0,
        );
    };
    if ($@) {
        $load_error = "Config load error: $@";
    }

    my $action   = $FORM{action}  || 'dashboard';
    my $do       = $FORM{do}      || '';

    # --- Rate limiting for POST actions ---
    my $RATE_FILE = ($HGConfig::DATA_DIR || '/var/lib/hostguard') . '/whm_ratelimit';

    # --- Process POST actions ---
    my $message  = '';
    my $msg_type = 'info';

    if ($ENV{REQUEST_METHOD} && $ENV{REQUEST_METHOD} eq 'POST' && $do) {
        if (!_csrf_ok($FORM{hg_token})) {
            $message  = "Request rejected: invalid or missing security token. "
                      . "Reload the page and try again.";
            $msg_type = 'danger';
        } elsif (!_check_rate_limit($RATE_FILE, $do)) {
            $message = "Rate limited. Please wait a few seconds between actions.";
            $msg_type = 'warning';
        } elsif ($load_error) {
            $message = "Cannot perform actions: $load_error";
            $msg_type = 'danger';
        } else {
            ($message, $msg_type) = _process_post_action($do, \%FORM, \%conf, \$action);
            # Refresh config after actions
            eval {
                $config = HGConfig->loadconfig();
                %conf = $config->config();
            };
        }
    }

    # --- Render page ---
    _print_html_header($action);
    _print_nav($action, \%conf);

    if ($load_error) {
        print qq(<div class="alert alert-danger">) . _h($load_error) . qq(</div>\n);
    }
    if ($message) {
        print qq(<div class="alert alert-$msg_type">) . _h($message) . qq(</div>\n);
    }

    # Route to page
    if    ($action eq 'dashboard')      { _page_dashboard(\%conf, \%FORM); }
    elsif ($action eq 'config')         { _page_config(\%conf); }
    elsif ($action eq 'allowlist')      { _page_list('allow', \%conf); }
    elsif ($action eq 'denylist')       { _page_list('deny', \%conf); }
    elsif ($action eq 'ignorelist')     { _page_list('ignore', \%conf); }
    elsif ($action eq 'tempblocks')     { _page_tempblocks(\%conf); }
    elsif ($action eq 'services')       { _page_services(\%conf); }
    elsif ($action eq 'blocklists')     { _page_blocklists(\%conf); }
    elsif ($action eq 'countries')      { _page_countries(\%conf); }
    elsif ($action eq 'tempallows')     { _page_tempallows(\%conf); }
    elsif ($action eq 'security')       { _page_security(\%conf); }
    elsif ($action eq 'statistics')     { _page_statistics(\%conf); }
    elsif ($action eq 'cluster')        { _page_cluster(\%conf); }
    elsif ($action eq 'logs')           { _page_logs(\%conf, \%FORM); }
    elsif ($action eq 'search_results') { _page_search_results(\%FORM); }
    else                                { _page_dashboard(\%conf, \%FORM); }

    _print_html_footer();
}

###############################################################################
# CSRF protection
#
# cpsrvd's session token guards the URL, but it does not prevent a page the
# administrator already has open from being made to POST here. Every
# state-changing action therefore carries a token tied to the current WHM
# session, checked before the action runs.
###############################################################################

my $CSRF_TOKEN;

sub _csrf_token {
    return $CSRF_TOKEN if defined $CSRF_TOKEN;

    # Keyed on a per-install secret plus the caller's WHM session, so a token
    # is valid only for the session and server that issued it.
    my $secret  = _csrf_secret();
    my $session = $ENV{SESSION_TEMP_USER} || $ENV{REMOTE_USER} || '';
    my $cptoken = $ENV{cp_security_token} || '';

    $CSRF_TOKEN = _digest_hex("$secret|$session|$cptoken");
    return $CSRF_TOKEN;
}

# A random secret, generated once and kept root-only.
sub _csrf_secret {
    my $file = ($HGConfig::DATA_DIR || '/var/lib/hostguard') . '/csrf.secret';
    if (open(my $fh, '<', $file)) {
        my $val = <$fh>;
        close($fh);
        chomp $val if defined $val;
        return $val if defined $val && length($val) >= 16;
    }

    my $secret = '';
    if (open(my $rnd, '<', '/dev/urandom')) {
        binmode($rnd);
        my $buf;
        if (read($rnd, $buf, 32)) {
            $secret = unpack('H*', $buf);
        }
        close($rnd);
    }
    unless (length $secret) {
        $secret = _digest_hex(join('|', $$, time(), rand(), $file));
    }

    # Created 0600 at open time, so the secret is never momentarily readable
    # by other users.
    if (sysopen(my $wfh, $file, O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
        flock($wfh, LOCK_EX);
        print $wfh $secret;
        close($wfh);
        chmod(0600, $file);
    }
    return $secret;
}

# Digest::SHA is core Perl and present on cPanel servers. The inline fallback
# keeps token generation working if it is ever unavailable.
sub _digest_hex {
    my ($data) = @_;
    my $hex = eval {
        require Digest::SHA;
        Digest::SHA::sha256_hex($data);
    };
    return $hex if defined $hex && length $hex;

    my $h1 = 0x1505;
    my $h2 = 0x7fed;
    for my $c (unpack('C*', $data)) {
        $h1 = (($h1 * 33) ^ $c) & 0xFFFFFFFF;
        $h2 = (($h2 * 31) + $c) & 0xFFFFFFFF;
    }
    return sprintf('%08x%08x', $h1, $h2);
}

# Constant-time comparison, so a token cannot be recovered byte by byte from
# the time a rejection takes.
sub _csrf_ok {
    my ($given) = @_;
    return 0 unless defined $given;
    my $want = _csrf_token();
    return 0 unless length($given) == length($want);
    my $diff = 0;
    for my $i (0 .. length($want) - 1) {
        $diff |= ord(substr($given, $i, 1)) ^ ord(substr($want, $i, 1));
    }
    return $diff == 0 ? 1 : 0;
}

# The hidden field every state-changing form must carry.
sub _csrf_field {
    return '<input type="hidden" name="hg_token" value="' . _h(_csrf_token()) . '">';
}

###############################################################################
# POST Action Processor
###############################################################################
sub _process_post_action {
    my ($post_action, $FORM, $conf, $action_ref) = @_;
    my ($msg, $type) = ('', 'info');

    if ($post_action eq 'firewall_start') {
        ($msg, $type) = _cli_action("Firewall started.", '-e');

    } elsif ($post_action eq 'firewall_stop') {
        ($msg, $type) = _cli_action("Firewall stopped.", '-x');

    } elsif ($post_action eq 'firewall_reload') {
        ($msg, $type) = _cli_action("Firewall rules reloaded.", '-r');

    # These go through the CLI rather than calling systemctl here, so the same
    # decision about which mechanism owns the daemon is made in one place. The
    # CLI reports what it actually did; repeat that rather than assuming.
    } elsif ($post_action eq 'daemon_start') {
        ($msg, $type) = _cli_action("Daemon started.", '--start-daemon');

    } elsif ($post_action eq 'daemon_stop') {
        ($msg, $type) = _cli_action("Daemon stopped.", '--stop-daemon');

    } elsif ($post_action eq 'daemon_restart') {
        ($msg, $type) = _cli_action("Daemon restarted.", '--restart-daemon');

    } elsif ($post_action eq 'save_config') {
        my $cfg_text = $FORM->{config_text} || '';
        if ($conf->{RESTRICT_UI} && $conf->{RESTRICT_UI} ne "0") {
            $msg = "UI config changes are restricted. Change via SSH.";
            $type = 'danger';
        } else {
            my $file = "$HGConfig::CONFIG_DIR/hostguard.conf";

            # Under the same lock HGConfig->set() takes. This form replaces
            # the whole file from a textarea, so without it a save landing
            # between another process reading the file and writing it back
            # discards everything that process had changed - and the reverse,
            # which is worse: 'hostguard --preset' setting twenty keys one at
            # a time can drop this entire save while the page reports it
            # succeeded.
            my $lock;
            eval {
                $lock = HGConfig->get_lock_wait('config', 15);
                _backup_file($file);
                _save_file($file, $cfg_text);
                1;
            };
            my $save_err = $@;
            close($lock) if $lock;
            $@ = $save_err;
            if ($@) {
                $msg = "Error saving config: $@"; $type = 'danger';
            } else {
                _audit("replaced hostguard.conf");
                $msg  = "Configuration saved; the previous version is in "
                      . "hostguard.conf.bak. Reload the firewall to apply.";
                $type = 'success';
            }
        }

    } elsif ($post_action eq 'save_list') {
        my $list_name = $FORM->{list_name} || '';
        my $list_text = $FORM->{list_text} || '';

        if ($list_name !~ /^(allow|deny|ignore)$/) {
            $msg = "Invalid list name."; $type = 'danger';

        # These files are firewall policy: the allowlist decides who bypasses
        # every block, and an advanced filter in it opens a port. RESTRICT_UI
        # reads as "the browser may not change the firewall", so it has to
        # cover them as well as hostguard.conf.
        } elsif ($conf->{RESTRICT_UI} && $conf->{RESTRICT_UI} ne "0") {
            $msg = "UI policy changes are restricted (RESTRICT_UI=1). Edit "
                 . "${list_name}.conf over SSH, or use the quick-add field "
                 . "above, which validates a single address.";
            $type = 'danger';

        } else {
            # Every line is checked before anything is written. The quick-add
            # path validates a single address, and editing the whole file in a
            # textarea has to validate too - otherwise a paste error becomes
            # firewall policy.
            my @errors = _validate_list_text($list_text);
            if (@errors) {
                $msg  = "Not saved. " . scalar(@errors) . " line(s) rejected: "
                      . join('; ', @errors[0 .. ($#errors > 4 ? 4 : $#errors)])
                      . ($#errors > 4 ? ' ...' : '');
                $type = 'danger';
            } else {
                my $file = "$HGConfig::CONFIG_DIR/${list_name}.conf";
                eval {
                    _backup_file($file);
                    _save_file($file, $list_text);
                };
                if ($@) {
                    $msg = "Error: $@"; $type = 'danger';
                } else {
                    _audit("replaced ${list_name}.conf ("
                         . scalar(split(/\n/, $list_text)) . " lines)");
                    $msg  = ucfirst($list_name) . " list saved; the previous "
                          . "version is in ${list_name}.conf.bak. Reload to apply.";
                    $type = 'success';
                }
            }
        }

    } elsif ($post_action eq 'quick_allow') {
        my $ip = _sanitize_ip($FORM->{ip} || '');
        my $comment = _sanitize_comment($FORM->{comment} || 'WHM allow');
        if ($ip) {
            ($msg, $type) = _cli_action("IP $ip added to the allowlist.",
                                        '-a', $ip, $comment);
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }

    } elsif ($post_action eq 'quick_deny') {
        my $ip = _sanitize_ip($FORM->{ip} || '');
        my $comment = _sanitize_comment($FORM->{comment} || 'WHM deny');
        if ($ip) {
            ($msg, $type) = _cli_action("IP $ip added to the denylist.",
                                        '-d', $ip, $comment);
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }

    } elsif ($post_action eq 'quick_ignore') {
        # ignore.conf is consulted afresh on every block decision, so an
        # appended entry takes effect immediately and needs no reload.
        my $ip = _sanitize_ip($FORM->{ip} || '');
        my $comment = _sanitize_comment($FORM->{comment} || 'WHM ignore');
        if ($ip) {
            eval { _append_list_entry("$HGConfig::CONFIG_DIR/ignore.conf", $ip, $comment); };
            $msg  = $@ ? "Error: $@" : "IP $ip added to ignore list.";
            $type = $@ ? 'danger' : 'success';
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }

    } elsif ($post_action eq 'update_blocklists') {
        ($msg, $type) = _cli_action("Block list update finished.", '-b');

    } elsif ($post_action eq 'force_blocklists') {
        ($msg, $type) = _cli_action("Block list update finished.", '-b', 'force');

    } elsif ($post_action eq 'update_countries') {
        ($msg, $type) = _cli_action("Country zone update finished.", '-c');

    } elsif ($post_action eq 'force_countries') {
        ($msg, $type) = _cli_action("Country zone update finished.", '-c', 'force');

    } elsif ($post_action eq 'temp_allow') {
        my $ip      = _sanitize_ip($FORM->{ip} || '');
        my $seconds = $FORM->{seconds} || '3600';
        my $comment = _sanitize_comment($FORM->{comment} || 'Added from WHM');
        $seconds = 3600 unless $seconds =~ /^\d+$/ && $seconds > 0 && $seconds <= 31536000;
        if ($ip) {
            ($msg, $type) = _cli_action("Temporary allow added for $ip.",
                                        '-ta', $ip, $seconds, $comment);
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }

    } elsif ($post_action eq 'temp_allow_remove') {
        my $ip = _sanitize_ip($FORM->{ip} || '');
        if ($ip) {
            ($msg, $type) = _cli_action("Temporary allow removed for $ip.",
                                        '-tar', $ip);
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }

    } elsif ($post_action eq 'cluster_ping') {
        ($msg, $type) = _cli_action("Cluster ping sent.", '--cluster', 'ping');

    } elsif ($post_action eq 'integrity_reset') {
        ($msg, $type) = _cli_action("Integrity baseline cleared.",
                                    '--integrity-reset');

    } elsif ($post_action eq 'unblock') {
        my $ip = _sanitize_ip($FORM->{ip} || '');
        if ($ip) {
            ($msg, $type) = _cli_action("Temporary block removed for $ip.",
                                        '-tr', $ip);
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }

    } elsif ($post_action eq 'search_ip') {
        my $ip = _sanitize_ip($FORM->{ip} || '');
        if ($ip) {
            $$action_ref = 'search_results';
        } else {
            $msg = "Invalid IP address."; $type = 'danger';
        }
    }

    return ($msg, $type);
}

# Run CLI command safely (list-form exec, no shell interpolation)
# Run the CLI and return (exit code, output).
#
# The exit code is returned, and the caller has to use it. The CLI reports
# failure honestly - adding an allow that never reached the running firewall
# exits non-zero and says why - so discarding the status here would turn every
# one of those into a green "added" in the browser.
sub _run_cli {
    my @args = @_;
    my $cmd = '/usr/local/hostguard/bin/hostguard';
    return (-1, "$cmd is not executable") unless -x $cmd;

    my $pid = open(my $fh, '-|');
    return (-1, "Failed to fork: $!") unless defined $pid;

    if ($pid == 0) {
        open(STDERR, '>&STDOUT');
        exec($cmd, @args) or exit(127);
    }

    my $output = do { local $/; <$fh> };

    # close() on a '-|' pipe reaps the child and sets $?. Reading it any later,
    # or calling waitpid as well, would report the failure of that call rather
    # than the exit status of the command.
    close($fh);
    my $rc = ($? == -1) ? -1 : ($? >> 8);

    return ($rc, defined $output ? $output : '');
}

# Run a CLI command and turn its outcome into a message and a banner type.
#
# One place decides what success and failure look like, so a handler cannot
# forget to check. The CLI's own output is shown either way: it explains what
# it did, and on failure it names what to do about it.
sub _cli_action {
    my ($ok_msg, @args) = @_;

    my ($rc, $out) = _run_cli(@args);
    my $detail = _summarise_cli($out);

    if ($rc == 0) {
        return (length $detail ? "$ok_msg $detail" : $ok_msg, 'success');
    }

    return (length $detail ? $detail
                           : "The command failed (exit $rc). See the daemon log.",
            'danger');
}

###############################################################################
# Page: Dashboard
###############################################################################
sub _page_dashboard {
    my ($conf, $FORM) = @_;
    my $fw_status = _check_fw_status();
    my $daemon_pid = _get_daemon_pid();
    my $daemon_running = $daemon_pid && kill(0, $daemon_pid);

    my @allow  = _safe_load_iplist("$HGConfig::CONFIG_DIR/allow.conf");
    my @deny   = _safe_load_iplist("$HGConfig::CONFIG_DIR/deny.conf");
    my @blocks = _load_tempblocks();
    my @active = grep { $_->{active} } @blocks;
    my @recent_log = _tail_log($conf, 10);

    my $fw_html = $fw_status->{running}
        ? '<span class="status-on">ACTIVE</span>'
        : '<span class="status-off">INACTIVE</span>';
    my $fw_since = $fw_status->{since} ? scalar(localtime($fw_status->{since})) : 'N/A';
    my $dm_html = $daemon_running
        ? '<span class="status-on">RUNNING</span>'
        : '<span class="status-off">STOPPED</span>';
    # Two standing conditions the dashboard has to show, because neither
    # produces a symptom until it is too late: an auto-clear cron still armed
    # after TESTING was turned off, and deny.conf entries the limit is
    # discarding.
    my @standing;
    if (-e '/etc/cron.d/hostguard_testing' && ($conf->{TESTING} || '0') ne '1') {
        push @standing, 'TESTING is 0 but /etc/cron.d/hostguard_testing is '
                      . 'still installed, so the firewall will be torn down on '
                      . 'its schedule. Reload the firewall to remove it.';
    }
    {
        my $limit = $conf->{DENY_IP_LIMIT} || 0;
        if ($limit =~ /^\d+$/ && $limit > 0) {
            my @deny = HGConfig->load_iplist("$HGConfig::CONFIG_DIR/deny.conf");
            my $over = scalar(@deny) - $limit;
            push @standing, "$over deny.conf entrie(s) are not being blocked "
                          . "because DENY_IP_LIMIT is $limit. They are recorded "
                          . "as permanently blocked and are not in the firewall."
                if $over > 0;
        }
    }
    for my $warn (@standing) {
        print '<p class="alert alert-danger">' . _h($warn) . '</p>';
    }

    my $testing = ($conf->{TESTING} || '0') eq '1'
        ? '<span class="status-warn">TESTING MODE</span>'
        : 'Disabled';
    my $ipv6 = ($conf->{IPV6} || '0') eq '1' ? 'Enabled' : 'Disabled';
    # Escaped like every other value that reaches the page. This one was the
    # exception among 58 output sites, and while the actor who could put markup
    # in LF_SSHD is root, an exception is the thing that survives an ACL change.
    my $ssh_thresh = _h($conf->{LF_SSHD} || '5');
    my $block_dur = _format_duration($conf->{LF_TEMP_BLOCK_DURATION} || 3600);
    my $dm_pid_display = $daemon_running ? $daemon_pid : 'N/A';
    my $allow_count = scalar @allow;
    my $deny_count  = scalar @deny;
    my $active_count = scalar @active;

    # The headline numbers lead, because the questions an administrator opens
    # this page to answer are "is it running" and "how much is it holding".
    # The detail that qualifies each one sits under it rather than beside it.
    my $fw_word    = $fw_status->{running} ? 'Active'  : 'Inactive';
    my $fw_cls     = $fw_status->{running} ? 'ok'      : 'bad';
    my $dm_word    = $daemon_running       ? 'Running' : 'Stopped';
    my $dm_cls     = $daemon_running       ? 'ok'      : 'bad';
    my $dm_sub     = $daemon_running ? "PID $daemon_pid" : 'Not running';
    my $fw_sub     = $fw_status->{running} ? "Since $fw_since" : 'No rules loaded';

    print <<HTML;
<h2>Dashboard</h2>
<p>Firewall, daemon and current blocking activity on this server.</p>

<div class="stats" style="margin-bottom:16px;">
  <div class="stat">
    <div class="stat-label">Firewall</div>
    <div class="stat-value $fw_cls">$fw_word</div>
    <div class="stat-sub">$fw_sub</div>
  </div>
  <div class="stat">
    <div class="stat-label">Daemon</div>
    <div class="stat-value $dm_cls">$dm_word</div>
    <div class="stat-sub">$dm_sub</div>
  </div>
  <div class="stat">
    <div class="stat-label">Temporary Blocks</div>
    <div class="stat-value">$active_count</div>
    <div class="stat-sub">Currently held</div>
  </div>
  <div class="stat">
    <div class="stat-label">Allowlist</div>
    <div class="stat-value">$allow_count</div>
    <div class="stat-sub">Entries</div>
  </div>
  <div class="stat">
    <div class="stat-label">Denylist</div>
    <div class="stat-value">$deny_count</div>
    <div class="stat-sub">Permanent blocks</div>
  </div>
</div>

<div class="grid">
  <div class="card">
    <h3>Firewall</h3>
    <table class="info-table">
      <tr><td>Status</td><td>$fw_html</td></tr>
      <tr><td>Since</td><td>$fw_since</td></tr>
      <tr><td>Testing</td><td>$testing</td></tr>
      <tr><td>IPv6</td><td>$ipv6</td></tr>
    </table>
  </div>
  <div class="card">
    <h3>Login Failure Daemon</h3>
    <table class="info-table">
      <tr><td>Status</td><td>$dm_html</td></tr>
      <tr><td>PID</td><td>$dm_pid_display</td></tr>
      <tr><td>SSH threshold</td><td>$ssh_thresh failures</td></tr>
      <tr><td>Block duration</td><td>$block_dur</td></tr>
    </table>
  </div>
  <div class="card">
    <h3>IP Lists</h3>
    <table class="info-table">
      <tr><td>Allowlist</td><td>$allow_count entries</td></tr>
      <tr><td>Denylist</td><td>$deny_count entries</td></tr>
      <tr><td>Temp blocks</td><td>$active_count active</td></tr>
    </table>
  </div>
</div>

<div class="card">
  <h3>Quick Actions</h3>
  <form method="post" class="inline-form">
    ${\ _csrf_field() }
    <input type="hidden" name="action" value="dashboard">
    <label>IP: <input type="text" name="ip" size="20" required></label>
    <label>Note: <input type="text" name="comment" size="20"></label>
    <button type="submit" name="do" value="quick_allow" class="btn btn-success">Allow</button>
    <button type="submit" name="do" value="quick_deny" class="btn btn-danger">Deny</button>
    <button type="submit" name="do" value="search_ip" class="btn btn-info">Search</button>
  </form>
</div>

<div class="card">
  <h3>Recent Blocks</h3>
HTML

    if (@active) {
        print '<table class="data-table"><tr><th>IP</th><th>Expires</th><th>TTL</th><th>Reason</th><th>Action</th></tr>';
        my $count = 0;
        for my $b (sort { $b->{expires} <=> $a->{expires} } @active) {
            last if ++$count > 10;
            my $exp = strftime("%Y-%m-%d %H:%M", localtime($b->{expires}));
            my $ttl = _format_duration($b->{ttl});
            my $eip = _h($b->{ip});
            my $erea = _h($b->{reason});
            print qq(<tr><td>$eip</td><td>$exp</td><td>$ttl</td><td>$erea</td>);
            print qq(<td><form method="post" style="display:inline">) . _csrf_field() . qq(<input type="hidden" name="action" value="dashboard"><input type="hidden" name="ip" value="$eip"><button type="submit" name="do" value="unblock" class="btn btn-sm">Unblock</button></form></td></tr>\n);
        }
        print '</table>';
    } else {
        print '<p>No active temporary blocks.</p>';
    }

    print <<HTML;
</div>
<div class="card">
  <h3>Recent Log Entries</h3>
  <pre class="log-box">
HTML
    for my $line (@recent_log) {
        print _h($line) . "\n";
    }
    print "</pre>\n</div>\n";
}

###############################################################################
# Page: Config Editor
###############################################################################
sub _page_config {
    my ($conf) = @_;
    my $cfg_file = "$HGConfig::CONFIG_DIR/hostguard.conf";
    my $content = _read_file($cfg_file);

    unless (defined $content) {
        print "<p class='alert alert-danger'>Cannot read config file: $cfg_file</p>";
        return;
    }

    my $readonly = ($conf->{RESTRICT_UI} && $conf->{RESTRICT_UI} ne "0") ? 'readonly' : '';
    my $disabled = $readonly ? 'disabled' : '';
    my $escaped = _h($content);

    print <<HTML;
<h2>Firewall Configuration</h2>
<div class="card">
  <p>Edit <code>/etc/hostguard/hostguard.conf</code>. After saving, reload the firewall to apply changes.</p>
HTML
    if ($readonly) {
        my $rval = _h($conf->{RESTRICT_UI});
        print qq(<p class="alert alert-warning">Config editing is restricted (RESTRICT_UI=$rval). Change this setting via SSH.</p>\n);
    }
    print <<HTML;
  <form method="post">
    ${\ _csrf_field() }
    <input type="hidden" name="action" value="config">
    <textarea name="config_text" rows="35" cols="100" class="code-editor" $readonly>$escaped</textarea>
    <br>
    <button type="submit" name="do" value="save_config" class="btn btn-primary" $disabled>Save Configuration</button>
    <button type="submit" name="do" value="firewall_reload" class="btn btn-warning">Reload Firewall</button>
  </form>
</div>
HTML
}

###############################################################################
# Page: IP List Editor (allow/deny/ignore)
###############################################################################
sub _page_list {
    my ($list_name, $conf) = @_;
    my $file = "$HGConfig::CONFIG_DIR/${list_name}.conf";
    my $display_name = ucfirst($list_name) . "list";

    my $content = _read_file($file);
    unless (defined $content) {
        print "<p class='alert alert-danger'>Cannot read $file</p>";
        return;
    }
    my $escaped = _h($content);
    my $ucname = ucfirst($list_name);

    # Each list has its own quick-add action, so the button on a page always
    # writes to the list that page is editing.
    my %quick_action = (
        allow  => 'quick_allow',
        deny   => 'quick_deny',
        ignore => 'quick_ignore',
    );
    my $quick_do = $quick_action{$list_name} || 'quick_allow';

    # These files are firewall policy, so the bulk editor answers to
    # RESTRICT_UI exactly as the configuration editor does. Quick-add stays
    # available either way: it takes one address and validates it.
    my $restricted = ($conf->{RESTRICT_UI} && $conf->{RESTRICT_UI} ne "0") ? 1 : 0;
    my $readonly   = $restricted ? 'readonly' : '';
    my $disabled   = $restricted ? 'disabled' : '';

    print <<HTML;
<h2>$display_name Editor</h2>
<div class="card">
  <p>Edit <code>$file</code>. One IP/CIDR per line, with an optional <code>#</code> comment.</p>
HTML

    if ($restricted) {
        my $rval = _h($conf->{RESTRICT_UI});
        print qq(<p class="alert alert-warning">Bulk editing is restricted )
            . qq((RESTRICT_UI=$rval), because this file decides what the )
            . qq(firewall permits. Quick Add below still works and validates )
            . qq(the address. To replace the whole file, edit it over SSH.</p>
);
    }

    print <<HTML;

  <form method="post" class="inline-form" style="margin-bottom:10px;">
    ${\ _csrf_field() }
    <input type="hidden" name="action" value="${list_name}list">
    <label>Quick Add IP: <input type="text" name="ip" size="20"></label>
    <label>Comment: <input type="text" name="comment" size="20"></label>
    <button type="submit" name="do" value="$quick_do" class="btn btn-primary">Add to $ucname</button>
  </form>

  <form method="post">
    ${\ _csrf_field() }
    <input type="hidden" name="action" value="${list_name}list">
    <input type="hidden" name="list_name" value="$list_name">
    <textarea name="list_text" rows="25" cols="100" class="code-editor" $readonly>$escaped</textarea>
    <br>
    <button type="submit" name="do" value="save_list" class="btn btn-primary" $disabled>Save $display_name</button>
    <button type="submit" name="do" value="firewall_reload" class="btn btn-warning">Reload Firewall</button>
  </form>
</div>
HTML
}

###############################################################################
# Page: Temporary Blocks
###############################################################################
sub _page_tempblocks {
    my ($conf) = @_;
    my @blocks = _load_tempblocks();
    my @active = grep { $_->{active} } @blocks;
    my $active_count = scalar @active;

    print <<HTML;
<h2>Temporary Blocks</h2>
<div class="card">
  <p>Currently active temporary blocks. These expire automatically after their TTL.</p>
HTML

    if (@active) {
        print '<table class="data-table">';
        print '<tr><th>IP Address</th><th>Expires</th><th>TTL</th><th>Reason</th><th>Action</th></tr>';
        for my $b (sort { $a->{expires} <=> $b->{expires} } @active) {
            my $exp = strftime("%Y-%m-%d %H:%M:%S", localtime($b->{expires}));
            my $ttl = _format_duration($b->{ttl});
            my $eip = _h($b->{ip});
            my $erea = _h($b->{reason});
            print <<HTML;
    <tr>
      <td>$eip</td><td>$exp</td><td>$ttl</td><td>$erea</td>
      <td>
        <form method="post" style="display:inline">
          ${\ _csrf_field() }
          <input type="hidden" name="action" value="tempblocks">
          <input type="hidden" name="ip" value="$eip">
          <button type="submit" name="do" value="unblock" class="btn btn-sm btn-danger">Unblock</button>
          <button type="submit" name="do" value="quick_allow" class="btn btn-sm btn-success">Allow</button>
        </form>
      </td>
    </tr>
HTML
        }
        print "</table>\n";
        print "<p>Total active blocks: $active_count</p>\n";
    } else {
        print "<p>No active temporary blocks.</p>\n";
    }
    print "</div>\n";
}

###############################################################################
# Page: Service Controls
###############################################################################
sub _page_services {
    my ($conf) = @_;
    my $fw_status = _check_fw_status();
    my $daemon_pid = _get_daemon_pid();
    my $daemon_running = $daemon_pid && kill(0, $daemon_pid);

    my $fw_html = $fw_status->{running}
        ? '<span class="status-on">ACTIVE</span>'
        : '<span class="status-off">INACTIVE</span>';
    my $dm_html = $daemon_running
        ? "<span class='status-on'>RUNNING (PID $daemon_pid)</span>"
        : '<span class="status-off">STOPPED</span>';

    print <<HTML;
<h2>Service Controls</h2>
<div class="grid">
  <div class="card">
    <h3>Firewall</h3>
    <p>Status: $fw_html</p>
    <form method="post">
      ${\ _csrf_field() }
      <input type="hidden" name="action" value="services">
      <button type="submit" name="do" value="firewall_start" class="btn btn-success">Start</button>
      <button type="submit" name="do" value="firewall_stop" class="btn btn-danger">Stop</button>
      <button type="submit" name="do" value="firewall_reload" class="btn btn-warning">Reload Rules</button>
    </form>
  </div>
  <div class="card">
    <h3>Login Failure Daemon</h3>
    <p>Status: $dm_html</p>
    <form method="post">
      ${\ _csrf_field() }
      <input type="hidden" name="action" value="services">
      <button type="submit" name="do" value="daemon_start" class="btn btn-success">Start</button>
      <button type="submit" name="do" value="daemon_stop" class="btn btn-danger">Stop</button>
      <button type="submit" name="do" value="daemon_restart" class="btn btn-warning">Restart</button>
    </form>
  </div>
</div>
HTML
}

###############################################################################
# Page: External Block Lists
###############################################################################
sub _page_blocklists {
    my ($conf) = @_;

    my $enabled = (!defined $conf->{BLOCKLIST_ENABLE} || $conf->{BLOCKLIST_ENABLE} ne "0");
    my @lists = eval { HGBlocklist->load() };
    my $load_err = $@;

    print <<HTML;
<h2>External Block Lists</h2>
<div class="card">
  <p>Lists are defined in <code>/etc/hostguard/blocklists.conf</code>. Each one
     is downloaded on its own schedule and matched below the allowlist, so an
     allowed address is never blocked by a list.</p>
HTML

    if ($load_err) {
        print qq(<p class="alert alert-danger">Cannot read block lists: ) . _h($load_err) . qq(</p>\n);
        print "</div>\n";
        return;
    }

    unless ($enabled) {
        print qq(<p class="alert alert-warning">BLOCKLIST_ENABLE is 0, so no list )
            . qq(is applied to the firewall.</p>\n);
    }

    unless (@lists) {
        print "<p>No block lists are configured. Uncomment one in "
            . "<code>blocklists.conf</code> to enable it.</p>\n</div>\n";
        return;
    }

    print '<table class="data-table">';
    print '<tr><th>Name</th><th>Entries</th><th>Last updated</th>'
        . '<th>Refresh</th><th>Cap</th><th>Source</th></tr>';

    for my $entry (@lists) {
        # Counted, not loaded. cached_entries builds an array per address, and
        # this page only wants a number - which on three large lists meant
        # several million scalars to print three integers, in a process that has
        # lifted its own memory limits.
        my ($v4, $v6) = HGBlocklist->cached_counts($entry->{name}, $conf);
        my $count = $v4 + $v6;
        my $age   = HGBlocklist->age($entry);
        my $when  = defined $age ? _format_duration($age) . " ago" : "never downloaded";
        my $due   = HGBlocklist->is_due($entry) ? " (due)" : "";

        printf('<tr><td>%s</td><td>%d</td><td>%s%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' . "\n",
               _h($entry->{name}),
               $count,
               _h($when),
               $due,
               _h(_format_duration($entry->{interval})),
               $entry->{max} ? $entry->{max} : 'all',
               _h($entry->{url}));
    }
    print "</table>\n";

    print <<HTML;
  <form method="post" style="margin-top:12px;">
    ${\ _csrf_field() }
    <input type="hidden" name="action" value="blocklists">
    <button type="submit" name="do" value="update_blocklists" class="btn btn-primary">Update lists that are due</button>
    <button type="submit" name="do" value="force_blocklists" class="btn btn-warning">Re-download every list</button>
  </form>
  <p style="margin-top:10px; color:#666;">Downloading runs while this page
     loads, so re-downloading several large lists can take a while. The daemon
     also refreshes lists on their own schedule without any action here.</p>
</div>
HTML
}

###############################################################################
# Page: Country Filtering
###############################################################################
sub _page_countries {
    my ($conf) = @_;

    my ($mode, @codes) = eval { HGGeo->mode($conf) };
    my $err = $@;
    $mode = '' unless defined $mode;

    print <<HTML;
<h2>Country Filtering</h2>
<div class="card">
  <p>Allows or denies traffic by the country an address is registered to,
     using published zone files cached under
     <code>/var/lib/hostguard/geo/</code>. Configured with
     <code>GEO_ENABLE</code>, <code>GEO_DENY</code> and <code>GEO_ALLOW</code>
     in <code>hostguard.conf</code>.</p>
HTML

    if ($err) {
        print qq(<p class="alert alert-danger">Cannot read the country settings: )
            . _h($err) . qq(</p>\n</div>\n);
        return;
    }

    unless ($mode) {
        print qq(<p class="alert alert-warning">Country filtering is off. Set )
            . qq(<code>GEO_ENABLE=1</code> and list ISO country codes in )
            . qq(<code>GEO_DENY</code> or <code>GEO_ALLOW</code>.</p>\n</div>\n);
        return;
    }

    if ($mode eq 'allow') {
        print qq(<p class="alert alert-warning"><strong>Allow mode.</strong> )
            . qq(Everything the zone files do not account for is dropped, )
            . qq(including addresses reassigned since publication. Your )
            . qq(allowlist still wins, and HostGuard Pro refuses to apply )
            . qq(allow mode if the zone files are empty.</p>\n);
    }

    unless (@codes) {
        print "<p>No country codes are configured.</p>\n</div>\n";
        return;
    }

    print "<p>Mode: <strong>" . uc(_h($mode)) . "</strong></p>\n";
    print '<table class="data-table">';
    print '<tr><th>Country</th><th>IPv4 ranges</th><th>IPv6 ranges</th>'
        . '<th>Last updated</th></tr>';

    for my $cc (@codes) {
        # Counted, not loaded, for the same reason as the block list page. A
        # large country's zone file holds hundreds of thousands of ranges.
        my $v4 = HGGeo->cached_count($cc, 'inet', $conf)  // 0;
        my $v6 = HGGeo->cached_count($cc, 'inet6', $conf) // 0;
        my $age = HGGeo->age($cc, 'inet');
        my $when = defined $age ? _format_duration($age) . " ago" : "never downloaded";
        my $due  = HGGeo->is_due($cc, $conf, 'inet') ? " (due)" : "";

        printf('<tr><td>%s</td><td>%d</td><td>%d</td><td>%s%s</td></tr>' . "\n",
               _h($cc), $v4, $v6, _h($when), $due);
    }
    print "</table>\n";

    print <<HTML;
  <form method="post" style="margin-top:12px;">
    ${\ _csrf_field() }
    <input type="hidden" name="action" value="countries">
    <button type="submit" name="do" value="update_countries" class="btn btn-primary">Update zones that are due</button>
    <button type="submit" name="do" value="force_countries" class="btn btn-warning">Re-download every zone</button>
  </form>
  <p style="margin-top:10px; color:#666;">Zone files are large, so a full
     re-download can take a while. After the first download, reload the
     firewall from the Services page to build the matching rules.</p>
</div>
HTML
}

###############################################################################
# Page: Temporary Allows
###############################################################################
sub _page_tempallows {
    my ($conf) = @_;

    my @allows = _load_tempallows();

    print <<HTML;
<h2>Temporary Allows</h2>
<div class="card">
  <p>An address allowed for a bounded period. It expires on its own and
     <code>allow.conf</code> is never touched, which suits a dynamic address
     or access needed for an afternoon.</p>

  <form method="post" class="inline-form">
    ${\ _csrf_field() }
    <input type="hidden" name="action" value="tempallows">
    <input type="text" name="ip" placeholder="IP address" required>
    <input type="text" name="seconds" placeholder="Seconds (3600)" size="14">
    <input type="text" name="comment" placeholder="Comment" size="24">
    <button type="submit" name="do" value="temp_allow" class="btn btn-primary">Add temporary allow</button>
  </form>
HTML

    unless (@allows) {
        print "<p style='margin-top:12px;'>No active temporary allows.</p>\n</div>\n";
        return;
    }

    print '<table class="data-table" style="margin-top:12px;">';
    print '<tr><th>IP Address</th><th>Expires</th><th>Remaining</th>'
        . '<th>Comment</th><th></th></tr>';

    for my $a (sort { $a->{expires} <=> $b->{expires} } @allows) {
        my $eip = _h($a->{ip});
        printf('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>',
               $eip,
               _h(scalar(localtime($a->{expires}))),
               _h(_format_duration($a->{ttl})),
               _h($a->{note}));
        print qq(<td><form method="post" style="display:inline">)
            . _csrf_field()
            . qq(<input type="hidden" name="action" value="tempallows">)
            . qq(<input type="hidden" name="ip" value="$eip">)
            . qq(<button type="submit" name="do" value="temp_allow_remove" class="btn btn-sm">Remove</button>)
            . qq(</form></td></tr>\n);
    }
    print "</table>\n";
    print "<p style='margin-top:10px;'>" . scalar(@allows) . " active.</p>\n";
    print "</div>\n";
}

###############################################################################
# Page: Security Check
###############################################################################
sub _page_security {
    my ($conf) = @_;

    my @findings = eval { HGSystem->security_check($conf) };
    my $err = $@;

    print <<HTML;
<h2>Security Check</h2>
<div class="card">
  <p>A review of the settings that decide how exposed this host is. Every
     finding names where the setting lives, so you can weigh it against how
     the server is actually used.</p>
  <p><strong>Nothing here changes anything.</strong> A finding is a question
     worth answering, not a fault, and some will be correct for your host.</p>
HTML

    if ($err) {
        print qq(<p class="alert alert-danger">The check could not run: )
            . _h($err) . qq(</p>\n</div>\n);
        return;
    }

    unless (@findings) {
        print qq(<p class="alert alert-success">No findings. Every setting )
            . qq(reviewed looks reasonable.</p>\n</div>\n);
        return;
    }

    my %order  = (high => 0, medium => 1, low => 2);
    my %colour = (high => '#ef4444', medium => '#d68910', low => '#7f8c8d');

    my $high   = grep { $_->{level} eq 'high' }   @findings;
    my $medium = grep { $_->{level} eq 'medium' } @findings;
    my $low    = grep { $_->{level} eq 'low' }    @findings;

    print "<p style='margin-top:12px;'><strong>$high</strong> high, "
        . "<strong>$medium</strong> medium, <strong>$low</strong> low.</p>\n";

    print '<table class="data-table" style="margin-top:12px;">';
    print '<tr><th>Level</th><th>Finding</th><th>Setting</th></tr>';

    for my $f (sort { $order{$a->{level}} <=> $order{$b->{level}} } @findings) {
        my $c = $colour{ $f->{level} } || '#7f8c8d';
        printf('<tr><td><span style="color:%s;font-weight:600">%s</span></td>'
             . '<td><strong>%s</strong><br><span style="color:#666">%s</span></td>'
             . '<td><code>%s</code></td></tr>' . "\n",
               $c, uc(_h($f->{level})), _h($f->{title}), _h($f->{detail}),
               _h($f->{where}));
    }
    print "</table>\n";

    print <<HTML;
  <form method="post" style="margin-top:12px;">
    ${\ _csrf_field() }
    <input type="hidden" name="action" value="security">
    <button type="submit" name="do" value="integrity_reset" class="btn btn-warning">Reset integrity baseline</button>
  </form>
  <p style="margin-top:10px; color:#666;">Reset the baseline after a
     deliberate package update, so the next check starts from the new state.
     Do not use it to silence a report you have not explained.</p>
</div>
HTML
}

###############################################################################
# Page: System Statistics
###############################################################################
sub _page_statistics {
    my ($conf) = @_;

    my @rows = eval { HGSystem->statistics(360) };
    my $err = $@;

    print <<HTML;
<h2>System Statistics</h2>
<div class="card">
  <p>Load, memory, processes and active blocks, sampled once a minute while
     <code>STATS_ENABLE</code> is on.</p>
HTML

    if ($err) {
        print qq(<p class="alert alert-danger">Cannot read the samples: )
            . _h($err) . qq(</p>\n</div>\n);
        return;
    }
    unless (@rows) {
        print qq(<p class="alert alert-warning">No samples recorded yet. The )
            . qq(daemon writes one a minute; check that it is running and that )
            . qq(<code>STATS_ENABLE=1</code>.</p>\n</div>\n);
        return;
    }

    my $latest = $rows[-1];
    my $mem_pct = $latest->{mem_total}
                ? int(($latest->{mem_used} / $latest->{mem_total}) * 100) : 0;

    print '<table class="data-table" style="margin-bottom:16px;">';
    print '<tr><th>Load (1m)</th><th>Load (5m)</th><th>Load (15m)</th>'
        . '<th>CPU</th><th>Memory used</th><th>Processes</th>'
        . '<th>Active blocks</th></tr>';
    printf('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
         . '<td>%s%% of %s MB</td><td>%s</td><td>%s</td></tr>' . "\n",
           _h($latest->{load1}), _h($latest->{load5}), _h($latest->{load15}),
           defined $latest->{cpu} ? _h($latest->{cpu}) . '%' : 'n/a',
           $mem_pct, int($latest->{mem_total} / 1024),
           _h($latest->{procs}), _h($latest->{blocks}));
    print "</table>\n";

    # The graphs are inline SVG built from the samples. Drawing them here
    # avoids pulling a charting library into a WHM page, which would be a
    # third-party script running with an authenticated root session.
    _draw_graph('Load average (1 minute)', \@rows, sub { $_[0]->{load1} }, '#3b82f6');
    _draw_graph('Memory used (MB)', \@rows,
                sub { int(($_[0]->{mem_used} || 0) / 1024) }, '#10b981');
    _draw_graph('Processes', \@rows, sub { $_[0]->{procs} }, '#8b5cf6');
    _draw_graph('Active temporary blocks', \@rows, sub { $_[0]->{blocks} }, '#ef4444');

    my $span = $rows[-1]{time} - $rows[0]{time};
    print "<p style='margin-top:10px; color:#666;'>" . scalar(@rows)
        . " samples covering " . _h(_format_duration($span)) . ".</p>\n";
    print "</div>\n";
}

# Draw one series as an inline SVG line graph.
#
# Scaled to the highest value in the series, with a floor of 1 so a series
# that is entirely zero renders a flat line rather than dividing by zero.
sub _draw_graph {
    my ($title, $rows, $extract, $colour) = @_;

    my @values = map { my $v = $extract->($_); defined $v ? $v : 0 } @$rows;
    return unless @values;

    my $max = 0;
    for my $v (@values) { $max = $v if $v > $max; }
    $max = 1 if $max <= 0;

    my ($w, $h, $pad) = (900, 120, 4);
    my $step = @values > 1 ? ($w / (@values - 1)) : $w;

    my @points;
    for my $i (0 .. $#values) {
        my $x = sprintf('%.1f', $i * $step);
        my $y = sprintf('%.1f', $h - $pad - (($values[$i] / $max) * ($h - 2 * $pad)));
        push @points, "$x,$y";
    }
    my $line = join(' ', @points);
    # Close the path along the baseline so the area under the line can be
    # filled without a second point list.
    my $area = "0,$h " . $line . " " . sprintf('%.1f', $#values * $step) . ",$h";

    print qq{<div style="margin-bottom:18px;">\n};
    print qq{<div style="font-weight:600; margin-bottom:4px;">}
        . _h($title)
        . qq{ <span style="font-weight:400;color:#666">peak }
        . _h($max)
        . qq{</span></div>\n};
    print qq(<svg viewBox="0 0 $w $h" preserveAspectRatio="none" )
        . qq(style="width:100%; height:${h}px; background:var(--bg); )
        . qq(border:1px solid var(--border-sm); border-radius:10px;">\n);
    print qq(  <polygon points="$area" fill="$colour" opacity="0.12" />\n);
    print qq(  <polyline points="$line" fill="none" stroke="$colour" )
        . qq(stroke-width="1.5" vector-effect="non-scaling-stroke" />\n);
    print qq(</svg>\n</div>\n);
}

###############################################################################
# Page: Cluster
###############################################################################
sub _page_cluster {
    my ($conf) = @_;

    my $enabled = ($conf->{CLUSTER_ENABLE} // '0') eq '1';
    my @members = eval { HGCluster->members() };
    my $err     = $@;
    my ($kstat, $kmsg) = eval { HGCluster->key_status($conf) };
    $kstat = 'missing' unless defined $kstat;
    $kmsg  = ''        unless defined $kmsg;

    print <<HTML;
<h2>Cluster</h2>
<div class="card">
  <p>Propagates blocks between HostGuard Pro servers, so an address that
     attacks one member is refused by all of them. Members are listed in
     <code>/etc/hostguard/cluster.conf</code> and share a secret held in
     <code>cluster.key</code>.</p>
  <p>Messages are authenticated with an HMAC over their contents, so a host
     that cannot produce the secret cannot inject a block. Members need
     roughly synchronised clocks, because a message older than
     <code>CLUSTER_WINDOW</code> is refused as a possible replay.</p>
HTML

    if ($err) {
        print qq(<p class="alert alert-danger">Cannot read the member list: )
            . _h($err) . qq(</p>\n</div>\n);
        return;
    }

    print '<table class="data-table" style="margin-top:12px;">';
    printf('<tr><th>Setting</th><th>Value</th></tr>');
    printf('<tr><td>Status</td><td>%s</td></tr>' . "\n",
           $enabled ? 'enabled' : 'disabled');
    printf('<tr><td>Shared key</td><td>%s</td></tr>' . "\n",
           $kstat eq 'ok' ? 'configured'
                          : '<strong>' . _h(uc($kstat)) . '</strong>: ' . _h($kmsg));
    printf('<tr><td>Port</td><td>%s</td></tr>' . "\n",
           _h($conf->{CLUSTER_PORT} || '7654'));
    printf('<tr><td>Listening on</td><td>%s</td></tr>' . "\n",
           _h($conf->{CLUSTER_BIND} || '127.0.0.1'));
    printf('<tr><td>Replay window</td><td>%s seconds</td></tr>' . "\n",
           _h($conf->{CLUSTER_WINDOW} || '300'));
    printf('<tr><td>Members</td><td>%d</td></tr>' . "\n", scalar(@members));
    print "</table>\n";

    if ($enabled && $kstat ne 'ok') {
        print qq(<p class="alert alert-danger"><strong>The cluster is enabled, )
            . qq(but the key is not usable, so nothing is sent or accepted.)
            . qq(</strong><br>) . _h($kmsg) . qq(</p>\n);

        # Say why refusing is the right answer, because the obvious reading of
        # a stopped cluster is that HostGuard Pro is being unhelpful.
        print qq(<p class="alert alert-warning">The key is the whole of the )
            . qq(cluster's security. Anyone who can read it can tell every )
            . qq(member to block or allow any address, so on a shared host a )
            . qq(readable key means every account on this machine can. )
            . qq(HostGuard Pro refuses such a key rather than carrying on with )
            . qq(a warning.</p>\n)
            if $kstat =~ /^insecure/;

        print qq(<p>Generate one and copy it to every member:<br>)
            . qq(<code>openssl rand -hex 32 &gt; /etc/hostguard/cluster.key</code><br>)
            . qq(<code>chmod 600 /etc/hostguard/cluster.key</code><br>)
            . qq(<code>chown root:root /etc/hostguard/cluster.key</code></p>\n)
            if $kstat eq 'missing' || $kstat eq 'short';
    }

    if (@members) {
        print '<table class="data-table" style="margin-top:12px;">';
        print '<tr><th>Member</th></tr>';
        print '<tr><td>' . _h($_) . "</td></tr>\n" for @members;
        print "</table>\n";

        print <<HTML;
  <form method="post" style="margin-top:12px;">
    ${\ _csrf_field() }
    <input type="hidden" name="action" value="cluster">
    <button type="submit" name="do" value="cluster_ping" class="btn btn-primary">Ping members</button>
  </form>
HTML
    } else {
        print "<p style='margin-top:12px;'>No members configured. Add one "
            . "address per line to <code>cluster.conf</code>.</p>\n";
    }

    print qq(<p style="margin-top:10px; color:#666;">Open the cluster port to )
        . qq(members only, never to the internet.</p>\n);
    print "</div>\n";
}

###############################################################################
# Page: Log Viewer
###############################################################################
sub _page_logs {
    my ($conf, $FORM) = @_;
    my $lines = $FORM->{lines} || 100;
    $lines = 100 unless $lines =~ /^\d+$/ && $lines > 0 && $lines <= 1000;
    my @log = _tail_log($conf, $lines);

    print <<HTML;
<h2>Daemon Log</h2>
<div class="card">
  <form method="get" class="inline-form" style="margin-bottom:10px;">
    <input type="hidden" name="action" value="logs">
    <label>Lines: <input type="number" name="lines" value="$lines" min="10" max="1000" size="5"></label>
    <button type="submit" class="btn btn-info">Refresh</button>
  </form>
  <pre class="log-box" style="max-height:600px; overflow-y:auto;">
HTML
    for my $line (@log) {
        my $eline = _h($line);
        if ($line =~ /\[ERROR\]/) {
            print qq(<span style="color:#dc3545">$eline</span>\n);
        } elsif ($line =~ /\[WARN\]/) {
            print qq(<span style="color:#ffc107">$eline</span>\n);
        } else {
            print "$eline\n";
        }
    }
    print "</pre>\n</div>\n";
}

###############################################################################
# Page: Search Results
###############################################################################
sub _page_search_results {
    my ($FORM) = @_;
    my $ip = _sanitize_ip($FORM->{ip} || '');
    my $eip = _h($ip);
    print "<h2>Search Results for $eip</h2>\n";
    print '<div class="card">';

    if ($ip) {
        # Taken as a list. In scalar context this would collapse to the last
        # element and the exit code would go unnoticed, which is the habit
        # that let failures read as successes everywhere else.
        my ($rc, $output) = _run_cli('-g', $ip);

        if ($rc != 0) {
            print qq(<p class="alert alert-danger">The search failed. )
                . _h(_summarise_cli($output)) . qq(</p>\n);
        } elsif ($output && $output !~ /No entries found/) {
            print "<pre class='log-box'>" . _h($output) . "</pre>\n";
        } else {
            print "<p>No entries found for $eip.</p>\n";
        }
    } else {
        print "<p>Invalid IP address.</p>\n";
    }
    print "</div>\n";
}

###############################################################################
# HTML Template
###############################################################################
sub _print_html_header {
    my ($action) = @_;

    my $hostname = $ENV{SERVER_NAME} || '';
    if (!$hostname) {
        eval { require Sys::Hostname; $hostname = Sys::Hostname::hostname(); };
        $hostname ||= 'server';
    }
    my $ehostname = _h($hostname);

    print qq(<!DOCTYPE html>\n<html lang="en">\n<head>\n);
    print qq(<meta charset="UTF-8">\n);
    print qq(<meta name="viewport" content="width=device-width, initial-scale=1.0">\n);
    print qq(<title>HostGuard Pro - $ehostname</title>\n);

    # Every asset is served from this plugin's own directory. Nothing is fetched
    # from another origin: a WHM session runs as root, and a third-party asset
    # in it would be someone else's code executing with that authority. Icons
    # are inline SVG and the type is a system stack, so the interface renders
    # with the machine offline.
    # The stylesheet is a separate file so the browser caches it once instead of
    # re-sending it with all fourteen pages, which is about half of each. The
    # version query means an upgrade fetches the new one rather than styling new
    # markup with an old cached copy.
    my $ver = _h($HGConfig::VERSION || '1.0.0');
    print qq(<link rel="stylesheet" href="hostguard.css?v=$ver">\n);
    print qq(</head>\n<body>\n<div class="container">\n);
}

###############################################################################
# Navigation
###############################################################################

# Inline SVG icons.
#
# Drawn here rather than pulled from an icon font or a sprite file, so the
# interface has no asset to fetch and nothing to go missing. Each is a 24x24
# stroke path inheriting currentColor.
sub _icon {
    my ($name) = @_;

    my %paths = (
        dashboard  => '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
        statistics => '<path d="M3 3v18h18"/><path d="M7 15l4-4 3 3 5-6"/>',
        allowlist  => '<path d="M12 3l7 3v6c0 4-3 7.5-7 9-4-1.5-7-5-7-9V6z"/><path d="M9 12l2 2 4-4"/>',
        denylist   => '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
        ignorelist => '<path d="M9.9 4.2A9.1 9.1 0 0112 4c5 0 9 4.5 9 8a11 11 0 01-2.1 3.5M6.2 6.2C3.9 7.8 3 10.4 3 12c0 3.5 4 8 9 8 1.6 0 3-.4 4.3-1"/><path d="M3 3l18 18"/>',
        tempblocks => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        tempallows => '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 018 0"/>',
        blocklists => '<path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/>',
        countries  => '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 000 18a14 14 0 000-18"/>',
        cluster    => '<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M7.7 7.7l3 8M16.3 7.7l-3 8M8.5 6h7"/>',
        security   => '<path d="M12 3l7 3v6c0 4-3 7.5-7 9-4-1.5-7-5-7-9V6z"/><path d="M12 9v4M12 16h.01"/>',
        config     => '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="8" cy="18" r="2"/>',
        services   => '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
        logs       => '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 17h4"/>',
        shield     => '<path d="M12 3l7 3v6c0 4-3 7.5-7 9-4-1.5-7-5-7-9V6z"/>',
    );

    my $d = $paths{$name} || $paths{dashboard};
    return qq(<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" )
         . qq(stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" )
         . qq(aria-hidden="true">$d</svg>);
}

# The sidebar, grouped so that a page is found by what it does rather than by
# reading a flat list of fourteen entries.
#
# Returned from a sub rather than held in a package variable: this file runs
# _main() and exits before its own top-level statements are reached, so an
# assignment out here would still be empty by the time the sidebar is drawn.
sub _nav_sections {
    return (
        ['Overview', [
        ['dashboard',   'Dashboard',      'dashboard'],
        ['statistics',  'Statistics',     'statistics'],
    ]],
        ['Access Control', [
        ['allowlist',   'Allowlist',      'allowlist'],
        ['denylist',    'Denylist',       'denylist'],
        ['ignorelist',  'Ignore List',    'ignorelist'],
        ['tempblocks',  'Temp Blocks',    'tempblocks'],
        ['tempallows',  'Temp Allows',    'tempallows'],
    ]],
        ['Threat Sources', [
        ['blocklists',  'Block Lists',    'blocklists'],
        ['countries',   'Countries',      'countries'],
        ['cluster',     'Cluster',        'cluster'],
    ]],
        ['System', [
        ['security',    'Security Check', 'security'],
        ['config',      'Configuration',  'config'],
        ['services',    'Services',       'services'],
        ['logs',        'Log Viewer',     'logs'],
    ]],
    );
}

# Page titles for the bar above the content, so the current page is named even
# when the body of it has scrolled away.
sub _nav_title {
    my ($key) = @_;
    for my $section (_nav_sections()) {
        for my $item (@{ $section->[1] }) {
            return $item->[1] if $item->[0] eq $key;
        }
    }
    return 'Dashboard';
}

sub _print_nav {
    my ($current, $conf) = @_;
    my $script = "hostguard.cgi";
    $conf ||= {};

    print qq(<aside class="sidebar">\n);
    print qq(<div class="brand">\n);
    print qq(  <div class="brand-mark">) . _icon('shield') . qq(</div>\n);
    print qq(  <div class="brand-name">Host<span>Guard</span> Pro</div>\n);
    print qq(</div>\n);

    print qq(<nav class="nav">\n);
    for my $section (_nav_sections()) {
        my ($label, $items) = @$section;
        print qq(<div class="nav-section">) . _h($label) . qq(</div>\n);
        for my $item (@$items) {
            my ($key, $text, $icon) = @$item;
            my $cls = ($current eq $key) ? ' class="active"' : '';
            print qq(<a href="$script?action=$key"$cls>) . _icon($icon)
                . qq(<span>) . _h($text) . qq(</span></a>\n);
        }
    }
    print qq(</nav>\n);

    my $ver = _h($HGConfig::VERSION || '1.0.0');
    print qq(<div class="sidebar-foot"><span>Version $ver</span></div>\n);

    # Attribution. The only outbound link in the interface: one the admin
    # chooses to follow, not an asset the page fetches, so the interface still
    # renders with the machine offline. noopener/noreferrer keep the WHM session
    # out of the opened tab's reach and out of the referrer.
    print qq(<div class="sidebar-credit">Architected and developed by<br>)
        . qq(<a href="https://fasthive.com" target="_blank")
        . qq( rel="noopener noreferrer">Fast Hive</a></div>\n);
    print qq(</aside>\n);

    # --- main column, topbar ---
    my $title = _h(_nav_title($current));
    my $host  = $ENV{SERVER_NAME} || '';
    unless ($host) {
        eval { require Sys::Hostname; $host = Sys::Hostname::hostname(); };
        $host ||= '';
    }

    my $fw_on     = _check_fw_status()->{running} ? 1 : 0;
    my $daemon_on = _get_daemon_pid() ? 1 : 0;
    my $testing   = (($conf->{TESTING} // '') eq '1') ? 1 : 0;

    print qq(<div class="main">\n);
    print qq(<header class="topbar">\n);
    print qq(  <div class="topbar-title">$title</div>\n);
    print _pill($fw_on ? 'on' : 'off', $fw_on ? 'Firewall active' : 'Firewall inactive');
    print _pill($daemon_on ? 'on' : 'off', $daemon_on ? 'Daemon running' : 'Daemon stopped');
    print _pill('warn', 'Testing mode') if $testing;
    print qq(  <div class="topbar-spacer"></div>\n);
    print qq(  <div class="topbar-host">) . _h($host) . qq(</div>\n) if $host;
    print qq(</header>\n);
    print qq(<div class="content">\n);
}

# A small status pill: a coloured dot and a label.
sub _pill {
    my ($state, $label) = @_;
    my %cls = (on => 'pill-on', off => 'pill-off', warn => 'pill-warn');
    my $c = $cls{$state} || '';
    return qq(  <span class="pill $c"><span class="dot"></span>)
         . _h($label) . qq(</span>\n);
}

sub _print_html_footer {
    print "</div>\n</div>\n</div>\n</body>\n</html>\n";
}

###############################################################################
# Utility Functions (zero external module dependencies for safety)
###############################################################################

# HTML escape - short name for convenience
sub _h {
    my ($text) = @_;
    return '' unless defined $text;
    $text =~ s/&/&amp;/g;
    $text =~ s/</&lt;/g;
    $text =~ s/>/&gt;/g;
    $text =~ s/"/&quot;/g;
    $text =~ s/'/&#39;/g;
    return $text;
}

# Return the address unchanged if it is a valid IPv4 or IPv6 address or CIDR
# range, and the empty string otherwise.
#
# Validation is delegated to HGConfig so the interface accepts exactly what the
# CLI and daemon accept, and an address rejected here never reaches a list file
# or a rule.
sub _sanitize_ip {
    my ($ip) = @_;
    return '' unless defined $ip;
    $ip =~ s/\s//g;
    return '' unless length $ip;
    return '' unless $ip =~ m{^[0-9a-fA-F.:/]+$};
    return '' unless HGConfig->valid_ip($ip);
    return $ip;
}

sub _sanitize_comment {
    my ($text) = @_;
    return '' unless defined $text;

    # A space, and no other whitespace.
    #
    # \s would not do here, because it matches newline. A comment of
    # "office\n0.0.0.0/0\n" would survive such a class, and the CLI would append
    # it to allow.conf as written - three lines, the second of which parses as a
    # bare 0.0.0.0/0 allowlist entry. The next reload would allowlist the whole
    # internet ahead of every deny check, from a field labelled "comment".
    #
    # HGFirewall strips line breaks on the writing side as well, so either
    # would close it. Both are here because a comment is written to three
    # different files by three different paths, and the field should not be able
    # to carry a line break in the first place.
    $text =~ s/[\r\n\t\f]+/ /g;
    $text =~ s/[^\w .,\-()\/]//g;
    $text =~ s/^\s+//;
    $text =~ s/\s+$//;
    return substr($text, 0, 200);
}

# Reduce the block list command's output to the lines worth showing in the
# page banner.
sub _summarise_cli {
    my ($out) = @_;
    return '' unless defined $out && length $out;
    my @lines = grep { /\S/ } split(/\n/, $out);
    return '' unless @lines;
    return _h($lines[-1]);
}

sub _read_file {
    my ($file) = @_;
    return undef unless defined $file && -f $file;
    open(my $fh, '<', $file) or return undef;
    my $content = do { local $/; <$fh> };
    close($fh);
    return $content;
}

sub _append_list_entry {
    my ($file, $ip, $comment) = @_;
    open(my $fh, '>>', $file) or die "Cannot write $file: $!\n";
    flock($fh, LOCK_EX);
    my $line = $comment ? "$ip # $comment - " . localtime() : $ip;

    # print and close are both checked, as every other writer in this codebase
    # checks them. A short write on a full filesystem reports itself at one or
    # the other, and this reported success either way - so WHM said "IP added
    # to ignore list" in green while the entry was not there and the daemon
    # went on blocking the address the operator had just protected.
    my $wrote = print $fh "$line\n";
    my $err   = $wrote ? '' : "$!";
    unless (close($fh)) {
        $err ||= "$!";
        $wrote = 0;
    }
    die "Cannot write $file: $err\n" unless $wrote;
    return 1;
}

# Written to a temporary file in the same directory and renamed over the
# target, so an interrupted save cannot leave a half-written configuration or
# IP list behind.
# Check every line of a submitted allow, deny or ignore list.
#
# Returns a list of complaints, empty when the text is acceptable. The forms
# permitted are the ones the firewall engine actually parses: a blank line, a
# comment, an address or CIDR range with an optional trailing comment, and an
# advanced filter. Anything else would be dropped silently at load time, which
# is the failure worth preventing: the administrator believes an address is
# allowed, and it is not.
sub _validate_list_text {
    my ($text) = @_;

    my @errors;
    my $n = 0;

    for my $line (split(/\r?\n/, defined $text ? $text : '')) {
        $n++;
        my $l = $line;
        $l =~ s/^\s+//;
        $l =~ s/\s+$//;
        next if $l eq '' || $l =~ /^#/;

        # An Include points the loader at another file. Adding one from a
        # browser is a way to pull an arbitrary path into firewall policy, so
        # it stays an SSH-only construct. Existing ones are untouched on disk.
        if ($l =~ /^Include\b/i) {
            push @errors, "line $n: Include may only be added over SSH";
            next;
        }

        # Advanced filter, e.g. tcp|in|d=22|s=10.0.0.5
        #
        # Judged by the engine's own definition rather than by a copy kept
        # here. A second copy would drift from the engine's, and the direction
        # it drifts matters: a browser stricter than the file would reject lines
        # the file accepts, and a browser laxer than the file would accept lines
        # the engine turns into something else.
        if ($l =~ /\|/) {
            my ($ok, $why) = HGFirewall->valid_filter($l);
            push @errors, "line $n: " . _h($why) unless $ok;
            next;
        }

        # Address or range, with an optional trailing comment.
        my ($entry) = split(/\s*#\s*/, $l, 2);
        $entry =~ s/\s+$// if defined $entry;
        unless (defined $entry && length $entry && HGConfig->valid_ip($entry)) {
            my $shown = defined $entry ? $entry : $l;
            $shown = substr($shown, 0, 32);
            push @errors, "line $n: '" . _h($shown) . "' is not an IP or CIDR range";
        }
    }

    return @errors;
}

# Keep one copy of what is being replaced.
#
# A bulk edit through a textarea replaces the whole file, so a mistake loses
# everything that was there. One generation back is enough to undo it.
sub _backup_file {
    my ($file) = @_;
    return unless -f $file;

    my $content = _read_file($file);
    return unless defined $content;

    _save_file("$file.bak", $content);
    return 1;
}

# Record a policy change in the daemon log, with the WHM account that made it.
#
# These files decide what the firewall permits, and the log is otherwise the
# only place a change of that kind is visible at all.
sub _audit {
    my ($what) = @_;

    my $who  = $ENV{REMOTE_USER} || 'unknown';
    my $from = $ENV{REMOTE_ADDR} || 'unknown';
    $who  =~ s/[^\w.@-]//g;
    $from =~ s/[^\w.:@-]//g;

    eval { HGLogger->info("WHM: $who from $from $what"); 1 };
    return 1;
}

sub _save_file {
    my ($file, $content) = @_;

    # allow.conf and deny.conf are written in place, not renamed over.
    #
    # hostguardd's unit grants write access to those two files individually
    # rather than to /etc/hostguard, deliberately, so that a fault in the
    # daemon cannot reach hostguard.conf or cluster.key. systemd implements
    # that as a bind mount, and a bind mount of a file is bound to the inode.
    #
    # So a rename here installs a new inode at the path while the daemon's
    # mount still resolves to the old one. The daemon then appends a permanent
    # block to a file that has been unlinked: print and close both succeed, the
    # ipset add succeeds, permblock correctly reports success - and the next
    # reload reads the file this page wrote, which has never contained that
    # address. Every permanent block and cluster allow recorded between a save
    # here and the next daemon restart disappeared, silently.
    #
    # Writing in place trades atomicity for keeping the mount valid. The
    # handler has already taken a .bak copy, which is the recovery path if this
    # is interrupted, and the lock serialises it against another request.
    if (_is_bind_mounted_list($file)) {
        return _save_file_in_place($file, $content);
    }

    my $tmp = "$file.tmp.$$";

    sysopen(my $fh, $tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600)
        or die "Cannot write $tmp: $!\n";
    flock($fh, LOCK_EX);
    print $fh $content or do { close($fh); unlink($tmp); die "Write failed: $!\n" };
    close($fh) or do { unlink($tmp); die "Close failed: $!\n" };
    chmod(0600, $tmp);

    rename($tmp, $file) or do {
        unlink($tmp);
        die "Cannot replace $file: $!\n";
    };
}

# The two files hostguardd's unit bind-mounts by name.
sub _is_bind_mounted_list {
    my ($file) = @_;
    return 0 unless defined $file;
    my $dir = $HGConfig::CONFIG_DIR || '/etc/hostguard';
    return ($file eq "$dir/allow.conf" || $file eq "$dir/deny.conf") ? 1 : 0;
}

# Replace a file's contents without replacing the file.
#
# Writing in place gives up the atomicity a rename would have provided, and
# that matters here more than it usually would: this is allow.conf, and a
# failed write that left it truncated would mean the next reload builds a
# ruleset with no allowlist. That is the lockout the file exists to prevent.
#
# So the existing contents are read first and written back if the new write
# fails. Not a substitute for atomicity - a crash between the truncate and the
# restore still leaves a short file, and the .bak the caller made is the answer
# to that - but it covers the failure that actually happens, which is a full
# filesystem rather than a power cut.
sub _save_file_in_place {
    my ($file, $content) = @_;

    # Opened read-write and locked before the existing contents are read.
    #
    # Reading them outside the lock would let two concurrent saves each hold a
    # copy from before the other wrote, so the one whose write failed would
    # restore its copy over the one that had succeeded. Both actors are WHM root
    # and the action is rate limited, so the window needs two tabs - but the
    # restore exists to avoid losing a list, and losing a different one instead
    # is not a fix.
    sysopen(my $fh, $file, O_RDWR | O_CREAT, 0600)
        or die "Cannot write $file: $!\n";
    flock($fh, LOCK_EX) or do { close($fh); die "Cannot lock $file: $!\n" };

    my $previous = do { local $/; <$fh> };
    seek($fh, 0, 0);

    my $restore = sub {
        my ($why) = @_;
        if (defined $previous) {
            truncate($fh, 0);
            seek($fh, 0, 0);
            print $fh $previous;
        }
        close($fh);
        die "$why $file was left as it was.\n" if defined $previous;
        die "$why\n";
    };

    truncate($fh, 0) or $restore->("Cannot truncate $file: $!.");
    seek($fh, 0, 0);

    # print and close are both checked: a short write on a full filesystem
    # reports itself at one or the other.
    unless (print $fh $content) {
        $restore->("Write to $file failed: $!.");
    }
    unless (close($fh)) {
        my $err = $!;
        # The handle is gone, so the restore has to reopen.
        if (defined $previous && open(my $r, '>', $file)) {
            print $r $previous;
            close($r);
            die "Write to $file failed: $err. $file was left as it was.\n";
        }
        die "Write to $file failed: $err\n";
    }

    chmod(0600, $file);
    return 1;
}

sub _check_fw_status {
    my $file = ($HGConfig::DATA_DIR || '/var/lib/hostguard') . '/firewall.started';
    if (-f $file) {
        my $ts = _read_file($file);
        chomp $ts if defined $ts;
        return { running => 1, since => $ts };
    }
    return { running => 0, since => 0 };
}

sub _get_daemon_pid {
    my $pidfile = "/run/hostguardd.pid";
    return 0 unless -f $pidfile;
    open(my $fh, '<', $pidfile) or return 0;
    my $pid = <$fh>;
    close($fh);
    chomp $pid if $pid;
    return ($pid && $pid =~ /^\d+$/) ? int($pid) : 0;
}

sub _safe_load_iplist {
    my ($file) = @_;
    return () unless -f $file;
    my @entries;
    eval { @entries = HGConfig->load_iplist($file); };
    return @entries;
}

# Active temporary allows, read the same way temporary blocks are.
sub _load_tempallows {
    my $file = ($HGConfig::DATA_DIR || '/var/lib/hostguard') . '/tempallow.dat';
    my @records;
    return @records unless -f $file;

    open(my $fh, '<', $file) or return @records;
    flock($fh, LOCK_SH);
    my $now = time();
    while (my $line = <$fh>) {
        chomp $line;
        next unless length $line;
        my ($ip, $expires, $note) = split(/\|/, $line, 3);
        next unless defined $ip && defined $expires && $expires =~ /^\d+$/;
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

sub _load_tempblocks {
    my $tempfile = ($HGConfig::DATA_DIR || '/var/lib/hostguard') . '/tempblock.dat';
    my @blocks;
    return @blocks unless -f $tempfile;
    open(my $fh, '<', $tempfile) or return @blocks;
    my $now = time();
    while (my $line = <$fh>) {
        chomp $line;
        my ($ip, $expires, $reason) = split(/\|/, $line, 3);
        next unless $ip && $expires;
        push @blocks, {
            ip      => $ip,
            expires => $expires,
            reason  => $reason || '',
            active  => ($expires > $now ? 1 : 0),
            ttl     => ($expires > $now ? $expires - $now : 0),
        };
    }
    close($fh);
    return @blocks;
}

# Read the last N lines of the daemon log.
#
# The file is walked backwards in blocks from the end. The log can reach tens
# of megabytes, and loading all of it into a CGI to display the last hundred
# lines would be a reliable way to exhaust memory on a busy server.
sub _tail_log {
    my ($conf, $num_lines) = @_;
    $num_lines ||= 50;
    my $logfile = $conf->{LOG_FILE} || '/var/log/hostguard/daemon.log';
    return ("(log file not found: $logfile)") unless -f $logfile;
    return _tail_file($logfile, $num_lines);
}

sub _tail_file {
    my ($file, $num_lines) = @_;
    open(my $fh, '<', $file) or return ("Cannot read log: $!");
    binmode($fh);

    my $size = -s $fh;
    return () unless $size;

    # Walk backwards in blocks until enough newlines are found, or the start
    # of the file is reached.
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
        last if (($data =~ tr/\n//) > $num_lines);
        # Ceiling on how much of the file is ever held in memory.
        last if length($data) > 4 * 1024 * 1024;
    }
    close($fh);

    my @lines = split(/\n/, $data);
    shift @lines if $pos > 0 && @lines;    # discard the partial first line
    my $start = @lines > $num_lines ? @lines - $num_lines : 0;
    return @lines[$start .. $#lines];
}

sub _format_duration {
    my ($secs) = @_;
    return '0s' unless $secs;
    $secs = int($secs);
    if ($secs >= 86400) {
        return sprintf("%dd %dh", int($secs/86400), int(($secs%86400)/3600));
    } elsif ($secs >= 3600) {
        return sprintf("%dh %dm", int($secs/3600), int(($secs%3600)/60));
    } elsif ($secs >= 60) {
        return sprintf("%dm %ds", int($secs/60), $secs%60);
    }
    return "${secs}s";
}

# Rate limit repeated state-changing actions.
#
# The window is kept per action, so throttling one control does not lock an
# administrator out of the others. Read-only actions are never limited, and a
# timestamp is recorded only for an action that is about to run.
sub _check_rate_limit {
    my ($rate_file, $action) = @_;
    $action = '' unless defined $action;

    # Lookups change nothing and are never limited.
    my %read_only = (search_ip => 1);
    return 1 if $read_only{$action};

    $action =~ s/[^\w]//g;
    return 1 unless length $action;

    my $now    = time();
    my $window = 5;

    my %seen;
    if (open(my $fh, '<', $rate_file)) {
        while (my $line = <$fh>) {
            chomp $line;
            my ($key, $ts) = split(/\|/, $line, 2);
            next unless defined $key && defined $ts && $ts =~ /^\d+$/;
            # Discard stale entries so the file stays bounded.
            next if ($now - $ts) > 3600;
            $seen{$key} = $ts;
        }
        close($fh);
    }

    if (defined $seen{$action} && ($now - $seen{$action}) < $window) {
        return 0;
    }

    $seen{$action} = $now;
    if (open(my $fh, '>', "$rate_file.tmp")) {
        flock($fh, LOCK_EX);
        print $fh "$_|$seen{$_}\n" for sort keys %seen;
        close($fh);
        chmod(0600, "$rate_file.tmp");
        rename("$rate_file.tmp", $rate_file) or unlink("$rate_file.tmp");
    }
    return 1;
}
