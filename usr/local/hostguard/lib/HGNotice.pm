package HGNotice;
###############################################################################
# HostGuard Pro - Block Notice Service
# /usr/local/hostguard/lib/HGNotice.pm
#
# Answers blocked visitors instead of ignoring them.
#
# A dropped packet looks the same to a visitor as a server that is down, and a
# site with real users pays for that in support requests from people whose
# office address was caught by a shared block. When the notice service is on,
# a blocked address reaching the web port is redirected to a small responder
# that serves a page saying what happened and how to ask for it to be undone.
#
# What this is not: the notice is served, the block still stands. Nothing here
# lets a visitor remove their own block, and the responder never reads a path,
# a parameter or a header from the request - it answers every request on its
# port with the same page, whatever was asked for.
#
# Only cleartext HTTP can be answered. A TLS client expects a handshake and
# will report a certificate error rather than render a redirect, so HTTPS
# traffic from a blocked address is left to drop as before. This is a
# limitation of the approach, not of the implementation.
###############################################################################
use strict;
use warnings;
use Socket;
use Errno qw(EWOULDBLOCK EAGAIN EINTR);
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use HGConfig;
use HGLogger;

# Ports whose traffic is redirected to the responder. Only ports carrying
# cleartext HTTP belong here.
our $DEFAULT_PORTS = '80';

# Largest request read before answering. A response is sent regardless of what
# arrives, so the request is read only to keep the client's send buffer from
# filling; a cap keeps a client that streams forever from holding the socket.
our $MAX_REQUEST = 4096;

# How long one connection may take, in total, from accept to last byte written.
#
# Every peer on this socket is an address the firewall has already blocked -
# that is what the nat redirect selects for - so the population served here and
# the population attacking the host are the same set. That is what makes the
# bound load-bearing rather than tidy.
#
# service_sockets calls this up to fifty times per pass, on the daemon's single
# main loop. A blocking read would let a client connect, send one byte and never
# send the blank line, so fifty such connections would cost fifty times the
# timeout - during which no log is read, no block expires, no scheduled task
# runs and no new attack from any source is detected. A blocked attacker could
# switch off the thing that blocked them and buy an unwatched window on every
# other service.
#
# One second, measured against the clock and enforced with a non-blocking
# socket, so a slow client is dropped rather than waited for. A real browser
# has already sent its request headers by the time this runs.
our $CONN_TIMEOUT = 1;

# Wall-clock deadline enforcement on a non-blocking handle.
#
# select() rather than alarm(): alarm is a single per-process timer, so setting
# one here silently discards whatever the caller had running and a SIGALRM from
# elsewhere lands in the middle of a socket call. HGCluster::_send_all already
# argues this at length; the same reasoning applies to being on the receiving
# end.
sub _set_nonblocking {
    my ($fh) = @_;
    my $flags = fcntl($fh, F_GETFL, 0);
    return 0 unless defined $flags;
    return fcntl($fh, F_SETFL, $flags | O_NONBLOCK) ? 1 : 0;
}

sub _wait_ready {
    my ($fh, $deadline, $for_write) = @_;
    my $left = $deadline - _now();
    return 0 if $left <= 0;

    my $vec = '';
    vec($vec, fileno($fh), 1) = 1;
    my $n = $for_write ? select(undef, my $w = $vec, undef, $left)
                       : select(my $r = $vec, undef, undef, $left);
    return (defined $n && $n > 0) ? 1 : 0;
}

sub _now {
    return eval { require Time::HiRes; Time::HiRes::time() } || time();
}

###############################################################################
# Configuration
###############################################################################

sub enabled {
    my ($class, $config) = @_;
    return ($config->{NOTICE_ENABLE} // '0') eq '1' ? 1 : 0;
}

# The port the responder listens on.
#
# Deliberately not 80: the responder is not a web server and must never
# compete with the real one for the port a site is served from.
sub port {
    my ($class, $config) = @_;
    my $port = $config->{NOTICE_PORT} // 8899;
    $port = 8899 unless $port =~ /^\d+$/ && $port > 0 && $port <= 65535;
    return $port;
}

# The ports whose traffic is redirected, as a validated list.
sub redirect_ports {
    my ($class, $config) = @_;

    my $value = $config->{NOTICE_PORTS} // $DEFAULT_PORTS;
    my @ports;
    for my $p (split(/,/, $value)) {
        $p =~ s/\s//g;
        next unless length $p;
        unless ($p =~ /^\d+$/ && $p > 0 && $p <= 65535) {
            HGLogger->error("Ignoring invalid notice redirect port: $p");
            next;
        }
        push @ports, $p;
    }

    return @ports;
}

###############################################################################
# Page content
###############################################################################

# Build the response body.
#
# An administrator-supplied file is used when NOTICE_FILE names one, so a site
# can match its own wording and branding. The built-in page is the fallback
# and is deliberately plain.
#
# The visitor's address is substituted so they can quote it in a support
# request. Nothing else about the request is reflected: echoing a path or a
# header into the page would turn the responder into a way to serve arbitrary
# content from the site's own address.
sub page {
    my ($class, $config, $ip) = @_;

    $ip = '' unless defined $ip && HGConfig->valid_ip($ip);

    my $file = $config->{NOTICE_FILE} || '';
    my $body;

    if (length $file && -f $file) {
        if (open(my $fh, '<', $file)) {
            $body = do { local $/; <$fh> };
            close($fh);
        } else {
            HGLogger->log_warn("Cannot read notice page $file: $!");
        }
    }

    unless (defined $body && length $body) {
        my $contact = $config->{NOTICE_CONTACT} || '';
        my $contact_html = length $contact
            ? '<p>If you believe this is a mistake, contact '
              . _escape($contact) . ' and quote your address.</p>'
            : '<p>If you believe this is a mistake, contact the site '
              . 'administrator and quote your address.</p>';

        $body = <<"HTML";
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access blocked</title>
<style>
  body { font: 16px/1.6 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; padding: 3rem 1.5rem; background: #f6f7f9; color: #1c2024; }
  main { max-width: 34rem; margin: 0 auto; background: #fff; padding: 2rem;
         border: 1px solid #dfe3e8; border-radius: 8px; }
  h1 { margin: 0 0 1rem; font-size: 1.4rem; }
  code { background: #f0f2f5; padding: .15rem .4rem; border-radius: 4px; }
  p { margin: 0 0 1rem; }
  .addr { font-size: 1.1rem; }
</style>
</head>
<body>
<main>
<h1>Access blocked</h1>
<p>This server is not accepting connections from your address.</p>
<p class="addr">Your address: <code>[IP]</code></p>
$contact_html
</main>
</body>
</html>
HTML
    }

    $body =~ s/\[IP\]/_escape($ip)/ge;
    return $body;
}

# Escape the five characters that carry meaning in HTML.
#
# The address is validated before it reaches here, so this is belt and braces
# - but the administrator's contact string is not validated, and it lands in
# the same page.
sub _escape {
    my ($text) = @_;
    return '' unless defined $text;
    $text =~ s/&/&amp;/g;
    $text =~ s/</&lt;/g;
    $text =~ s/>/&gt;/g;
    $text =~ s/"/&quot;/g;
    $text =~ s/'/&#39;/g;
    return $text;
}

###############################################################################
# Responder
###############################################################################

# Open the responder's listening socket.
#
# Bound to every interface, which is not what it looks like.
#
# The obvious choice is loopback, on the reasoning that the redirect happens
# inside the host's own nat table so the responder never needs to be reachable
# from outside. That reasoning is wrong about what REDIRECT does: it rewrites
# the destination to the primary address of the incoming interface, and only a
# locally generated packet is sent to 127.0.0.1. A responder on loopback
# therefore never received a single redirected packet, and the feature could
# not work at all.
#
# Binding to every interface does not publish the service, because the port is
# not opened by the firewall. NOTICE_PORT is absent from TCP_IN, and the only
# rule that admits traffic to it is scoped to the temporary block set - so the
# addresses that can reach the responder are exactly the addresses the redirect
# can send to it. Anything else falls through to the drop at the end of the
# input chain. The confinement is in the ruleset rather than in the bind, which
# is where it can actually be stated.
sub listener {
    my ($class, $config) = @_;

    return undef unless $class->enabled($config);

    my $port = $class->port($config);
    my $bind = $config->{NOTICE_BIND} || '0.0.0.0';
    unless (HGConfig->valid_ipv4($bind)) {
        HGLogger->error("NOTICE_BIND is not an IPv4 address: $bind");
        return undef;
    }

    if ($bind =~ /^127\./) {
        HGLogger->log_warn("NOTICE_BIND is $bind. The redirect sends blocked "
                         . "visitors to this host's interface address, not to "
                         . "loopback, so this responder will never be reached "
                         . "and blocked visitors will see a refused connection "
                         . "rather than the notice page. Set NOTICE_BIND to "
                         . "0.0.0.0, or to the address the site is served on.");
    }

    my $sock;
    unless (socket($sock, PF_INET, SOCK_STREAM, getprotobyname('tcp'))) {
        HGLogger->error("Cannot create notice listener: $!");
        return undef;
    }
    setsockopt($sock, SOL_SOCKET, SO_REUSEADDR, pack('l', 1));

    unless (bind($sock, sockaddr_in($port, inet_aton($bind)))) {
        HGLogger->error("Cannot bind notice listener to $bind:$port: $!");
        close($sock);
        return undef;
    }
    unless (listen($sock, 20)) {
        HGLogger->error("Cannot listen on $bind:$port: $!");
        close($sock);
        return undef;
    }

    HGLogger->info("Block notice service listening on $bind:$port");
    return $sock;
}

# Accept one pending connection and answer it.
#
# Every step is bounded by a wall-clock deadline on a non-blocking socket, not
# by an alarm - see $CONN_TIMEOUT. The clients reaching this port are by
# definition ones the host has already decided to block, so a client that opens
# a connection and stalls must not be able to hold up the daemon's main loop,
# and a per-process timer is the wrong tool for saying so.
sub serve {
    my ($class, $listen, $config) = @_;

    # A peer that goes away mid-write must not take the daemon with it.
    #
    # syswrite to a socket the other end has closed delivers SIGPIPE as well as
    # returning EPIPE, and SIGPIPE's default action terminates the process.
    # Perl installs no handler, and hostguardd sets TERM, INT, HUP, USR1 and
    # CHLD but not PIPE - so without this line a client that sends a request
    # and then resets the connection kills the firewall's daemon.
    #
    # Every peer reaching this socket is an address the firewall has already
    # blocked, because that is what the nat redirect selects for. So the
    # population that can trigger it and the population attacking the host are
    # the same set, and closing a connection early is not something they have
    # to be clever to do. A blocked attacker could switch off the thing that
    # blocked them, on demand, in a loop.
    #
    # HGCluster::_send_all and HGAlert::_deliver take the same precaution on
    # the same grounds; this is the third socket write in the codebase and was
    # the one without it.
    local $SIG{PIPE} = 'IGNORE';

    my $peer_addr = accept(my $conn, $listen);
    return 0 unless $peer_addr;

    my ($peer_port, $addr) = sockaddr_in($peer_addr);
    my $peer = inet_ntoa($addr);

    my $body = $class->page($config, $peer);
    my $len  = length($body);

    # Non-blocking from here on. If the descriptor cannot be put into that
    # mode there is no way to bound how long this takes, so the connection is
    # dropped rather than served: an unserved notice costs a blocked visitor a
    # blank page, and an unbounded one costs everybody the daemon.
    unless (_set_nonblocking($conn)) {
        HGLogger->log_warn("Cannot set the notice connection from $peer "
                         . "non-blocking; dropping it rather than risking a "
                         . "blocking read on the main loop");
        close($conn);
        return 0;
    }

    my $deadline = _now() + $CONN_TIMEOUT;

    # Read and discard the request. Nothing in it influences the response; it
    # is drained so the client can finish sending before the socket is closed
    # under it, which is what makes browsers render the page rather than report
    # a reset connection.
    my $buf = '';
    while (length($buf) < $MAX_REQUEST) {
        last unless _wait_ready($conn, $deadline, 0);
        my $chunk;
        my $n = sysread($conn, $chunk, $MAX_REQUEST - length($buf));
        if (!defined $n) {
            last unless $! == EWOULDBLOCK || $! == EAGAIN || $! == EINTR;
            next;
        }
        last if $n == 0;                 # client closed
        $buf .= $chunk;
        last if $buf =~ /\r?\n\r?\n/;
    }

    my $out = "HTTP/1.1 403 Forbidden\r\n"
            . "Content-Type: text/html; charset=UTF-8\r\n"
            . "Content-Length: $len\r\n"
            . "Cache-Control: no-store\r\n"
            . "Connection: close\r\n"
            . "\r\n"
            . $body;

    # Written under the same deadline. A client that opens its window and then
    # stops reading would otherwise hold this here once the socket buffer
    # filled, which is the same denial of service from the other direction.
    my $sent = 0;
    while ($sent < length($out)) {
        last unless _wait_ready($conn, $deadline, 1);
        my $n = syswrite($conn, $out, length($out) - $sent, $sent);
        if (!defined $n) {
            last unless $! == EWOULDBLOCK || $! == EAGAIN || $! == EINTR;
            next;
        }
        last if $n == 0;
        $sent += $n;
    }

    close($conn);

    if ($sent < length($out)) {
        HGLogger->debug("Block notice to $peer was cut short after ${sent} of "
                      . length($out) . " bytes (client too slow)");
    } else {
        HGLogger->debug("Served block notice to $peer");
    }
    return 1;
}

1;
