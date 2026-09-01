# 🛡️ HostGuard Pro

> Advanced Firewall & Real-Time Intrusion Protection for cPanel / WHM Servers

HostGuard Pro is a high-performance firewall and brute-force protection suite built specifically for modern cPanel/WHM environments.
It delivers real-time attack mitigation, intelligent login monitoring, and a fully integrated WHM interface, all with secure defaults and enterprise-grade stability.

Designed for AlmaLinux, Rocky Linux, CloudLinux, CentOS, RHEL and Oracle
Linux cPanel servers, versions 7 to 10. The installer refuses to run on
anything else rather than installing part of itself.

------------------------------------------------------------------------

## 🚀 Why HostGuard Pro?

Public-facing servers are constantly targeted by:

-   Brute-force login attempts
-   SSH abuse
-   SMTP authentication attacks
-   FTP scanning
-   cPanel / WHM login probing
-   Port scanning
-   Distributed credential attacks
-   Compromised accounts sending spam
-   Payloads dropped in world-writable directories
-   Replaced system binaries

HostGuard Pro continuously monitors your system and reacts within seconds blocking threats before they escalate.

------------------------------------------------------------------------

## 🔥 Core Features

### 🧱 Stateful Firewall Engine

-   Default deny inbound policy
-   Allow established & related connections
-   Configurable `TCP_IN`, `TCP_OUT`, `UDP_IN`, `UDP_OUT`
-   IPv4 + IPv6 support
-   iptables + ipset optimized rule sets
-   Works with the iptables-nft backend on AlmaLinux / Rocky 8+
-   Secure auto-allow protection during installation
-   Built-in TEST mode to prevent accidental lockouts
-   Zero-downtime rule swaps: a new ruleset is assembled in an idle slot and
    attached only once complete, so the host is never left unfiltered. Attaching
    takes several iptables commands, which cannot be issued as one, so it is
    made all-or-nothing: a jump that fails to insert undoes the ones before it
-   A ruleset that iptables partly rejects is never activated. The slot is torn
    down and the previous rules keep serving, rather than a partial ruleset
    being installed and reported as a success
-   SYN flood, connection-limit and per-port flood mitigation
-   Port scan detection, counting only arrivals that matched no open port
-   Bogon filtering for source addresses that cannot arrive from the internet
-   Traffic to unused server addresses dropped outright
-   Permanent, temporary (TTL) and **temporary allow** (TTL) entries
-   Low / Medium / High presets that never touch your port settings

------------------------------------------------------------------------

### 🧠 Real-Time Login Protection

HostGuard Pro includes a persistent background daemon (`hostguardd`) that:

-   Monitors authentication logs continuously
-   Detects brute-force behavior instantly
-   Aggregates login attempts across multiple services
-   Blocks attackers automatically
-   Supports temporary blocks with automatic expiry
-   Optionally promotes repeat offenders to permanent block
-   Handles log rotation gracefully

Supported detection targets include:

-   **SSH** (OpenSSH)
-   **WHM / cPanel / Webmail** logins (`login_log`, `error_log`)
-   **SMTP AUTH**: Exim, Dovecot submission
-   **IMAP / POP3**: Dovecot, Courier, uw-imap, Kerio
-   **FTP**: Pure-FTPd, ProFTPD, vsftpd
-   **Password protected web pages** (Apache htpasswd)
-   **ModSecurity** rule violations (v1 and v2)
-   **Suhosin** alerts
-   **Anything else you define**: your own log file and regular expression,
    in `patterns.conf`, with no code changes

It also detects what the per-address counters cannot see:

-   **Distributed attacks**: many addresses failing against one account.
    Each source looks like a user who mistyped; counting per *account*
    reveals the pattern and blocks the whole set.
-   **Login rate abuse**: an address authenticating far too often per hour,
    which is a misconfigured mail client at best and credential testing at
    worst.

------------------------------------------------------------------------

### 👁️ Host Monitoring

Beyond traffic, HostGuard Pro watches the server itself. Every check below is
**off by default** and switched on individually.

-   **Suspicious process reporting**: reverse shells, miners, scanners,
    processes running from a deleted binary or out of `/tmp`. Reported, never
    killed.
-   **Excessive user processes**: accounts running more than they should
-   **Resource usage**: processes over a CPU or memory ceiling, optionally
    sent `SIGTERM` (never `SIGKILL`)
-   **Suspicious file reporting**: executables, setuid files and scripts in
    `/tmp`, `/var/tmp`, `/dev/shm`
-   **Directory and file watching**: report when a watched path changes
-   **Integrity monitoring**: the last line of detection, reporting changes
    to system and application binaries
-   **Account modification tracking**: a changed shell, uid, home directory
    or password. The password itself is never stored or sent, only the fact
    that it changed.
-   **Outbound mail tracking**: messages per account and per sending script,
    which is where a compromised site usually shows itself first
-   **Sustained load alerting**: load that stays high, not load that spikes
-   **Server security check**: a review of the settings that decide how
    exposed the host is, with the top CPU consumers attached

------------------------------------------------------------------------

### 🔔 Notifications

One engine handles every message, with three guards, because the events that
most need reporting are exactly the ones that arrive in floods:

-   A master switch, plus a switch per kind of notice
-   An hourly ceiling per kind
-   Repeat suppression, so one persistent attacker yields one message

Reportable events include SSH logins, `su` activity, WHM root access, account
changes, blocks, port scans, high load, excessive mail, and every host check
above.

Every notice renders from its own template in
`/usr/local/hostguard/tpl/`, so the wording, the advice and the branding are
yours to change. A template that is missing or unreadable falls back to
built-in plain text, so an edit that goes wrong degrades to a readable message
rather than an empty one.

------------------------------------------------------------------------

### 🌐 External Block Lists

Download publicly published lists of hostile networks and block them at the
firewall:

-   Spamhaus DROP / EDROP, DShield, Blocklist.de, GreenSnow and any other
    HTTP(S) list
-   Per-list refresh interval and import cap
-   Refreshed and applied by the daemon without interrupting the firewall
-   Allowlisted addresses always win over a list
-   A download is applied only if it looks like the list it claims to be:
    it has to parse as addresses, and it must not have collapsed against
    the copy it replaces. Otherwise the previous copy is kept

All lists ship disabled, so nothing is downloaded until one is enabled.

------------------------------------------------------------------------

### 🌍 Country Filtering

Allow or deny traffic by the ISO country code an address is registered to,
using published zone files cached locally.

-   `GEO_DENY` blocks the countries you name
-   `GEO_ALLOW` blocks everything *except* the countries you name

Your allowlist always wins over both. Allow mode is a sharp instrument (it
drops everything the zone files do not account for), so HostGuard Pro refuses
to apply it if the zone files came back empty, rather than locking you out on
the strength of a failed download.

------------------------------------------------------------------------

### 🔗 Server Clustering

Propagate blocks between HostGuard Pro servers, so an address that attacks one
member is refused by all of them.

-   Messages authenticated with an HMAC over their contents; a host that
    cannot produce the shared secret cannot inject a block
-   A replay window bounds how long a captured message stays valid
-   Members listen on loopback by default, so the port must be opened
    deliberately
-   A member applies what it is told and stops there, so a block cannot loop
    around the cluster
-   Members are contacted concurrently, so `CLUSTER_TIMEOUT` bounds the whole
    broadcast rather than each unreachable member in turn

------------------------------------------------------------------------

### 💬 Block Notice Service

A dropped packet looks the same to a visitor as a server that is down, which
costs a site with real users in support requests. When enabled, a blocked
address reaching the web port is answered with a page explaining what happened
and how to ask for it to be undone.

The notice is served; the block still stands. Nothing lets a visitor remove
their own block. HTTP only: a TLS client would report a certificate error
rather than render a page, so HTTPS from a blocked address is left to drop.

------------------------------------------------------------------------

## 🖥️ Native WHM Integration

Access HostGuard Pro directly inside WHM:

**WHM → HostGuard Pro**

Features:

-   📊 Live Dashboard (status, recent blocks, system overview)
-   ⚙️ Firewall Configuration Editor (read-only by default; set `RESTRICT_UI=0` to allow saving)
-   🧾 Allowlist / Denylist / Ignore Manager, with validated quick-add and a
    bulk editor that is read-only unless `RESTRICT_UI=0`
-   ⏳ Temporary Blocks Viewer with One-Click Unblock
-   ⏱️ Temporary Allows with TTL, added and revoked in place
-   🔄 Service Controls (Start / Stop / Restart / Reload)
-   🌐 Block List Manager (entry counts, last update, on-demand refresh)
-   🌍 Country Filter Manager (per-country range counts and refresh)
-   🔗 Cluster status and member reachability
-   🛡️ Security Check with severity-ranked findings
-   📈 System Statistics: load, memory, processes and blocks, drawn as
    inline SVG with no third-party charting script
-   📜 Integrated Log Viewer

Requests are CSRF-protected and rate-limited, and authentication fails closed:
if the WHM access control modules cannot be loaded, the request is refused
rather than served.

------------------------------------------------------------------------

## 💻 Command Line Interface

HostGuard Pro provides a powerful CLI for system administrators:

``` bash
hostguard -e                # Enable firewall
hostguard -x                # Disable firewall
hostguard -r                # Reload firewall rules
hostguard -a <ip> [note]    # Allow IP
hostguard -d <ip> [note]    # Deny IP
hostguard -tr <ip>          # Remove temporary block
hostguard -g <ip>           # Search IP in configuration
hostguard -l                # List temporary blocks
hostguard -b                # Update external block lists that are due
hostguard -b force          # Re-download every external block list

hostguard -ta <ip> [secs] [note]   # Allow an IP temporarily (default 1h)
hostguard -tar <ip>                # Remove a temporary allow
hostguard -la                      # List active temporary allows

hostguard -c                # Update country zone files that are due
hostguard -c force          # Re-download every country zone file

hostguard --security        # Run the server security check
hostguard --scan            # Run the process and file checks now
hostguard --preset high     # Apply a threshold preset
hostguard --integrity-reset # Clear the binary integrity baseline

hostguard --cluster list           # Show cluster configuration
hostguard --cluster ping           # Confirm members are reachable
hostguard --cluster deny <ip>      # Block an address across every member

hostguard -s                # Status, including which subsystems are on
```

The `myfw` command is an alias that works identically.

------------------------------------------------------------------------

## 📂 Directory Structure

    /etc/hostguard/               # Configuration files
      hostguard.conf              #   Main configuration
      allow.conf / deny.conf      #   Permanent allow and deny lists
      ignore.conf                 #   Never auto-blocked
      blocklists.conf             #   External block list definitions
      patterns.conf               #   Your own log patterns
      watch.conf                  #   Paths to watch for changes
      cluster.conf                #   Cluster members
      procignore.conf             #   Process and file scan exceptions
    /usr/local/hostguard/bin/     # CLI & daemon
    /usr/local/hostguard/lib/     # Internal modules
    /usr/local/hostguard/tpl/     # Alert templates, one per notice kind
    <whm docroot>/cgi/hostguard/  # WHM interface: hostguard.cgi + .css
    /var/lib/hostguard/           # Runtime data, baselines & counters
      blocklists/                 #   Cached external lists
      geo/                        #   Cached country zone files
    /var/log/hostguard/           # Daemon logs

------------------------------------------------------------------------

## 🔐 Security Architecture

-   Strong validation for IP/CIDR/port inputs
-   No unsafe shell execution: every command is exec'd as an argument list,
    so no configuration value or log capture ever reaches a shell
-   Downloaded block list and zone data is validated line by line and never
    interpolated into a command
-   Secure configuration file permissions
-   Allowlist priority override, above every deny path including country and
    block list rules
-   HMAC-authenticated cluster messages with a bounded replay window
-   CSRF protection and fail-closed authentication in the WHM interface
-   Safe recovery mechanisms
-   Both systemd units are sandboxed: read-only filesystem outside their own
    paths, a bounded capability set, and `/home` read-only or inaccessible

### Defaults

Every subsystem added beyond the core firewall ships **off**. Nothing is
downloaded, no mail is sent, no process is terminated and no traffic is
filtered by country until you turn it on. Start with `hostguard --security`
and `hostguard --scan` to see what a host reports before enabling anything
that acts.

------------------------------------------------------------------------

## ⚙️ Installation

``` bash
git clone https://github.com/zaltom/HostGuard-PRO.git hostguard-pro
cd hostguard-pro
bash install.sh
```

------------------------------------------------------------------------

## 🔄 Uninstallation

``` bash
bash uninstall.sh
```

The uninstaller removes HostGuard Pro's own chains, ipsets and rules and
nothing else. It does not reset default policies it cannot show HostGuard Pro
changed, and it names any other firewall manager it finds - CSF, firewalld,
ufw, shorewall, nftables, fail2ban, Docker - before it starts. See *Running
Alongside Another Firewall* in `guide.md`.

------------------------------------------------------------------------

Secure your infrastructure, React instantly.
