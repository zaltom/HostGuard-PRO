#!/bin/bash
###############################################################################
# HostGuard Pro - Installation Script
# Run as root on a cPanel/WHM server (AlmaLinux/Rocky/CentOS)
###############################################################################
set -e

# Every file this script creates is created before its mode is set, so the mode
# in force while it exists is whatever the invoking shell happened to have.
# /etc/hostguard is 0755, so a permissive umask left hostguard.conf - which
# names CLUSTER_KEY_FILE, PRE_SCRIPT, POST_SCRIPT and the whole port policy -
# readable by every local account for as long as the install took.
umask 077

VERSION="1.0.0"
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

###############################################################################
# Pre-flight checks
###############################################################################

echo ""
echo "=============================================="
echo "  HostGuard Pro v${VERSION} - Installer"
echo "=============================================="
echo ""

# Must be root
if [ "$(id -u)" -ne 0 ]; then
    log_error "This installer must be run as root."
    exit 1
fi

# Check for cPanel
if [ ! -e "/usr/local/cpanel/version" ]; then
    log_warn "cPanel not detected. WHM plugin integration will be skipped."
    log_warn "Firewall and daemon will still be installed."
    HAS_CPANEL=0
else
    CPANEL_VER=$(cat /usr/local/cpanel/version)
    log_info "cPanel detected: v${CPANEL_VER}"
    HAS_CPANEL=1
fi

###############################################################################
# Supported platform
###############################################################################
#
# Refused rather than attempted. Everything below this point writes to the
# system, and a partial install is the worst outcome: files in place, services
# registered, and a firewall that does not come up. The paths this depends on
# are the RHEL family's, which is what cPanel supports.
#
# What actually differs elsewhere: the authentication logs are named
# differently, the package manager is not yum or dnf, and the unit and cron
# directories are not always where these units expect. Some of that is handled
# by configuration; not all of it, and not silently.
#
# Set HG_ALLOW_UNSUPPORTED=1 to install anyway. That is a deliberate act with a
# clear message attached, not a default.

OS_ID=""
OS_VERSION=""
OS_NAME=""
OS_LIKE=""

if [ -r /etc/os-release ]; then
    # Read in a subshell so the sourced file cannot overwrite anything here.
    OS_ID=$(. /etc/os-release 2>/dev/null && echo "${ID:-}")
    OS_VERSION=$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID:-}")
    OS_NAME=$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-}")
    OS_LIKE=$(. /etc/os-release 2>/dev/null && echo "${ID_LIKE:-}")
fi

# Older releases carry only /etc/redhat-release.
if [ -z "$OS_ID" ] && [ -r /etc/redhat-release ]; then
    OS_NAME=$(cat /etc/redhat-release)
    case "$OS_NAME" in
        AlmaLinux*)   OS_ID="almalinux" ;;
        Rocky*)       OS_ID="rocky" ;;
        CloudLinux*)  OS_ID="cloudlinux" ;;
        CentOS*)      OS_ID="centos" ;;
        "Red Hat"*)   OS_ID="rhel" ;;
        Oracle*)      OS_ID="ol" ;;
    esac
    OS_VERSION=$(echo "$OS_NAME" | grep -oE '[0-9]+' | head -1)
fi

[ -n "$OS_NAME" ] || OS_NAME="${OS_ID:-unknown}"
log_info "OS: ${OS_NAME}"

# The RHEL family, by the names these distributions actually report.
OS_SUPPORTED=0
case "$OS_ID" in
    rhel|centos|almalinux|rocky|cloudlinux|ol|oraclelinux|virtuozzo)
        OS_SUPPORTED=1 ;;
esac

# A derivative that does not name itself but declares its lineage.
if [ "$OS_SUPPORTED" -eq 0 ] && [ -n "$OS_LIKE" ]; then
    case " $OS_LIKE " in
        *" rhel "*|*" fedora "*|*" centos "*)
            OS_SUPPORTED=1
            log_warn "  ${OS_ID} is not a release this has been tested on, but it"
            log_warn "  reports ID_LIKE=\"${OS_LIKE}\", so the RHEL layout is assumed."
            ;;
    esac
fi

if [ "$OS_SUPPORTED" -eq 1 ]; then
    OS_MAJOR=$(echo "$OS_VERSION" | cut -d. -f1)
    case "$OS_MAJOR" in
        7|8|9|10)
            log_info "Supported platform: ${OS_ID} ${OS_VERSION}"
            ;;
        *)
            # A newer major release is likely fine and is not worth refusing,
            # but it has not been tried.
            log_warn "Platform ${OS_ID} ${OS_VERSION:-unknown} is outside the"
            log_warn "tested range (7 to 10). Installation will continue; check"
            log_warn "the firewall comes up before relying on it."
            ;;
    esac
else
    log_error "Unsupported platform: ${OS_NAME}"
    log_error ""
    log_error "HostGuard Pro targets the RHEL family, which is what cPanel"
    log_error "supports: AlmaLinux, Rocky Linux, CloudLinux, CentOS, RHEL and"
    log_error "Oracle Linux, versions 7 to 10."
    log_error ""
    log_error "Refusing rather than installing part of it. On another"
    log_error "distribution the authentication logs are named differently, the"
    log_error "package manager is not yum or dnf, and the unit and cron paths"
    log_error "these services use are not guaranteed to exist. The result would"
    log_error "be files in place and a firewall that does not come up."
    log_error ""
    if [ "${HG_ALLOW_UNSUPPORTED:-0}" = "1" ]; then
        log_warn "HG_ALLOW_UNSUPPORTED=1 is set; continuing anyway."
        log_warn "You are responsible for checking that the firewall starts,"
        log_warn "that the daemon finds your authentication logs, and that the"
        log_warn "systemd units work as installed."
        echo ""
    else
        log_error "To install anyway, knowing the above:"
        log_error "  HG_ALLOW_UNSUPPORTED=1 bash install.sh"
        exit 1
    fi
fi

# systemd is not optional: both services are units, and nothing starts without
# it. Checked here rather than left to fail after the files are in place.
if [ ! -d /run/systemd/system ]; then
    log_error "systemd is not running this host."
    log_error "Both HostGuard Pro services are systemd units; without it"
    log_error "nothing would start after installation."
    if [ "${HG_ALLOW_UNSUPPORTED:-0}" = "1" ]; then
        log_warn "HG_ALLOW_UNSUPPORTED=1 is set; continuing without systemd."
        log_warn "You will need to start hostguard and hostguardd yourself."
    else
        log_error "To install anyway:  HG_ALLOW_UNSUPPORTED=1 bash install.sh"
        exit 1
    fi
fi

###############################################################################
# Who else manages this host's firewall
###############################################################################
#
# The uninstaller has checked for this since it was written; the installer,
# which is where the collision actually begins, did not. Two managers both
# inserting a jump at the head of INPUT gives a firewall whose behaviour
# depends on which service reloaded last - and that is a question of start
# order, so it changes on reboot.
#
# HostGuard Pro's own teardown is scoped to its own chains and sets and will not
# damage what it finds. The problem is not destruction, it is two things
# deciding the same question.

OTHER_FIREWALLS=""
CONFLICTING_FIREWALL=0
note_firewall() { OTHER_FIREWALLS="${OTHER_FIREWALLS}  - $1"$'\n'; }

# CSF is the one that cannot coexist: it is the same product category, it owns
# the same chains at the top of INPUT, and it reads the same logs to block the
# same addresses. Everything else in this list is something to know about, not
# something to stop for - firewalld and Docker are routinely present on a host
# that also wants this, and refusing to install unattended because fail2ban is
# running turns a warning into an outage for anyone using Ansible or a
# curl-to-bash install.
if command -v csf &>/dev/null || [ -f /etc/csf/csf.conf ]; then
    note_firewall "CSF (ConfigServer Security & Firewall) - it does the same job as this"
    CONFLICTING_FIREWALL=1
fi
if systemctl is-active firewalld &>/dev/null; then
    note_firewall "firewalld (active)"
fi
if systemctl is-active ufw &>/dev/null || (command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -qi '^Status: active'); then
    note_firewall "ufw (active)"
fi
if systemctl is-active shorewall &>/dev/null; then
    note_firewall "shorewall (active)"
fi
if systemctl is-active nftables &>/dev/null; then
    note_firewall "nftables (active)"
fi
if systemctl is-active fail2ban &>/dev/null; then
    note_firewall "fail2ban (active) - it blocks addresses too, from the same logs"
fi
if command -v iptables &>/dev/null && iptables -S 2>/dev/null | grep -q -- '-j DOCKER'; then
    note_firewall "Docker - it owns the FORWARD policy, so set FORWARD_POLICY=ACCEPT"
fi

if [ -n "$OTHER_FIREWALLS" ]; then
    echo ""
    log_warn "Something else is already managing this host's firewall:"
    printf '%s' "$OTHER_FIREWALLS"
    echo ""
    log_warn "Running two firewall managers means both insert rules at the top of"
    log_warn "INPUT, and whichever reloaded last decides. That is a question of"
    log_warn "service start order, so it changes on reboot."
    echo ""

    if [ "$CONFLICTING_FIREWALL" -eq 1 ]; then
        # Only CSF gets in the way of the install itself.
        if [ "${HG_ALLOW_OTHER_FIREWALL:-0}" = "1" ]; then
            log_warn "HG_ALLOW_OTHER_FIREWALL=1 is set; installing alongside CSF anyway."
        elif [ -t 0 ]; then
            read -r -p "CSF is present. Continue anyway? (y/N): " FW_CONFIRM
            if [ "$FW_CONFIRM" != "y" ] && [ "$FW_CONFIRM" != "Y" ]; then
                log_error "Aborted."
                exit 1
            fi
        else
            log_error "CSF is installed, and it does the same job as HostGuard Pro."
            log_error "Refusing to install both unattended. Remove CSF, or:"
            log_error "  HG_ALLOW_OTHER_FIREWALL=1 bash install.sh"
            exit 1
        fi
    else
        log_warn "Continuing. Confirm after installing that the other manager is"
        log_warn "still doing what you expect:  iptables -S | head"
        echo ""
    fi
fi

###############################################################################
# Compatibility test
###############################################################################

log_step "Running compatibility checks..."

COMPAT_ERRORS=0

# iptables
if command -v iptables &>/dev/null; then
    IPT_VER=$(iptables --version 2>/dev/null | head -1)
    log_info "iptables found: ${IPT_VER}"
else
    log_error "iptables not found. Install iptables first."
    COMPAT_ERRORS=$((COMPAT_ERRORS + 1))
fi

# ip6tables
if command -v ip6tables &>/dev/null; then
    log_info "ip6tables found."
else
    log_warn "ip6tables not found. IPv6 support will be unavailable."
fi

# ipset
if command -v ipset &>/dev/null; then
    IPSET_VER=$(ipset --version 2>/dev/null | head -1)
    log_info "ipset found: ${IPSET_VER}"
else
    log_warn "ipset not found. Installing..."
    yum install -y ipset &>/dev/null || dnf install -y ipset &>/dev/null || apt-get install -y ipset &>/dev/null || true
    if command -v ipset &>/dev/null; then
        log_info "ipset installed successfully."
    else
        log_warn "ipset installation failed. Large blocklists will use individual iptables rules (slower)."
    fi
fi

# Kernel modules behind the matches and targets the rules use. Most kernels
# load these on demand, so a failure here is not fatal on its own; the probe
# below is what decides whether a match actually works.
for mod in ip_tables iptable_filter nf_conntrack ip_conntrack \
           xt_conntrack xt_state xt_limit xt_recent xt_connlimit xt_hl \
           xt_set ip_set xt_LOG xt_REJECT; do
    modprobe "$mod" 2>/dev/null || true
done

# Probe every match and target the firewall builds with, by adding a real rule
# to a scratch chain and removing it again. A match that is missing here would
# otherwise surface as a rule that silently fails to load at runtime.
log_step "Probing iptables matches..."

HG_PROBE="_hg_probe_$$"
iptables -F "$HG_PROBE" 2>/dev/null || true
iptables -X "$HG_PROBE" 2>/dev/null || true

if iptables -N "$HG_PROBE" 2>/dev/null; then
    probe() {
        # probe <label> <required|optional> <feature it serves> <rule arguments...>
        local label="$1"; local required="$2"; local feature="$3"; shift 3
        if iptables -A "$HG_PROBE" "$@" 2>/dev/null; then
            iptables -D "$HG_PROBE" "$@" 2>/dev/null
            log_info "  ${label}: available"
            return 0
        fi
        if [ "$required" = "required" ]; then
            log_error "  ${label}: NOT available - ${feature} cannot work"
            COMPAT_ERRORS=$((COMPAT_ERRORS + 1))
        else
            log_warn "  ${label}: not available - ${feature} will not work"
        fi
        return 1
    }

    # Connection tracking. One of the two spellings must work, or the firewall
    # cannot tell an established connection from a new one.
    CONNTRACK_OK=0
    if iptables -A "$HG_PROBE" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null; then
        iptables -D "$HG_PROBE" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null
        log_info "  conntrack match: available"
        CONNTRACK_OK=1
    elif iptables -A "$HG_PROBE" -m state --state NEW -j ACCEPT 2>/dev/null; then
        iptables -D "$HG_PROBE" -m state --state NEW -j ACCEPT 2>/dev/null
        log_warn "  conntrack match: unavailable, but the older state match works"
        log_warn "  Set USE_CONNTRACK=0 in hostguard.conf"
        CONNTRACK_OK=1
    fi
    if [ "$CONNTRACK_OK" -eq 0 ]; then
        log_error "  Neither the conntrack nor the state match is available."
        COMPAT_ERRORS=$((COMPAT_ERRORS + 1))
    fi

    probe "limit match"     optional "ICMP rate limiting and SYNFLOOD" \
          -m limit --limit 5/min -j ACCEPT
    probe "recent match"    optional "PORTFLOOD" \
          -m recent --set --name hgprobe --rsource -j ACCEPT
    probe "connlimit match" optional "CONNLIMIT" \
          -p tcp -m connlimit --connlimit-above 5 -j ACCEPT
    probe "LOG target"      optional "DROP_LOGGING" \
          -m limit --limit 1/min -j LOG
    probe "REJECT target"   optional "DROP_ACTION=REJECT" \
          -j REJECT

    probe "comment match"   optional "the block notice redirect" \
          -m comment --comment hgprobe -j ACCEPT

    # The set match and the SET target both need a set to point at, so probe
    # with a scratch one. The two are separate kernel modules: a host can have
    # the match and not the target, which would leave port scan detection
    # counting sources it can never block.
    if command -v ipset &>/dev/null; then
        if ipset create _hg_probe_set hash:net family inet timeout 0 2>/dev/null; then
            probe "set match" optional "ipset acceleration of the IP lists" \
                  -m set --match-set _hg_probe_set src -j ACCEPT
            probe "SET target" optional "port scan detection" \
                  -j SET --add-set _hg_probe_set src --timeout 60 --exist
            ipset destroy _hg_probe_set 2>/dev/null || true
        fi
    fi

    iptables -F "$HG_PROBE" 2>/dev/null || true
    iptables -X "$HG_PROBE" 2>/dev/null || true

    # The block notice redirect lives in the nat table, which is a separate
    # table from everything probed above and may be absent on a stripped
    # kernel.
    HG_NAT_PROBE="_hg_nat_$$"
    if iptables -t nat -N "$HG_NAT_PROBE" 2>/dev/null; then
        if iptables -t nat -A "$HG_NAT_PROBE" -p tcp --dport 80 \
                    -j REDIRECT --to-port 8899 2>/dev/null; then
            iptables -t nat -D "$HG_NAT_PROBE" -p tcp --dport 80 \
                     -j REDIRECT --to-port 8899 2>/dev/null
            log_info "  nat REDIRECT target: available"
        else
            log_warn "  nat REDIRECT target: not available - the block notice service will not work"
        fi
        iptables -t nat -F "$HG_NAT_PROBE" 2>/dev/null || true
        iptables -t nat -X "$HG_NAT_PROBE" 2>/dev/null || true
    else
        log_warn "  nat table: unavailable - the block notice service will not work"
    fi

    # IPv6 filtering uses a separate binary and its own kernel modules.
    if command -v ip6tables &>/dev/null; then
        if ip6tables -L -n &>/dev/null; then
            log_info "  ip6tables: available"

            # The hop-limit match, which is what restricts neighbour discovery
            # to on-link senders. Probed because without it the firewall has to
            # accept ND unrestricted - IPv6 does not work otherwise - and that
            # is a decision an operator should know was taken.
            HG6_PROBE="_hg6_probe_$$"
            if ip6tables -N "$HG6_PROBE" 2>/dev/null; then
                if ip6tables -A "$HG6_PROBE" -p icmpv6 --icmpv6-type 135                              -m hl --hl-eq 255 -j ACCEPT 2>/dev/null; then
                    ip6tables -D "$HG6_PROBE" -p icmpv6 --icmpv6-type 135                               -m hl --hl-eq 255 -j ACCEPT 2>/dev/null
                    log_info "  ip6tables hl match: available"
                else
                    log_warn "  ip6tables hl match: NOT available"
                    log_warn "    Neighbour discovery will be accepted without a"
                    log_warn "    hop-limit check, because IPv6 needs it to work."
                    log_warn "    Load xt_hl to close that: modprobe xt_hl"
                fi
                ip6tables -F "$HG6_PROBE" 2>/dev/null || true
                ip6tables -X "$HG6_PROBE" 2>/dev/null || true
            fi
        else
            log_warn "  ip6tables: present but not usable - leave IPV6=0"
        fi
    else
        log_warn "  ip6tables: not installed - leave IPV6=0"
    fi

    iptables -F "$HG_PROBE" 2>/dev/null || true
    iptables -X "$HG_PROBE" 2>/dev/null || true
else
    log_warn "Could not create a scratch chain; skipping match probe."
fi

# Perl check
if command -v perl &>/dev/null; then
    PERL_VER=$(perl -v 2>/dev/null | grep version | head -1)
    log_info "Perl found."
else
    log_error "Perl not found. Required for HostGuard Pro."
    COMPAT_ERRORS=$((COMPAT_ERRORS + 1))
fi

# sendmail for alerts
if [ -x /usr/sbin/sendmail ]; then
    log_info "sendmail found."
else
    log_warn "sendmail not found. Email alerts will be unavailable."
fi

# Syntax-check every script before it is copied into place. A script that does
# not compile would leave the firewall or the daemon silently inoperative.
if command -v perl &>/dev/null; then
    # Globbed rather than listed. A list goes stale the moment a module is
    # added, and a module that is not checked here is one that can reach the
    # system without compiling.
    for src in \
        "${INSTALL_DIR}"/usr/local/hostguard/lib/*.pm \
        "${INSTALL_DIR}/usr/local/hostguard/bin/hostguard" \
        "${INSTALL_DIR}/usr/local/hostguard/bin/hostguardd" \
        "${INSTALL_DIR}/whm/cgi/hostguard/hostguard.cgi"
    do
        [ -f "$src" ] || continue
        if ! perl -I "${INSTALL_DIR}/usr/local/hostguard/lib" -c "$src" &>/dev/null; then
            log_error "Syntax check failed: $src"
            perl -I "${INSTALL_DIR}/usr/local/hostguard/lib" -c "$src" 2>&1 | head -5
            COMPAT_ERRORS=$((COMPAT_ERRORS + 1))
        fi
    done
    if [ "$COMPAT_ERRORS" -eq 0 ]; then
        log_info "Perl syntax checks passed."
    fi

fi

if [ "$COMPAT_ERRORS" -gt 0 ]; then
    log_error "Compatibility checks failed with $COMPAT_ERRORS error(s). Cannot continue."
    exit 1
fi

log_info "All compatibility checks passed."
echo ""

###############################################################################
# Create directories
###############################################################################

# Where HostGuard Pro is already present, stop the daemon before its binaries
# and libraries are replaced, so it never runs against half-written modules.
IS_UPGRADE=0
if [ -x /usr/local/hostguard/bin/hostguard ]; then
    IS_UPGRADE=1
    PREV_VERSION=$(cat /etc/hostguard/version.txt 2>/dev/null || echo "unknown")
    log_step "Existing installation detected (version ${PREV_VERSION}); upgrading."
    if command -v systemctl &>/dev/null && systemctl is-active hostguardd &>/dev/null; then
        log_info "Stopping hostguardd for upgrade..."
        systemctl stop hostguardd || true
        RESTART_DAEMON=1
    fi
fi

log_step "Creating directories..."

mkdir -p /etc/hostguard
mkdir -p /usr/local/hostguard/bin
mkdir -p /usr/local/hostguard/lib
mkdir -p /usr/local/hostguard/tpl
mkdir -p /var/lib/hostguard
mkdir -p /var/lib/hostguard/blocklists
mkdir -p /var/lib/hostguard/geo
mkdir -p /var/log/hostguard

# Runtime state and logs are root-only. The files inside are written with
# restrictive modes; these keep the directories themselves from being listed
# by other users.
chmod 700 /var/lib/hostguard
chmod 700 /var/lib/hostguard/blocklists
chmod 700 /var/lib/hostguard/geo
chmod 750 /var/log/hostguard
chown root:root /var/lib/hostguard /var/lib/hostguard/blocklists \
                /var/lib/hostguard/geo /var/log/hostguard

###############################################################################
# Install config files (preserve existing)
###############################################################################

log_step "Installing configuration files..."

install_config() {
    local src="$1"
    local dst="$2"
    if [ -f "$dst" ]; then
        log_warn "Config exists, preserving: $dst"
        cp "$src" "${dst}.dist"
    else
        cp "$src" "$dst"
        log_info "Installed: $dst"
    fi
}

install_config "${INSTALL_DIR}/etc/hostguard/hostguard.conf" "/etc/hostguard/hostguard.conf"
install_config "${INSTALL_DIR}/etc/hostguard/allow.conf"     "/etc/hostguard/allow.conf"
install_config "${INSTALL_DIR}/etc/hostguard/deny.conf"      "/etc/hostguard/deny.conf"
install_config "${INSTALL_DIR}/etc/hostguard/ignore.conf"    "/etc/hostguard/ignore.conf"
install_config "${INSTALL_DIR}/etc/hostguard/blocklists.conf" "/etc/hostguard/blocklists.conf"
install_config "${INSTALL_DIR}/etc/hostguard/patterns.conf"   "/etc/hostguard/patterns.conf"
install_config "${INSTALL_DIR}/etc/hostguard/watch.conf"      "/etc/hostguard/watch.conf"
install_config "${INSTALL_DIR}/etc/hostguard/cluster.conf"    "/etc/hostguard/cluster.conf"
install_config "${INSTALL_DIR}/etc/hostguard/procignore.conf" "/etc/hostguard/procignore.conf"

# An upgrade over an installation from before these settings existed leaves a
# hostguard.conf without them. Every new setting has a safe default in code, so
# the firewall still runs - but the file no longer documents what can be
# configured, and .dist is where to look for the rest.
if ! grep -q '^GEO_ENABLE' /etc/hostguard/hostguard.conf 2>/dev/null; then
    log_warn "hostguard.conf predates this version's settings."
    log_warn "New features are off by default; see hostguard.conf.dist for them."
fi

# Set strict permissions on config files
# The daemon's unit makes deny.conf and allow.conf writable individually
# rather than the whole of /etc/hostguard, and systemd cannot bind-mount a
# file that is not there: without both of these the service refuses to start.
# install_config leaves an existing file alone, so this covers a host where
# one was deleted rather than emptied.
for conf in /etc/hostguard/deny.conf /etc/hostguard/allow.conf; do
    if [ ! -f "$conf" ]; then
        : > "$conf"
        log_info "Created empty $conf (the daemon's unit needs it to exist)."
    fi
done

chmod 600 /etc/hostguard/*.conf
chown root:root /etc/hostguard/*.conf

# The stylesheet and icon are served to a browser and must stay readable; every
# other installed file is root-only. Restated after the umask above so a future
# reader does not have to infer it.


###############################################################################
# Snapshot the rules that were here first
###############################################################################
#
# Taken before HostGuard Pro is ever started, so there is something to compare
# against and something to restore from. It is not used automatically - putting
# an old ruleset back over a live one unasked would be its own hazard - but
# without it an operator who wants to back out has nothing to back out to.
#
# Written once. A second install must not overwrite the record of what the host
# looked like before the first one.
if [ ! -f /var/lib/hostguard/preinstall-rules.v4 ]; then
    if command -v iptables-save &>/dev/null; then
        if iptables-save > /var/lib/hostguard/preinstall-rules.v4 2>/dev/null; then
            chmod 600 /var/lib/hostguard/preinstall-rules.v4
            log_info "Saved the existing IPv4 ruleset to /var/lib/hostguard/preinstall-rules.v4"
        else
            rm -f /var/lib/hostguard/preinstall-rules.v4
            log_warn "Could not save the existing IPv4 ruleset."
        fi
    fi
fi
if [ ! -f /var/lib/hostguard/preinstall-rules.v6 ]; then
    if command -v ip6tables-save &>/dev/null; then
        if ip6tables-save > /var/lib/hostguard/preinstall-rules.v6 2>/dev/null; then
            chmod 600 /var/lib/hostguard/preinstall-rules.v6
            log_info "Saved the existing IPv6 ruleset to /var/lib/hostguard/preinstall-rules.v6"
        else
            rm -f /var/lib/hostguard/preinstall-rules.v6
            log_warn "Could not save the existing IPv6 ruleset."
        fi
    fi
fi

###############################################################################
# IPv6
###############################################################################
#
# IPV6 ships as 0, which is right for a host with no IPv6 and a complete bypass
# of the product for a host that has it: with IPV6=0 no ip6tables chain is
# built and none is attached, so the v6 policy stays ACCEPT with no rules -
# every port open, and no allowlist, denylist, block list, country rule or
# temporary block applying to a single packet.
#
# Whether that default is right is answerable here and nowhere else, so it is
# answered here rather than left to be discovered. Only a fresh install is
# changed; an existing hostguard.conf is the operator's.
if [ "$IS_UPGRADE" != "1" ] \
   && command -v ip6tables &>/dev/null && ip6tables -L -n &>/dev/null \
   && ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
    if grep -q '^IPV6 = "0"' /etc/hostguard/hostguard.conf 2>/dev/null; then
        sed -i 's/^IPV6 = "0"/IPV6 = "1"/' /etc/hostguard/hostguard.conf
        log_info "This host has a global IPv6 address and usable ip6tables;"
        log_info "  set IPV6=1 so IPv6 is filtered too. Check TCP6_IN and"
        log_info "  UDP6_IN before disabling TESTING mode."
    fi
elif command -v ip &>/dev/null \
     && ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
    log_warn "This host has a global IPv6 address but ip6tables is unusable."
    log_warn "IPv6 will not be filtered at all: every port is reachable over it"
    log_warn "and no block applies. Install and verify ip6tables, then set"
    log_warn "IPV6=1 in /etc/hostguard/hostguard.conf."
fi

# The cluster secret is not generated here. A key created at install time
# would differ on every member, and a cluster whose members cannot
# authenticate to each other is worse than one that is plainly not set up.
# See cluster.conf for how to generate and distribute one.
if [ -f /etc/hostguard/cluster.key ]; then
    chmod 600 /etc/hostguard/cluster.key
    chown root:root /etc/hostguard/cluster.key
fi

###############################################################################
# Install binaries and libraries
###############################################################################

log_step "Installing binaries and libraries..."

# Perl modules
cp "${INSTALL_DIR}"/usr/local/hostguard/lib/*.pm /usr/local/hostguard/lib/
chmod 644 /usr/local/hostguard/lib/*.pm

# Every module must load before anything is started. A module that fails to
# compile - a partial copy, a Perl older than expected - would otherwise show
# up as a daemon that refuses to start with no obvious cause.
for mod in /usr/local/hostguard/lib/*.pm; do
    if ! perl -I /usr/local/hostguard/lib -c "$mod" >/dev/null 2>&1; then
        log_error "Module failed to compile: $mod"
        perl -I /usr/local/hostguard/lib -c "$mod" 2>&1 | head -5
        exit 1
    fi
done
log_info "$(ls -1 /usr/local/hostguard/lib/*.pm | wc -l) Perl modules installed and verified."

# CLI tool
cp "${INSTALL_DIR}/usr/local/hostguard/bin/hostguard" /usr/local/hostguard/bin/hostguard
chmod 755 /usr/local/hostguard/bin/hostguard

# Daemon
cp "${INSTALL_DIR}/usr/local/hostguard/bin/hostguardd" /usr/local/hostguard/bin/hostguardd
chmod 755 /usr/local/hostguard/bin/hostguardd

# Templates
# Alert templates.
#
# An edited template is an administrator's own wording, so an upgrade leaves it
# alone and writes the new version alongside as .dist. A template that is
# missing entirely is installed, so a new notice kind arrives with its text on
# an upgrade rather than silently falling back to the built-in plain text.
for tpl in "${INSTALL_DIR}"/usr/local/hostguard/tpl/*.txt; do
    name=$(basename "$tpl")
    dest="/usr/local/hostguard/tpl/${name}"
    if [ -f "$dest" ]; then
        if cmp -s "$tpl" "$dest"; then
            cp "$tpl" "$dest"
        else
            cp "$tpl" "${dest}.dist"
            log_warn "Template edited locally, preserving: ${name} (new version: ${name}.dist)"
        fi
    else
        cp "$tpl" "$dest"
    fi
done
chmod 644 /usr/local/hostguard/tpl/*.txt
log_info "$(ls -1 /usr/local/hostguard/tpl/*.txt | grep -vc '\.dist$') alert templates installed."

# Create symlinks for convenience
ln -sf /usr/local/hostguard/bin/hostguard /usr/sbin/hostguard
ln -sf /usr/local/hostguard/bin/hostguardd /usr/sbin/hostguardd

# Also create 'myfw' alias as per spec
ln -sf /usr/local/hostguard/bin/hostguard /usr/sbin/myfw

log_info "Binaries installed."

###############################################################################
# Initialize runtime data
###############################################################################

log_step "Initializing runtime data..."

touch /var/lib/hostguard/tempblock.dat
touch /var/lib/hostguard/tempallow.dat
touch /var/lib/hostguard/block_history.dat
chmod 600 /var/lib/hostguard/*.dat
chown root:root /var/lib/hostguard/*.dat

touch /var/log/hostguard/daemon.log
chmod 640 /var/log/hostguard/daemon.log
chown root:root /var/log/hostguard/daemon.log

###############################################################################
# Install systemd services
###############################################################################

log_step "Installing systemd services..."

cp "${INSTALL_DIR}/systemd/hostguard.service"  /etc/systemd/system/hostguard.service
cp "${INSTALL_DIR}/systemd/hostguardd.service" /etc/systemd/system/hostguardd.service
chmod 644 /etc/systemd/system/hostguard.service
chmod 644 /etc/systemd/system/hostguardd.service

# Both units are sandboxed with directives that arrived across several systemd
# releases. An older systemd does not fail on one it does not recognise, it
# logs a warning and ignores it, so the service still starts with less
# confinement than the unit asks for. Say so at install time rather than
# leaving it to be discovered.
#
#   229  ProtectSystem=strict
#   231  ReadWritePaths
#   232  ProtectKernelTunables, ProtectControlGroups, RestrictRealtime
#   235  RestrictNamespaces, LockPersonality
#   247  ProtectClock, ProtectProc
SYSTEMD_VER=$(systemctl --version 2>/dev/null | head -1 | awk '{print $2}' | tr -cd '0-9')
if [ -n "$SYSTEMD_VER" ]; then
    if [ "$SYSTEMD_VER" -lt 232 ]; then
        log_warn "systemd ${SYSTEMD_VER} predates most of the sandboxing in the"
        log_warn "unit files. The services will run, but with less confinement"
        log_warn "than intended. Check what took effect with:"
        log_warn "  systemd-analyze security hostguardd.service"
    elif [ "$SYSTEMD_VER" -lt 247 ]; then
        log_info "systemd ${SYSTEMD_VER}: most sandboxing applies; ProtectClock"
        log_info "and ProtectProc need 247 and will be ignored."
    else
        log_info "systemd ${SYSTEMD_VER}: full unit sandboxing supported."
    fi
fi

# Install logrotate
cp "${INSTALL_DIR}/systemd/hostguard.logrotate" /etc/logrotate.d/hostguard
chmod 644 /etc/logrotate.d/hostguard

systemctl daemon-reload

# Enable services
systemctl enable hostguard.service
systemctl enable hostguardd.service

log_info "Systemd services installed and enabled."

###############################################################################
# Auto-detect server IPs and add to ignore list
###############################################################################

log_step "Detecting server IP addresses..."

SERVER_IPS=$(ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[\d.]+' | sort -u)
for sip in $SERVER_IPS; do
    if ! grep -q "^${sip}$" /etc/hostguard/ignore.conf 2>/dev/null; then
        echo "$sip # Server IP (auto-detected)" >> /etc/hostguard/ignore.conf
        log_info "Added server IP to ignore list: $sip"
    fi
    if ! grep -q "^${sip}$" /etc/hostguard/allow.conf 2>/dev/null; then
        echo "$sip # Server IP (auto-detected)" >> /etc/hostguard/allow.conf
        log_info "Added server IP to allowlist: $sip"
    fi
done

# Determine the administrator's client IP so the installation cannot lock them
# out. The SSH environment variables are consulted first because who(1) reports
# nothing under sudo, in a non-tty session or under automation, which is
# precisely when this safeguard matters.
ADMIN_IP=""
if [ -n "${SSH_CONNECTION:-}" ]; then
    ADMIN_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
elif [ -n "${SSH_CLIENT:-}" ]; then
    ADMIN_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
fi
if [ -z "$ADMIN_IP" ]; then
    ADMIN_IP=$(who am i 2>/dev/null | grep -oP '\([\d.]+\)' | tr -d '()' | head -1)
fi
# Accept only a plain IPv4 or IPv6 literal.
if ! echo "$ADMIN_IP" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$'; then
    ADMIN_IP=""
fi
if [ -z "$ADMIN_IP" ]; then
    log_warn "Could not detect your client IP. If you are connecting remotely,"
    log_warn "add it by hand before disabling TESTING mode:"
    log_warn "  hostguard -a <your.ip.here> 'admin'"
fi
if [ -n "$ADMIN_IP" ] && [ "$ADMIN_IP" != "" ]; then
    if ! grep -q "^${ADMIN_IP}$" /etc/hostguard/allow.conf 2>/dev/null; then
        echo "$ADMIN_IP # Admin IP (auto-detected at install)" >> /etc/hostguard/allow.conf
        log_info "Added admin SSH IP to allowlist: $ADMIN_IP"
    fi
    if ! grep -q "^${ADMIN_IP}$" /etc/hostguard/ignore.conf 2>/dev/null; then
        echo "$ADMIN_IP # Admin IP (auto-detected at install)" >> /etc/hostguard/ignore.conf
    fi
fi

###############################################################################
# Install WHM plugin
###############################################################################

if [ "$HAS_CPANEL" -eq 1 ]; then
    log_step "Installing WHM plugin..."

    WHM_CGI="/usr/local/cpanel/whostmgr/docroot/cgi"
    WHM_PLUGINS="/usr/local/cpanel/whostmgr/docroot/addon_plugins"

    # Create CGI directory
    mkdir -p "${WHM_CGI}/hostguard"

    # Install CGI file
    cp "${INSTALL_DIR}/whm/cgi/hostguard/hostguard.cgi" "${WHM_CGI}/hostguard/hostguard.cgi"
    chmod 755 "${WHM_CGI}/hostguard/hostguard.cgi"
    chown root:root "${WHM_CGI}/hostguard/hostguard.cgi"

    # Stylesheet. Served from the same directory as the CGI and linked with a
    # ?v= carrying the version, so an upgrade fetches the new one instead of
    # styling new markup with a cached copy of the old.
    #
    # The pair must travel together: markup from one version with a stylesheet
    # from another renders wrong in ways that look like a bug in the firewall.
    cp "${INSTALL_DIR}/whm/cgi/hostguard/hostguard.css" "${WHM_CGI}/hostguard/hostguard.css"
    chmod 644 "${WHM_CGI}/hostguard/hostguard.css"
    chown root:root "${WHM_CGI}/hostguard/hostguard.css"

    # Install plugin icon
    cat > "${WHM_CGI}/hostguard/hostguard_icon.svg" << 'SVGEOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect width="64" height="64" rx="14" fill="#10b981"/>
  <path d="M32 15 L45 21 V32 C45 40 39 46 32 49 C25 46 19 40 19 32 V21 Z"
        fill="none" stroke="#ffffff" stroke-width="3.4"
        stroke-linejoin="round" stroke-linecap="round"/>
  <path d="M26.5 31.5 L30.5 35.5 L38 27.5"
        fill="none" stroke="#ffffff" stroke-width="3.4"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>
SVGEOF
    chmod 644 "${WHM_CGI}/hostguard/hostguard_icon.svg"

    # Register the WHM plugin using appconfig
    if [ -x /usr/local/cpanel/bin/register_appconfig ]; then
        # Use appconfig registration (modern cPanel)
        # A private temporary file, not a predictable name in /tmp.
        #
        # A fixed name in a world-writable directory, written as root by a
        # command that follows symlinks, is a bad pattern even where it is not
        # exploitable - fs.protected_symlinks is on by default everywhere this
        # runs and stops root following a user-owned symlink in /tmp. mktemp
        # costs nothing and removes the question.
        HG_APPCONF=$(mktemp /var/lib/hostguard/appconfig.XXXXXX)
        cp "${INSTALL_DIR}/whm/addon_plugins/hostguard.conf" "$HG_APPCONF"
        # Update icon path
        sed -i 's|icon=hostguard_icon.png|icon=hostguard/hostguard_icon.svg|' "$HG_APPCONF"
        /usr/local/cpanel/bin/register_appconfig "$HG_APPCONF"
        rm -f "$HG_APPCONF"
        log_info "WHM plugin registered via appconfig."
    else
        # Fallback: copy to addon_plugins directory
        mkdir -p "$WHM_PLUGINS"
        cp "${INSTALL_DIR}/whm/addon_plugins/hostguard.conf" "${WHM_PLUGINS}/hostguard.conf"
        # Reference the icon installed above.
        sed -i 's|icon=hostguard_icon.png|icon=hostguard/hostguard_icon.svg|' "${WHM_PLUGINS}/hostguard.conf"
        # Create the legacy addon CGI symlink
        ln -sf "${WHM_CGI}/hostguard/hostguard.cgi" "${WHM_CGI}/addon_hostguard.cgi"
        log_info "WHM plugin registered via addon_plugins."
    fi

    # Register ACL
    if [ -d /usr/local/cpanel/whostmgr/addonfeatures ]; then
        echo "hostguard:HostGuard Pro" > /usr/local/cpanel/whostmgr/addonfeatures/hostguard
    fi

    log_info "WHM plugin installed."
else
    log_warn "cPanel not found. WHM plugin not installed."
    log_info "You can manage HostGuard Pro via CLI: hostguard --help"
fi

###############################################################################
# Version file
###############################################################################

echo "$VERSION" > /etc/hostguard/version.txt
chmod 644 /etc/hostguard/version.txt

# Bring the daemon back up if it was stopped for the installation.
if [ "${RESTART_DAEMON:-0}" -eq 1 ]; then
    log_info "Restarting hostguardd after upgrade..."
    systemctl start hostguardd || log_warn "Could not restart hostguardd; start it by hand."
fi

###############################################################################
# Summary
###############################################################################

echo ""
echo "=============================================="
echo "  HostGuard Pro v${VERSION} - Installed!"
echo "=============================================="
echo ""
log_info "Configuration:  /etc/hostguard/"
log_info "Binaries:       /usr/local/hostguard/bin/"
log_info "Libraries:      /usr/local/hostguard/lib/"
log_info "Runtime data:   /var/lib/hostguard/"
log_info "Logs:           /var/log/hostguard/"
echo ""
log_info "CLI commands:"
echo "  hostguard -e          # Enable firewall"
echo "  hostguard -x          # Disable firewall"
echo "  hostguard -r          # Reload rules"
echo "  hostguard -s          # Show status"
echo "  hostguard -a <ip>     # Allow IP"
echo "  hostguard -d <ip>     # Deny IP"
echo "  hostguard -l          # List temp blocks"
echo "  hostguard --help      # Full help"
echo ""
log_info "Also available as: myfw (alias)"
echo ""

if [ "$HAS_CPANEL" -eq 1 ]; then
    log_info "WHM: Log into WHM and look for 'HostGuard Pro' in the left menu."
    echo ""
fi

log_warn "IMPORTANT: TESTING mode is ON by default."
log_warn "While TESTING=1, /etc/cron.d/hostguard_testing clears the firewall"
log_warn "every TESTING_INTERVAL minutes, so a ruleset that locks you out"
log_warn "cannot lock you out for long."
echo ""
log_info "To start the firewall now:"
echo "  systemctl start hostguard"
echo ""
log_info "Then, once you have confirmed you can still log in:"
echo "  vi /etc/hostguard/hostguard.conf     # set TESTING = \"0\""
echo "  hostguard -r                         # rebuild and remove the cron"
echo "  hostguard -s                         # confirm the cron is gone"
echo "  systemctl start hostguardd"
echo ""
log_info "hostguard -r is what removes the auto-clear cron. Until it reports"
log_info "the cron removed, the firewall is still on a timer."
echo ""
log_info "Installation complete."
