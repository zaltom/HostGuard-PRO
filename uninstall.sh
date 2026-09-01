#!/bin/bash
###############################################################################
# HostGuard Pro - Uninstallation Script
# Run as root to completely remove HostGuard Pro
###############################################################################
set -e

# The configuration backup below contains cluster.key.
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo ""
echo "=============================================="
echo "  HostGuard Pro - Uninstaller"
echo "=============================================="
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Must be run as root."
    exit 1
fi

###############################################################################
# Who else manages this host's firewall
###############################################################################
#
# HostGuard Pro is not necessarily the only thing writing iptables rules here.
# CSF, firewalld, ufw, shorewall, nftables and Docker all keep their own rules
# and, in several cases, their own default policies. This uninstaller removes
# what HostGuard Pro created and nothing else - in particular it does not
# touch default policies it cannot show HostGuard Pro changed - but the
# operator should know what else is running before removing a firewall.
OTHER_FIREWALLS=""
note_firewall() { OTHER_FIREWALLS="${OTHER_FIREWALLS}  - $1"$'\n'; }

if command -v csf &>/dev/null || [ -f /etc/csf/csf.conf ]; then
    note_firewall "CSF (ConfigServer Security & Firewall)"
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
    note_firewall "fail2ban (active; it keeps its own chains)"
fi
if command -v iptables &>/dev/null && iptables -S 2>/dev/null | grep -q -- '-j DOCKER'; then
    note_firewall "Docker (it owns the FORWARD policy and its own chains)"
fi

if [ -n "$OTHER_FIREWALLS" ]; then
    echo ""
    log_warn "Something else is managing this host's firewall:"
    printf '%s' "$OTHER_FIREWALLS"
    echo ""
    log_warn "Only HostGuard Pro's own chains, sets and rules will be removed."
    log_warn "Default policies are left alone unless HostGuard Pro recorded"
    log_warn "changing them. Check the above is still filtering afterwards:"
    log_warn "  iptables -S | head"
fi

# Confirm
echo ""
echo "This will completely remove HostGuard Pro from this server."
echo "Configuration files will be backed up to /root/hostguard_backup/"
echo ""
read -p "Continue? (y/N): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Aborted."
    exit 0
fi

###############################################################################
# Stop services
###############################################################################

log_info "Stopping services..."

# Stop daemon first
if systemctl is-active hostguardd &>/dev/null; then
    systemctl stop hostguardd
fi

# ...and stop it even where systemd is not what started it.
#
# "hostguard --start-daemon" runs the daemon directly on a host where systemd
# does not own the unit, and then "systemctl is-active" is false and this
# skipped it. The files were removed underneath a running root process: its
# modules already loaded, still writing to deleted paths, still trying to
# modify a firewall that no longer exists - and with /run/hostguardd.pid
# deleted a few lines further down, nothing left to find it by.
if [ -f /run/hostguardd.pid ]; then
    HGD_PID=$(cat /run/hostguardd.pid 2>/dev/null)
    case "$HGD_PID" in
        ''|*[!0-9]*) HGD_PID="" ;;
    esac
    # Confirm the pid is still the daemon before signalling it: a pid file
    # outlives the process that wrote it, and the number eventually belongs to
    # something else.
    if [ -n "$HGD_PID" ] && [ -r "/proc/$HGD_PID/cmdline" ] \
       && tr '\0' ' ' < "/proc/$HGD_PID/cmdline" | grep -q hostguardd; then
        log_info "Stopping hostguardd (PID $HGD_PID)..."
        kill -TERM "$HGD_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$HGD_PID" 2>/dev/null || break
            sleep 1
        done
        if kill -0 "$HGD_PID" 2>/dev/null; then
            log_warn "hostguardd did not stop; sending KILL."
            kill -KILL "$HGD_PID" 2>/dev/null || true
            sleep 1
        fi
    fi
fi

# Nothing is removed while a daemon is still running.
if pgrep -f '/usr/local/hostguard/bin/hostguardd' >/dev/null 2>&1; then
    echo -e "${RED}[ERROR]${NC} A hostguardd process is still running."
    echo "Removing the installation underneath it would leave a root daemon"
    echo "with no files, no pid file and no way to manage it. Stop it first:"
    echo "  pkill -f /usr/local/hostguard/bin/hostguardd"
    exit 1
fi

# Stop and flush firewall
if systemctl is-active hostguard &>/dev/null; then
    systemctl stop hostguard
fi

# Extra safety: flush our rules directly
if command -v iptables &>/dev/null; then
    # Chains are discovered from iptables rather than listed here.
    #
    # A hand-maintained list of chain names would fall behind the code, and
    # this is the fallback for exactly the case where the service could not be
    # stopped - so a name it missed would be one nothing else has removed.
    # Discovery by prefix cannot fall behind.
    #
    # A jump can appear more than once if a run was interrupted, so each is
    # deleted in a loop.
    #
    # -F before -X on every chain first, then delete: a chain that another
    # HostGuard chain still jumps to cannot be deleted until that one is empty.
    hg_chains() {
        "$1" -S 2>/dev/null \
            | sed -n 's/^-N \(HOSTGUARD[A-Za-z0-9_]*\).*/\1/p' \
            | sort -u
    }

    for ipt in iptables ip6tables; do
        command -v "$ipt" &>/dev/null || continue
        chains=$(hg_chains "$ipt")
        [ -n "$chains" ] || continue

        for chain in $chains; do
            for builtin in INPUT OUTPUT FORWARD; do
                for _ in 1 2 3 4 5 6 7 8 9 10; do
                    "$ipt" -D "$builtin" -j "$chain" 2>/dev/null || break
                done
            done
        done
        # Flush them all before deleting any, so cross-references are gone.
        for chain in $chains; do
            "$ipt" -F "$chain" 2>/dev/null || true
        done
        for chain in $chains; do
            "$ipt" -X "$chain" 2>/dev/null || true
        done
    done
    # Default policies are not reset.
    #
    # Setting INPUT, OUTPUT and FORWARD to ACCEPT here would open the host's
    # default policies on the way out, and leave them open until whatever else
    # manages this firewall happened to reload. HostGuard Pro sets one policy -
    # IPv4 FORWARD, from FORWARD_POLICY - and records what it replaced, so that
    # is the only one to put back. Stopping the service above has normally done
    # it already and removed the record; this covers an install whose service
    # could not be stopped.
    if [ -f /var/lib/hostguard/saved_policies ]; then
        while IFS='|' read -r family chain policy; do
            # The record is written by HostGuard Pro, but it is read here as
            # untrusted input all the same: only these chains and these
            # policies are ever set, whatever the file says.
            case "$chain"  in INPUT|OUTPUT|FORWARD) ;; *) continue ;; esac
            case "$policy" in ACCEPT|DROP)          ;; *) continue ;; esac

            case "$family" in
                inet)
                    if iptables -P "$chain" "$policy" 2>/dev/null; then
                        log_info "Restored the $chain policy to $policy."
                    fi
                    ;;
                inet6)
                    if ip6tables -P "$chain" "$policy" 2>/dev/null; then
                        log_info "Restored the IPv6 $chain policy to $policy."
                    fi
                    ;;
            esac
        done < /var/lib/hostguard/saved_policies
    fi
fi

# Destroy ipsets, discovered by prefix for the same reason the chains are.
#
# The hand-written list covered six sets and missed five kinds: hg_tempallow4,
# hg_tempallow6, hg_bogon4, the country sets (hgc_*, hgc6_*) and the staging
# sets a refresh leaves behind if it is interrupted (hgt_*). A country set can
# hold hundreds of thousands of ranges, so what survived an uninstall was not
# a stray name but real kernel memory, with nothing left on the host to explain
# it - and a name still in use blocks a later reinstall from creating a set of
# the same name with different parameters.
if command -v ipset &>/dev/null; then
    ipset list -n 2>/dev/null \
        | grep -E '^(hg_|hgb_|hgb6_|hgc_|hgc6_|hgt_)' \
        | while read -r hg_set; do
            ipset destroy "$hg_set" 2>/dev/null || true
        done
fi

log_info "Services stopped; HostGuard Pro's chains, sets and rules removed."

###############################################################################
# Disable and remove systemd services
###############################################################################

log_info "Removing systemd services..."

systemctl disable hostguard.service 2>/dev/null || true
systemctl disable hostguardd.service 2>/dev/null || true
rm -f /etc/systemd/system/hostguard.service
rm -f /etc/systemd/system/hostguardd.service
systemctl daemon-reload

# Remove cron
rm -f /etc/cron.d/hostguard_testing

# Remove logrotate
rm -f /etc/logrotate.d/hostguard

###############################################################################
# Remove WHM plugin
###############################################################################

log_info "Removing WHM plugin..."

# Unregister appconfig
if [ -x /usr/local/cpanel/bin/unregister_appconfig ]; then
    /usr/local/cpanel/bin/unregister_appconfig hostguard 2>/dev/null || true
fi

# Remove CGI files
rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/hostguard
rm -f /usr/local/cpanel/whostmgr/docroot/cgi/addon_hostguard.cgi

# Remove plugin config
rm -f /usr/local/cpanel/whostmgr/docroot/addon_plugins/hostguard.conf

# Remove ACL
rm -f /usr/local/cpanel/whostmgr/addonfeatures/hostguard

###############################################################################
# Backup config files
###############################################################################

log_info "Backing up configuration..."

BACKUP_DIR="/root/hostguard_backup/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
# The backup contains cluster.key. cp -a preserves its 0600, but the
# directories above it are created with whatever umask is in force, so they are
# tightened explicitly rather than left to it.
chmod 700 /root/hostguard_backup "$BACKUP_DIR"
cp -a /etc/hostguard/* "$BACKUP_DIR/" 2>/dev/null || true
log_info "Config backed up to: $BACKUP_DIR"

###############################################################################
# Remove files
###############################################################################

log_info "Removing installed files..."

rm -rf /etc/hostguard
rm -rf /usr/local/hostguard
rm -rf /var/lib/hostguard
rm -rf /var/log/hostguard
rm -f /usr/sbin/hostguard
rm -f /usr/sbin/hostguardd
rm -f /usr/sbin/myfw
rm -f /run/hostguardd.pid

# The notice redirect lives in the nat table and belongs to no chain that the
# teardown above removes, so it is deleted by its comment.
if command -v iptables &>/dev/null; then
    while iptables -t nat -S PREROUTING 2>/dev/null | grep -q 'hostguard-notice'; do
        rule=$(iptables -t nat -S PREROUTING | grep 'hostguard-notice' | head -1 | sed 's/^-A //')
        # shellcheck disable=SC2086
        iptables -t nat -D PREROUTING $rule 2>/dev/null || break
    done
fi

###############################################################################
# Done
###############################################################################

echo ""
echo "=============================================="
echo "  HostGuard Pro - Uninstalled"
echo "=============================================="
echo ""
log_info "All HostGuard Pro files have been removed."
log_info "HostGuard Pro's firewall rules have been removed."

# Verified rather than asserted.
HG_LEFT=""
if command -v iptables &>/dev/null && iptables -S 2>/dev/null | grep -q HOSTGUARD; then
    HG_LEFT="${HG_LEFT} iptables chains;"
fi
if command -v ip6tables &>/dev/null && ip6tables -S 2>/dev/null | grep -q HOSTGUARD; then
    HG_LEFT="${HG_LEFT} ip6tables chains;"
fi
if command -v ipset &>/dev/null \
   && ipset list -n 2>/dev/null | grep -qE '^(hg_|hgb_|hgb6_|hgc_|hgc6_|hgt_)'; then
    HG_LEFT="${HG_LEFT} ipsets;"
fi
if [ -n "$HG_LEFT" ]; then
    log_warn "Some HostGuard Pro objects could not be removed:${HG_LEFT}"
    log_warn "Inspect with: iptables -S | grep HOSTGUARD ; ipset list -n | grep ^hg"
fi
if [ -n "$OTHER_FIREWALLS" ]; then
    log_warn "Another firewall manager is present on this host. Confirm it is"
    log_warn "still filtering: iptables -S | head"
else
    log_warn "Nothing is filtering this host now unless another firewall is"
    log_warn "configured. Check with: iptables -S | head"
fi
log_info "Configuration backup: $BACKUP_DIR"
echo ""
log_warn "If you had other firewall software, you may need to restart it."
echo ""
