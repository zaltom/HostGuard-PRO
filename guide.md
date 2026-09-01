# HostGuard Pro - Administrator Guide

## Installation

### Prerequisites
- The RHEL family: AlmaLinux, Rocky Linux, CloudLinux, CentOS, RHEL or Oracle
  Linux, versions 7 to 10, with cPanel/WHM
- systemd
- Root SSH access
- iptables installed (standard on all supported OS)
- Perl 5.16+ (included with cPanel)

The installer **refuses to run on anything else** rather than installing part
of itself. Elsewhere the authentication logs are named differently, the package
manager is not yum or dnf, and the unit and cron paths these services use are
not guaranteed to exist. A partial install is the worst outcome available:
files in place, services registered, and a firewall that does not come up.

The check reads `ID` and `VERSION_ID` from `/etc/os-release`, falling back to
`/etc/redhat-release` on older releases. A distribution that does not name
itself but declares `ID_LIKE="rhel"` is accepted with a warning. A supported
family on an untested major version warns and continues; only an unrecognised
family stops the install.

To install anyway, knowing all of the above:

```bash
HG_ALLOW_UNSUPPORTED=1 bash install.sh
```

That also bypasses the systemd requirement. You are then responsible for
checking that the firewall starts, that the daemon finds your authentication
logs, and that the units work as installed.

### Install Steps
```bash
cd /usr/src
git clone https://github.com/zaltom/HostGuard-PRO.git hostguard-pro
cd hostguard-pro
bash install.sh
```

The installer will:
1. Run compatibility checks (iptables, ipset, Perl)
2. Create all directories and install files
3. Install systemd services
4. Auto-detect server IPs and add them to the allowlist/ignorelist
5. Auto-detect the admin's SSH IP and add it to the allowlist
6. Register the WHM plugin (if cPanel is present)
7. Install with TESTING=1 (safe mode) by default

### First Start
```bash
# Start the firewall. While TESTING=1 the CLI installs
# /etc/cron.d/hostguard_testing, which clears the firewall every
# TESTING_INTERVAL minutes so a bad ruleset cannot lock you out for long.
systemctl start hostguard

# Open a SECOND session and confirm you can still get in. Keep the first one
# open until you have: if the new ruleset is wrong, the existing session may
# survive where a new one does not.

# Then turn testing mode off:
vi /etc/hostguard/hostguard.conf
# Change: TESTING = "0"

# Reload. This is also what removes the auto-clear cron - the cron follows
# TESTING, and hostguard -r is what reconciles the two. It prints a line
# saying the cron was removed.
hostguard -r

# Confirm. With TESTING=0 and no cron, "Auto-clear" is absent from the output.
# If it is still listed, the firewall is still on a timer: do not go into
# production until it is gone.
hostguard -s

systemctl start hostguardd
```

Do not skip the `hostguard -s` check. The auto-clear cron used to survive this
transition, because it was removed only by `hostguard -x`. A host that had just
been put into production was then torn down once, minutes later, permanently -
and because `hostguard.service` is `Type=oneshot` with `RemainAfterExit=yes`,
`systemctl status hostguard` went on reporting the unit as active. The cron now
follows `TESTING` on every path that leaves a ruleset in force, and both
`hostguard -s` and the WHM dashboard report the two disagreeing.

## Configuring Ports

Edit `/etc/hostguard/hostguard.conf`:

```
# Allow incoming TCP ports (comma-separated, ranges with colon)
TCP_IN = "20,21,22,25,53,80,110,143,443,465,587,993,995,2077,2078,2079,2080,2082,2083,2086,2087,2095,2096,8443"

# Allow outgoing TCP ports
TCP_OUT = "20,21,22,25,37,43,53,80,110,113,443,587,873,993,995,2086,2087,2089"

# Allow incoming UDP ports
UDP_IN = "20,21,53,80,443"

# Allow outgoing UDP ports
UDP_OUT = "20,21,53,113,123,873,6277"
```

After changing ports, reload the firewall:
```bash
hostguard -r
```

### Common Port Additions
- **Custom SSH port**: Change `SSH_PORT` and add to `TCP_IN`
- **Mail**: Ports 25, 465, 587, 993, 995 (included by default)
- **DNS**: Port 53 TCP/UDP (included by default)
- **Game servers**: Add custom ports to `TCP_IN`/`UDP_IN`

## How Blocking Works

### Login Failure Detection
The daemon (`hostguardd`) continuously monitors log files for authentication
failures. These are the core services; see **Additional Detection Services**
below for the rest, and **Custom Login Failure Patterns** for defining your own.

| Service | Log File | Config Key |
|---------|----------|------------|
| SSH | /var/log/secure | LF_SSHD |
| FTP | /var/log/messages | LF_FTPD |
| POP3 | /var/log/maillog | LF_POP3D |
| IMAP | /var/log/maillog | LF_IMAPD |
| SMTP AUTH | /var/log/maillog | LF_SMTPAUTH |
| cPanel/WHM | /usr/local/cpanel/logs/login_log, /usr/local/cpanel/logs/error_log | LF_CPANEL |

### Blocking Flow
1. Daemon detects failed login attempt and records the source IP
2. If failures from one IP exceed the threshold within `LF_INTERVAL` seconds:
   - IP is temporarily blocked for `LF_TEMP_BLOCK_DURATION` seconds
   - Block is added to ipset (instant, kernel-level blocking)
   - `LF_TEMP_BLOCK_DURATION` must be a whole number of seconds above zero
     and no more than 2147483 (about 24 days), the longest timeout ipset
     holds. Anything else is refused and the daemon uses 3600 instead,
     saying so in the log. Zero in particular is not "forever": ipset
     reads it as no timeout, which would make the block permanent while
     still reporting it as expiring.
3. If the same IP gets temp-blocked `LF_PERM_BLOCK_AFTER` times:
   - IP is promoted to permanent block (added to deny.conf)
4. Allowlisted IPs are never blocked
5. Ignored IPs are never auto-blocked by the daemon

### How the repeat-offender count survives a restart

Step 3 needs to remember how often an address has been blocked before, across
restarts, so the count lives in `/var/lib/hostguard/block_history.dat`.

Writing it on every block would have made the cost of blocking one address grow
with the number blocked before it, which is the wrong way round during the
flood that produces them. Instead a block marks the table dirty and the
scheduler flushes it once a minute, as does shutdown.

The flush writes a temporary file, fsyncs it, and renames it over the previous
copy while holding `block_history.dat.lock`. Each part answers a way the file
could otherwise be lost: the rename means a crash part way through leaves the
old file rather than a truncated one; the fsync means the rename cannot publish
a name pointing at unwritten blocks; the lock, held on a separate file because
the data file's inode is about to be replaced, means two writers cannot
interleave. If any step fails the previous copy stays and the table stays
dirty, so the next flush tries again rather than the counts being dropped.

On startup, lines that do not parse are discarded, entries older than
`LF_PERM_BLOCK_INTERVAL` are dropped, and no more than
`LF_TRACK_MAX_ADDRESSES` are loaded - the cap that bounds the table in memory
has to bound what is read back into it, or a file grown by an earlier release
reintroduces the growth on the next start.

### Cross-Protocol Aggregation
When `LF_GLOBAL_THRESHOLD = "1"`, failures across all services count toward a single limit (`LF_GLOBAL_LIMIT`). An attacker trying SSH, then FTP, then SMTP AUTH will hit the combined limit faster.

## How a Ruleset is Swapped In

Rules are built into whichever of two slots is idle while the other keeps
filtering, and the new one is attached only once it is complete. The host is
never left without rules.

Attaching means inserting a jump at the top of each built-in chain: `INPUT` and
`OUTPUT`, and the same two again for IPv6. **That is two commands, or four, and
iptables offers no way to issue them as one.** Anything claiming a single
atomic switch through the iptables command line would be overstating it.

What is guaranteed instead is that the attachment is all or nothing. If any
jump cannot be inserted, the ones already inserted are removed again, the new
slot is torn down, and the slot that was already serving carries on:

```
[ERROR] Could not attach IPv4 outbound (HOSTGUARD_OUT_B to OUTPUT); undoing the
jumps already inserted so the slot is not left half active.
[ERROR] Refusing to complete the swap to slot _B: the chains could not be
attached.
[ERROR] The previously loaded ruleset (slot _A) is still in force.
```

That guarantee matters because of what comes next in a successful swap: the new
slot is recorded as live and the old one is dismantled. Half an attachment
followed by that teardown would leave a direction with no rules at all, and it
would be reported as a successful start.

### The remaining window

Between the `INPUT` jump landing and the `OUTPUT` jump landing there is a gap
of well under a millisecond. Inbound is attached first, deliberately, so that
during the gap the new slot governs what arrives while the previous rules, or
on a first start no rules, still govern what leaves. The reverse order would
cut outbound traffic while inbound was still open.

For a reload the gap is between two working rulesets rather than between rules
and none, since the old slot's jumps are still in place below the new ones
until the teardown.

### Which slot is live, and how that is known

The live slot is recorded in `/var/lib/hostguard/active_slot`, but that file
is the record, not the authority. The authority is the kernel: the slot
serving traffic is whichever `HOSTGUARD_IN` chain is jumped to from `INPUT`,
whatever the file says.

The distinction is not academic, because the two can disagree. Writing the
record was previously a note taken after the swap: if it failed, the failure
was logged and the start carried on. The new slot was already attached and
the old one was torn down moments later, so the record then named a ruleset
that no longer existed - and the next rebuild read that name, chose "the
other slot", and dismantled the one actually filtering traffic. The host was
left unfiltered for the length of a rebuild, which is the single thing the
two slots exist to prevent.

Two changes, either of which is enough on its own:

**Recording the slot is part of the swap.** If it cannot be written, the swap
is undone - the new jumps come out, the new slot is torn down, and the
previous ruleset, still built and still attached beneath them, governs
traffic again, which is what the unchanged record already says. The start
then fails, loudly, like any other build failure.

**The target slot is chosen against the kernel.** A rebuild asks iptables
which slot is attached and builds into the other one. A record that is
missing, stale, or restored from a backup taken at the wrong moment is
reported and corrected rather than believed.

### The window neither of those covers

Between attaching a slot and recording it there is a moment - one rename long
- where a crash leaves both slots attached, the new one on top, and the record
naming the old one. Nothing rolls that back, because nothing runs.

The damage is not that the two disagree. It is that the outgoing slot's sets
still exist, so an operation reading the record adds an address to a set the
live slot does not consult, the kernel accepts it, and the block is reported as
applied. That is the one remaining way this could say something untrue, so it
is not left to be discovered at the next reload:

- **Every process reconciles when it initialises.** One `iptables -S INPUT`,
  and where the record is wrong it is corrected on disk - not merely in that
  process, since every operation re-reads the record on its way in and would
  read a stale one straight back over the correction.
- **The daemon repeats the check every minute**, which bounds the exposure of
  a daemon that was already running when someone else's rebuild died.

```
[WARN] The recorded active slot (_A) is not the one attached to INPUT (_B);
correcting the record. Operations taken since the two diverged may have gone
to the wrong slot.
```

The check is skipped entirely when nothing of ours is attached, which is the
ordinary state of a stopped firewall, and it only takes the firewall lock when
there is something to correct.

Per-operation checking would close the window completely rather than bounding
it, and is deliberately not done: it would cost an `iptables` call on the path
that runs once per blocked address, during the flood that produces them.

### Operations on a ruleset that is already live

A block, an allow, an unblock, an expiry sweep and a block-list or country-set
refresh all act on the slot that is serving traffic, and that slot can change
under them: any other process - the CLI, the WHM page, a second daemon - can
reload and swap it at any moment.

Reading `active_slot` once at startup is not enough. The daemon reads it when it
initialises and then runs for weeks, so the name it holds is only a starting
position. Every operation that touches the live ruleset therefore takes the same
lock `hostguard -r` takes, and re-reads which slot is live once it holds it. A
block that arrives during a reload waits for the reload rather than being
dropped, and then goes into the slot that reload made live.

Without this the failure is quiet, which is what makes it worth the lock. A
block applied to a slot that has just been torn down leaves the address recorded
in `tempblock.dat` and listed by `hostguard -t`, with nothing anywhere actually
blocking it.

The same rule covers the two set refreshes. `ipset swap` is atomic, but the name
being swapped into has to belong to the ruleset serving traffic, and a set that
is not there is not part of it: the rules that match a block list or a country
are emitted when the ruleset is built. So a refresh whose set has gone reports
that a reload is needed rather than creating the set - creating it produced an
orphan nothing matched, and a log line claiming the list had been applied.

### When the record cannot be written

A temporary block is two things: the entry in the kernel that does the
blocking, and the line in `tempblock.dat` that records it. The kernel entry
is authoritative - a block the kernel refused is never recorded - but the
record is what makes it visible. `hostguard -t`, the WHM page, and the
rebuild that runs on the next reload all read that file, and nothing else
knows the address is held.

So a write to it that fails is a failure of the whole operation, and it is
reported as one. The helper used to die on a failed open and check neither
`print` nor `close`, which meant a full filesystem - the state directory is
small, and a runaway log or an oversized block list is all it takes - was
accepted in silence while the operation returned success.

When the record cannot be written the kernel change is undone. That leaves
an attacker unblocked because a disk is full, which is bad and visible; the
alternative is an address blocked with nothing recording it, which is bad
and silent, cannot be found to be removed, and with `LF_IPSET=0` carries no
timeout and so never expires. If the rollback fails too, the log names the
address and the command that removes it.

The same applies to a temporary allow, where an unrecorded entry is a hole
in the firewall rather than an unwanted block, and to `allow`, which writes
`allow.conf` before touching the kernel so that a failure there costs
nothing and needs no rollback.

Replacing an existing entry is one atomic write rather than a removal
followed by an append. In two steps there is a moment when the address is
in neither the old line nor the new one, and a failure there - or a crash
- left it recorded nowhere while it was still blocked, or still allowed,
in the kernel. A new address is still appended rather than rewriting the
file around it: there is nothing to lose when the address is in no line
yet, and it keeps the cost of recording a block from growing with the
number already recorded.

One consequence worth stating: a block reason is assembled from log text,
including names an attacker chooses. Both record files are now written by
the same code, which flattens `|` and newlines in a note, so a crafted user
name can no longer write a second line into the file it is recorded in.

## When a Rule Fails to Load

HostGuard Pro will not put a half-built ruleset in front of the host.

Rules are assembled into an idle slot while the live one keeps filtering. Every
command that builds the ruleset is checked, and if any of them is rejected the
slot is torn down and never activated. The ruleset already serving traffic
carries on unchanged.

```
ERROR: Firewall not started: 2 rule(s) failed to load.

The following rule(s) were rejected:

  /sbin/iptables -A HOSTGUARD_IN_B -m set --match-set hg_allow4_b src -j ACCEPT
  /sbin/iptables -A HOSTGUARD_IN_B -m set --match-set hg_deny4_b src -j ...

The firewall was not activated, so no half-built ruleset is in
force. Fix the cause and run 'hostguard -e' again.
```

The reason for refusing is that a partial ruleset fails in both directions at
once. A rejected deny match lets through addresses the daemon believes it has
blocked; a rejected allowlist match stops accepting the address you administer
the server from. Neither is visible from the outside, and both would otherwise
be reported as a successful start.

### Which rules are treated this way

Anything that decides what the firewall permits: chain creation, the allow,
deny and temporary block matches, the port rules, the default drop, and the
country and bogon matches.

### Which rules only warn

Rules that refine the ruleset without deciding what it permits: SYN flood
mitigation, connection limits, port flood detection, port scan tracking, ICMP
rate limiting, the logging rules and the block notice redirect. These need
kernel modules that not every host carries, which is why `install.sh` probes
them as optional. If one is unavailable the firewall starts without that
feature and the daemon log says which.

### What counts as part of the ruleset

Not only the rules. Everything loaded into it counts too: the allowlist, the
deny list, the temporary blocks and allows restored from `/var/lib/hostguard/`,
the external block lists, the country ranges and the bogon set. A slot whose
rules all loaded but whose allowlist is half there is not a complete ruleset,
and activating it means dropping the addresses the allowlist exists to protect.

The country ranges are the sharpest case. The rules matching them are emitted
from the zone files, before the ranges are loaded into the sets - so a load that
fails leaves rules matching an empty set. In `GEO_DENY` that is a country filter
that filters nothing. In `GEO_ALLOW` it is a chain that returns for nobody and
drops everything: a lockout. The guard against applying `GEO_ALLOW` with no
ranges checks the zone files; this checks what actually reached the kernel.

Those loads previously ran through a helper that discarded the result, so the
kernel refusing an address - a set that has filled up, a set that is not there
- was invisible and the slot was activated as though nothing had happened. They
are now counted, and any refusal keeps the slot from being activated, exactly
as a rejected rule does. The log reports one line per file rather than one per
address, since a full set refuses every remaining entry:

```
[ERROR] Temporary blocks: 143 of 892 entries were refused by the kernel
(for example 198.51.100.10)
```

Temporary allows have no implementation other than the ipset, so with
`LF_IPSET = "0"` they cannot be applied at all. Records made while it was on
would then be dropped from every rebuild in silence, while `hostguard -la` went
on listing them as access in force. That now says so, and says what to do about
it. A record file that exists but will not open - or that is not a regular file
at all, which is what a botched restore tends to leave - is a ruleset that
cannot be completed rather than one with nothing to restore, and is treated as
such.

A duplicate is not a refusal - the same address twice in `allow.conf`, or one
both permanently and temporarily blocked, is untidy rather than wrong - and a
record that cannot be applied at all is skipped rather than counted: a line
that does not parse, an IPv6 entry on a host with `IPV6 = "0"`, or an expiry
further off than an ipset timeout can express, which is brought down to the
maximum rather than sent to the kernel to be refused. One corrupt line must not
be able to stop the firewall starting for good.

### On a first start

There is no previous ruleset to fall back on, so a failed first start leaves
the host unfiltered rather than partly filtered. That is deliberate: a
firewall nobody can reason about is worse than one that plainly did not start.
The log names every command that was rejected.

A rejected match almost always means the kernel module behind it is not
loaded. Check one with:

```bash
iptables -m recent --help
modprobe xt_recent
```

## Advanced Filters and Precedence

An advanced filter line in `allow.conf` or `deny.conf` -
`tcp|in|d=22|s=10.0.0.5` - becomes a rule rather than an ipset member, and
where that rule sits decides what it does.

The order inside the input chain is:

| | |
|---|---|
| 1 | loopback, then established and related connections |
| 2 | `allow.conf` addresses and ranges (`hg_allow4`) |
| 3 | `allow.conf` **advanced filters** (`HOSTGUARD_AALLOW_IN`) |
| 4 | temporary allows |
| 5 | bogon source addresses |
| 6 | `deny.conf` addresses and ranges (`hg_deny4`), then temporary blocks |
| 7 | `deny.conf` **advanced filters** (`HOSTGUARD_ADENY_IN`) |
| 8 | external block lists, country rules |
| 9 | flood and connection limits |
| 10 | `TCP_IN` / `UDP_IN` / `SSH_PORT` accepts |
| 11 | default drop |

Two consequences worth knowing before you write one:

- An **advanced allow** is above every block, so `tcp|in|d=80` in `allow.conf`
  means no denied address, temporary block or block list entry applies to port
  80 at all. That is what an allowlist entry means, and it is rarely what
  someone wants for a public port.
- An **advanced deny** is below every allow, so `tcp|in|d=22` in `deny.conf`
  closes SSH to everyone *except* the addresses in `allow.conf`. Add your own
  address to `allow.conf` first.

These filters used to be inserted at the very top of the input chain with
`iptables -I`, above the loopback accept, above established connections and
above the allowlist. A `tcp|in|d=22` deny then cut the administrator's own live
session on the next reload, and a `tcp|in|d=80` allow made blocked addresses
reachable on port 80. Both contradicted this table, which the shipped
`allow.conf` and `deny.conf` have always described. They are now emitted into
chains that the table above places, so the order is what it says it is - and
insertion order within each file is file order again, which `-I` had reversed.

## Lockout Recovery

### If you get locked out

**Method 1: TESTING mode (preventive)**
TESTING=1 is on by default. The firewall auto-clears every `TESTING_INTERVAL`
minutes. Wait for the cron to fire, then SSH back in.

This only helps if the cron is actually installed, so check before you rely on
it rather than after:

```bash
hostguard -s | grep Auto-clear      # present means the net is armed
cat /etc/cron.d/hostguard_testing   # and this is the entry
```

`TESTING_INTERVAL` must be a whole number of minutes from 1 to 60. A value
outside that is refused and 5 is used, with a warning - a malformed value would
produce a crontab line cron rejects, and the net would silently not exist.

**Method 2: Console/IPMI/KVM access**
```bash
# Disable firewall immediately
hostguard -x

# Or flush iptables directly
iptables -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
```

**Method 3: From WHM (if web access works)**
Navigate to WHM > HostGuard Pro > Services > Stop Firewall

**Method 4: Via cPanel's Terminal**
If you can access WHM's built-in terminal, run:
```bash
hostguard -x
```

**Method 5: Reboot with init override**
If nothing else works, reboot and in the GRUB menu add `init=/bin/bash`, then:
```bash
mount -o remount,rw /
iptables -F
systemctl disable hostguard hostguardd
```

### Prevention Tips
- Always keep your own IP in the allowlist
- Use TESTING mode when making changes
- Test SSH access from a second terminal before closing your current session

## Managing Allow/Deny/Ignore Lists

### Via CLI
```bash
# Allow an IP
hostguard -a 203.0.113.10 "Office IP"

# Deny an IP
hostguard -d 198.51.100.50 "Known attacker"

# Remove a temporary block
hostguard -tr 192.0.2.100

# Search for an IP
hostguard -g 10.0.0.1

# List all temporary blocks
hostguard -l
```

### Via WHM
Navigate to WHM > HostGuard Pro > Allowlist/Denylist/Ignore List

Two ways to change a list from the browser, and they are treated differently
because they carry different risk:

**Quick Add** takes one address, validates it, and hands it to the CLI. It
works whatever `RESTRICT_UI` is set to.

**The bulk editor** replaces the whole file. It answers to `RESTRICT_UI` in the
same way the configuration editor does, and with the shipped default
(`RESTRICT_UI=1`) it is read-only. These files are firewall policy: the
allowlist decides who bypasses every block, and an advanced filter in it opens
a port. Until this release `RESTRICT_UI` covered `hostguard.conf` but not the
lists, which read as a stricter setting than it was.

With `RESTRICT_UI=0` the bulk editor accepts a save only if every line parses:

- a blank line or a `#` comment
- an address or CIDR range, with an optional trailing `# comment`
- an advanced filter such as `tcp|in|d=22|s=10.0.0.5`

A line that does not parse is reported by number and **nothing is written**.
Previously the text went to disk unchecked and the unparseable lines were
dropped silently at load, so an address could appear in the file and never be
allowed.

`Include` cannot be added from the browser. It points the loader at another
file, which is not something to be able to do from a web form; add one over
SSH. Existing `Include` lines already in a file are left alone.

Every save keeps one generation of backup (`allow.conf.bak`) and writes a line
to the daemon log naming the WHM account and address that made the change:

```
[2026-09-01 11:42:03] [INFO] WHM: root from 203.0.113.9 replaced allow.conf (14 lines)
```


### File Format
Edit files directly: `/etc/hostguard/allow.conf`, `deny.conf`, `ignore.conf`
```
# One IP/CIDR per line, optional comment after #
192.168.1.100        # Office network
10.0.0.0/8           # Internal
203.0.113.0/24       # Partner network - do not delete

# Include external files
Include /etc/hostguard/custom_allow.conf

# Advanced filter (allow SSH only from specific IP)
tcp|in|d=22|s=10.0.0.5
```

After editing files manually, reload the firewall:
```bash
hostguard -r
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `hostguard -e` | Enable/start firewall |
| `hostguard -x` | Disable/stop firewall |
| `hostguard -r` | Reload firewall rules |
| `hostguard -s` | Show status |
| `hostguard -a <ip> [note]` | Allow IP |
| `hostguard -d <ip> [note]` | Deny IP permanently |
| `hostguard -tr <ip>` | Remove temporary block |
| `hostguard -g <ip>` | Search for IP in all lists |
| `hostguard -l` | List active temp blocks |
| `hostguard -b` | Update external block lists that are due |
| `hostguard -b force` | Re-download every external block list |
| `hostguard -c` | Update country zone files that are due |
| `hostguard -c force` | Re-download every country zone file |
| `hostguard -ta <ip> [secs] [note]` | Allow an IP temporarily (default 3600s) |
| `hostguard -tar <ip>` | Remove a temporary allow |
| `hostguard -la` | List active temporary allows |
| `hostguard --security` | Run the server security check |
| `hostguard --scan` | Run the process and file checks now |
| `hostguard --preset <low\|medium\|high>` | Apply a threshold preset |
| `hostguard --integrity-reset` | Clear the binary integrity baseline |
| `hostguard --cluster list` | Show cluster configuration and members |
| `hostguard --cluster ping` | Confirm members are reachable |
| `hostguard --cluster deny <ip> [reason]` | Block an address across the cluster |
| `hostguard --start-daemon` | Start the daemon |
| `hostguard --stop-daemon` | Stop the daemon |
| `hostguard --restart-daemon` | Restart the daemon |
| `hostguard -v` | Show version |

The `myfw` command is an alias that works identically.

## External Block Lists

HostGuard Pro can download publicly published lists of hostile networks and
block them at the firewall. Lists are defined in
`/etc/hostguard/blocklists.conf`, one per line:

```
NAME|INTERVAL|MAX|URL
```

| Field | Meaning |
|-------|---------|
| `NAME` | Alphanumeric, max 24 characters. Names the ipset holding the list. |
| `INTERVAL` | Refresh interval in seconds. Values below 3600 are raised to 3600. |
| `MAX` | Maximum addresses to import, or `0` for the whole list. |
| `URL` | `http://` or `https://` address of the list. |

Several well-known lists ship commented out. Remove the leading `#` to enable
one:

```
SPAMDROP|86400|0|https://www.spamhaus.org/drop/drop.txt
```

Nothing is downloaded until you enable a list, so a default installation makes
no outbound requests.

### How lists are applied

Each list gets its own ipset, matched immediately below the allowlist and deny
list. An address in `allow.conf` therefore always wins, so allowlisting your
own networks protects them from every list.

The daemon checks for lists that have fallen due and applies new contents to
the running firewall without interrupting it. To update by hand:

```bash
hostguard -b          # fetch lists whose refresh interval has elapsed
hostguard -b force    # re-download every list
hostguard -s          # show entry counts and when each was last updated
```

Cached copies live in `/var/lib/hostguard/blocklists/`. A download is discarded
and the previous copy kept unless it looks like the list it claims to be, so a
provider outage cannot empty a list.

### What a download has to satisfy to be applied

Three things, in order. It has to yield at least one usable address; at least
`BLOCKLIST_MIN_VALID_PERCENT` of its content lines have to be addresses; and it
must not have fallen more than `BLOCKLIST_MAX_SHRINK_PERCENT` below the copy it
replaces.

Only the first of these used to be checked, and on its own it asks the wrong
question. It asks whether the download contains an address, when what matters is
whether the download is a block list. The two ways this goes wrong in practice
both pass it: a provider serving an error page, a status page or a lapsed-account
notice can carry an address at the start of a line, and a transfer cut short by a
proxy arrives looking complete with the fragment that did arrive parsing
perfectly well. Either way the firewall silently stops blocking nearly everything
the list covered, and the update is reported as a success, only smaller.

The ratio test separates a list from a document that mentions an address. It is
skipped for files of fewer than 20 content lines, where the proportion says
little. The shrink test separates a list that shrank from one that was
truncated; it is skipped for lists of fewer than 100 entries, and for a list read
only as far as its configured maximum. A genuine collapse - a provider that
really did retire most of its entries - is accepted with `hostguard -b force`.

### Downloading a list and applying it are two steps

The download writes the cache. Applying it swaps the new addresses into the
live ipset. They fail independently, and the second failing is the quieter of
the two: the new copy is already on disk, so `hostguard -b` and the WHM page
both read it and call the list up to date, while the kernel goes on matching
the old one.

So a refresh reports what actually reached the firewall, not what was
downloaded. Anything that leaves the previous data in place - a set the running
ruleset does not have, a swap the kernel refuses, a cached copy that cannot be
read or holds nothing usable - is an error naming that:

```
[ERROR] Blocklist SPAMHAUS was not fully applied: 1 of 2 set(s) could not be
replaced, so the running firewall still has the previous data for them. Run
'hostguard -r' to rebuild from the cached copy.
```

A partial apply counts as a failure. One family swapped and the other not
leaves the firewall matching the new list for IPv4 and the old one for IPv6,
and reporting the count of the half that worked described that as an update.

The daemon and the CLI both check the result rather than the download:

```
SPAMHAUS                 42918 entries downloaded, but NOT applied to the
                         running firewall
                         the firewall still has the previous data; see
                         /var/log/hostguard/daemon.log
```

Country zone files work the same way, for the same reasons.

### Settings

| Setting | Purpose |
|---------|---------|
| `BLOCKLIST_ENABLE` | Apply the configured lists (1=yes, 0=no) |
| `BLOCKLIST_TIMEOUT` | Seconds to wait for a download |
| `BLOCKLIST_MAX_SIZE` | Largest download accepted, in bytes |
| `BLOCKLIST_MIN_VALID_PERCENT` | Share of content lines that must be addresses (0 disables) |
| `BLOCKLIST_MAX_SHRINK_PERCENT` | How far a list may fall below its previous copy (100 disables) |

The size limit is applied by HostGuard Pro as the bytes arrive, rather than
being passed to the downloader and trusted. Neither downloader can be relied on
for it: `wget` has no option that bounds a single file, and `curl`'s
`--max-filesize` only acts on a size the server declares in advance, so a
response without `Content-Length` slips past it. A transfer that passes the
limit is abandoned and its partial file removed, which is what keeps a hostile
or broken URL from filling the disk the firewall's own state lives on.

Abandoning one is the interesting part. The downloader is still running when
HostGuard Pro stops reading from it, and it has to be stopped and collected
without the caller waiting on it indefinitely. It is signalled first and
escalated to `SIGKILL` if it will not leave, and the pipe is closed separately
from the wait so that closing it cannot block. Doing this the obvious way -
close the pipe, which waits for the child, and signal it afterwards - hangs on
the one case that matters: a downloader that has stopped writing because it is
waiting on the server never notices the closed pipe, and `wget` has no option
that bounds a transfer in total. On the daemon that wait ran on the main loop,
so a single misbehaving list provider stopped log reading, block expiry and
everything else with it.

The same limit and timeout govern the country zone files.

Enabling a list blocks every network it names, so use sources you trust and
check the entry count with `hostguard -s` after the first update.

## Additional Detection Services

Beyond the six original services, the daemon recognises these. Each has its own
threshold key; `0` switches the service off and its patterns are then never
tested.

| Service | Log source | Config key | Default |
|---------|-----------|------------|---------|
| Courier IMAP/POP3 | /var/log/maillog | LF_IMAPD / LF_POP3D | 10 |
| uw-imap / ipop3d | /var/log/maillog | LF_IMAPD / LF_POP3D | 10 |
| Kerio Connect | /var/log/maillog | LF_IMAPD / LF_POP3D | 10 |
| vsftpd | LOG_FTPD_ALT, /var/log/messages | LF_FTPD | 10 |
| htpasswd pages | LOG_APACHE_ERROR | LF_HTPASSWD | 0 (off) |
| ModSecurity v1/v2 | LOG_APACHE_ERROR, LOG_MODSEC | LF_MODSEC | 0 (off) |
| Suhosin | LOG_SUHOSIN, /var/log/messages | LF_SUHOSIN | 0 (off) |

The last three ship off because they need a log path that varies by host. Set
the matching `LOG_*` key first, confirm the file exists, then raise the
threshold above 0.

## Custom Login Failure Patterns

Watch a service HostGuard Pro does not know about without changing any code.
Patterns live in `/etc/hostguard/patterns.conf`, one per line:

```
NAME|LOGFILE|THRESHOLD|REGEX
```

| Field | Meaning |
|-------|---------|
| `NAME` | 1-24 letters, digits or underscores. Names the counter and appears in the block reason. |
| `LOGFILE` | Absolute path. The daemon opens it in addition to the standard logs. |
| `THRESHOLD` | Failures from one address before it is blocked. |
| `REGEX` | Perl regular expression with at least one capture group. |

The first capture group that validates as an IP address is taken as the
offender, so a pattern may capture a user name first:

```
PANEL|/var/log/panel.log|3|user=(\S+) result=fail ip=([\d.]+)
```

A pattern is only ever tested against lines from the file it names, so two
patterns cannot cross-match. An expression that does not compile is reported in
the daemon log and skipped; the rest still load.

Blocks from custom patterns behave exactly like built-in ones: the allowlist
and ignore list are honoured, repeat offenders are promoted, and blocks expire
after `LF_TEMP_BLOCK_DURATION`.

Test an expression before enabling it:

```bash
perl -ne 'print if /YOUR REGEX HERE/' /path/to/logfile
hostguard --restart-daemon
```

Two mistakes to avoid. Anchor the pattern to something specific; one that
matches any line containing an address will block your own monitoring. And
match the *failure*, not the attempt: some applications log one line when a
login starts and another when it fails, and matching the first counts every
successful login as a failure.

## Distributed Attack Detection

The per-address thresholds cannot see an attack spread across many hosts. Each
source fails twice and looks like a user who mistyped a password. What gives it
away is the *account*, not the address.

```
LF_DISTRIBUTED = "1"
LF_DISTRIBUTED_LIMIT = "25"
```

Distinct addresses attacking one account are counted per hour. Once the limit
is reached, every address that took part is blocked (not merely the one
that happened to cross the threshold), and the account is reported.

The counter resets each clock hour and each account is acted on once per hour,
so a sustained campaign produces one action rather than one per subsequent
failure.

## Tracking Table Limits

The daemon holds what it has seen in memory. Every one of those tables is keyed
by something the attacker chooses:

| Table | Keyed by | Limit |
|-------|----------|-------|
| Distributed attack accounts | a user name from a log line | `LF_TRACK_MAX_ACCOUNTS` (2000) |
| Login failure counters | source address | `LF_TRACK_MAX_ADDRESSES` (20000) |
| Login rate | source address | `LF_TRACK_MAX_ADDRESSES` |
| Block history | source address | `LF_TRACK_MAX_ADDRESSES` |

The account table is the one that matters most. A source that tries a fresh
user name on every attempt creates a new entry each time, and `Invalid user
<anything> from <address>` puts whatever it chose straight into the key. The
expiry passes only clear entries from a previous hour or window, so without a
cap the table grows for as long as the attack runs.

That is a denial of service on the thing meant to stop one: a daemon killed for
using too much memory blocks nothing at all.

### What happens at the limit

The least recently seen entries are dropped, down to three quarters of the cap,
and a line is written to the log:

```
[WARN] Account tracking table reached 2001 entries (limit 2000); dropped 501
least recently seen. This is normally a sign of a flood of invented names or
addresses.
```

Least-recently-seen is the right thing to drop rather than an arbitrary choice.
An attack worth catching keeps touching its entry and stays; the one-shot noise
that would flood the table is what goes.

**The tradeoff is real.** An attacker who floods the table can push out entries
that were part way to a threshold, and escape being counted that way. Being
forgotten is a better failure than the daemon being killed, but it is still a
failure, and it is why the limit is reported rather than handled silently.

**So detection is not guaranteed under flooding of arbitrary volume, and should
not be described as though it were.** Below the caps, an attack that crosses a
threshold is acted on. Above them, an attacker who can create entries faster
than the window expires them can push their own partial state out of the table
and avoid the threshold - at the cost of a warning in the log naming exactly
that behaviour, which is itself worth alerting on. Raising `LF_TRACK_MAX_*`
buys a higher ceiling in exchange for memory; it does not remove the ceiling.
The external block lists and country filtering do not depend on these tables at
all, and neither do permanent blocks already in `deny.conf`.
Seeing that warning regularly means either a flood worth looking at, or a host
busy enough to want a higher figure. Raise it if the machine has the memory:
each entry costs on the order of a hundred bytes.

### Watching the tables

```bash
kill -USR1 $(cat /run/hostguardd.pid)
grep -E 'counters|Login rate|Accounts under' /var/log/hostguard/daemon.log | tail
```

## Login Rate Tracking

A mail client that authenticates hundreds of times an hour is misconfigured at
best and testing credentials at worst.

```
LOGIN_RATE_LIMIT = "60"    # successful POP3/IMAP logins per address per hour
LOGIN_RATE_ALERT = "1"     # report
LOGIN_RATE_BLOCK = "0"     # block as well as report
```

Leave `LOGIN_RATE_BLOCK` at 0 until you know the normal rate for this host's
clients. Some phones poll far more often than you would expect, and blocking
before you have measured will lock out real users.

## Process Monitoring

All of these are off by default and report only: nothing is terminated unless
you explicitly enable it.

```
PROC_SCAN = "1"              # suspicious command lines
PROC_USER_LIMIT = "50"       # report accounts over this many processes
PROC_USAGE_CHECK = "1"       # report processes over a resource ceiling
PROC_USAGE_CPU = "90"        # percent of one core
PROC_USAGE_MEM = "1048576"   # resident KB
PROC_USAGE_TIME = "300"      # must have run this long to count
PROC_USAGE_KILL = "0"        # send SIGTERM to offenders
```

`PROC_SCAN` looks for reverse shells, miners, scanners, password crackers,
processes running from a deleted binary, and processes executing out of a
world-writable directory. None of these is proof of anything on its own, which
is why the check reports rather than acts.

`PROC_USAGE_TIME` matters more than it looks. Almost everything spikes at
startup (a compile, an archive, a backup), and reporting those trains you to
ignore the check.

`PROC_USAGE_KILL` sends `SIGTERM` and leaves the process to exit. HostGuard Pro
never sends `SIGKILL`: a process that ignores `SIGTERM` is a decision for a
person, not for a monitor.

### How a process is identified before it is signalled

A pid names a process only while that process is alive. The scan walks every
entry under `/proc`, reads and digests what it finds, and only then decides. On
a busy host that is long enough for a process to exit and its pid to be handed
to something else, so signalling on the pid alone can mean signalling whatever
holds it by then.

Immediately before the signal the process is read again and checked against the
pair that actually identifies it: the pid **and** its start time, in clock ticks
since boot. A reused pid belongs to a process that started later, so the start
time differs and nothing is signalled. The owner is checked too.

The fresh reading is also re-tested against the limits, so a process whose usage
fell back while the scan was running is left alone:

```
[INFO] Not terminating pid 21984: it is no longer the process that was scanned
[INFO] Not terminating pid 22317: usage fell back within limits before the signal
```

Never signalled at all: pid 0 and 1, the daemon itself, and anything in the
daemon's own process group, which is where the mailer and any `BLOCK_REPORT`
hook run.

The same care applies to the daemon's own pid file. A pid file outlives the
process that wrote it, so `hostguard --stop-daemon` confirms the pid is still a
running `hostguardd` before signalling it, rather than trusting a number that
may since have been reused.

Run the checks by hand at any time, without sending mail:

```bash
hostguard --scan
```

### Exceptions

`/etc/hostguard/procignore.conf` takes one rule per line:

```
backupuser              # a whole account
/opt/backup/bin         # a path prefix (also applies to file scanning)
cmd:collectd            # a command line fragment
```

Use these sparingly. Each is a place the checks will not look, and an exception
written to silence a report you have not explained is how a real finding gets
missed. Prefer a path or command fragment over a whole account: an account
exception hides everything that user ever runs, including whatever a compromise
of that account would run.

## File and Integrity Monitoring

### Suspicious files

```
FILE_SCAN = "1"
FILE_INTERVAL = "3600"
FILE_SCAN_DIRS = ""      # additional directories, comma-separated
```

Scans `/tmp`, `/var/tmp`, `/dev/shm` and `/run/shm` for executables, setuid
files and scripts. A payload has to land somewhere before it runs, and these
are where it lands. Symbolic links are never followed, and the walk is bounded
by depth and entry count so a large `/tmp` cannot make the check itself the
load problem.

### Watched paths

```
WATCH_ENABLE = "1"
WATCH_INTERVAL = "300"
```

List paths in `/etc/hostguard/watch.conf`, one absolute path per line. Files
are compared by size, mtime, mode, ownership and content digest. Directories
are compared by their immediate entries, so a file appearing or disappearing is
reported; the tree below is not walked.

### Integrity monitoring

```
INTEGRITY_ENABLE = "1"
INTEGRITY_INTERVAL = "86400"
INTEGRITY_DIRS = ""              # empty uses the built-in list
INTEGRITY_MAX_SIZE = "10485760"  # larger files compared by metadata only
```

Compares the executables in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`,
`/usr/local/bin` and `/usr/local/sbin` against a recorded baseline. This is the
last line of detection: by the time a binary has been replaced, everything
earlier has already been got past.

Metadata alone catches a replacement; the content digest catches an edit that
restored the original mtime. Symlinks are recorded by their target, so a
repointed alternatives link is seen.

**The first run records the baseline and reports nothing**, because everything
would otherwise look new. A changed binary is expected after a package
update. Run this afterwards so the next check starts from the new state:

```bash
hostguard --integrity-reset
```

Do not use it to silence a report you have not explained.

### Account modification

```
NOTIFY_ACCOUNT_MOD = "1"
```

Reports a changed shell, uid, gid, home directory or password, field by field,
along with accounts created and removed. The password hash is never stored or
reported: only a digest of it is kept, so HostGuard Pro can say that a
password changed without holding the material that would let anyone act on it.

## Port Scan Detection

```
SCAN_ENABLE = "1"
SCAN_LIMIT = "10"          # closed ports touched
SCAN_INTERVAL = "60"       # within this many seconds
SCAN_BLOCK_TIME = "3600"   # block for this long
```

The rules sit at the end of the input chain, after every accept, so they only
ever see traffic that matched nothing, which is precisely what a scan
generates and what an ordinary client does not. A real client connects to a
port something is listening on.

Only new TCP connections and UDP packets are counted, so a client whose
established connection outlived a rule change is not blocked. An address
already held is not counted again, so a block does not keep renewing itself.

Blocks expire on their own, exactly as login-failure blocks do.

### Reporting

The block is applied by the kernel, so the daemon does not see it happen. What
it can see is the `HG_SCAN:` line the rule logs, which is what the report is
built from. Reporting therefore needs two things beyond `SCAN_ALERT=1`:

- `DROP_LOGGING = "1"`, or the rule logs nothing
- the kernel log among the watched files, which on AlmaLinux, Rocky and CentOS
  is `/var/log/messages` and is already watched as `LOG_FTPD`

Without those the blocking still works; only the notice is missing.

## Bogon Filtering

```
BOGON_ENABLE = "1"
BOGON_PRIVATE = "0"
```

Drops packets whose source address cannot legitimately arrive from the
internet: documentation ranges, multicast, link-local, reserved space. Nothing
routable can be behind such an address, so a packet claiming one is forged.

`BOGON_PRIVATE` additionally filters `10/8`, `172.16/12`, `192.168/16` and
carrier-grade NAT. **Leave it at 0** on any host with an internal interface, a
VPN, or container networking; those ranges are entirely normal there.

Bogon rules sit *below* the allowlist, so an administrator who has deliberately
allowed a private range is never cut off by this check.

## Unused Addresses

```
UNUSED_IPS = "203.0.113.5,203.0.113.6"
```

Drops all traffic to addresses the host holds but serves nothing on. Traffic to
one of these is either a scan or a misconfiguration, and neither wants
answering.

Addresses are named explicitly rather than discovered. Guessing which of a
host's addresses are unused would eventually guess wrong and take a live site
offline.

## Country Filtering

```
GEO_ENABLE = "1"
GEO_DENY = "CN,RU,KP"      # deny these
GEO_ALLOW = ""             # or: allow only these, denying everything else
GEO_INTERVAL = "86400"
```

Country ranges are downloaded as published zone files and cached in
`/var/lib/hostguard/geo/`. Each country gets its own ipset, matched below the
allowlist.

```bash
hostguard -c            # update zones that are due
hostguard -c force      # re-download every zone
hostguard -s            # show per-country range counts
```

After the first download, reload the firewall so the matching rules are built:

```bash
hostguard -r
```

**On `GEO_ALLOW`.** It is a very sharp instrument. It drops everything the zone
files do not account for, which includes addresses reassigned since the files
were published and every address the publisher does not cover. Two safeguards
apply: your allowlist still wins, so allowlist your own address before enabling
it; and HostGuard Pro refuses to apply allow mode when the zone files are
empty, rather than dropping all traffic on the strength of a failed download.

Setting both `GEO_DENY` and `GEO_ALLOW` is a contradiction rather than a
combination. `GEO_DENY` wins and the conflict is logged.

## Block Notice Service

```
NOTICE_ENABLE = "1"
NOTICE_PORT = "8899"          # responder port, not 80
NOTICE_BIND = "127.0.0.1"
NOTICE_PORTS = "80"           # ports whose traffic is redirected
NOTICE_CONTACT = "support@example.com"
NOTICE_FILE = ""              # path to your own page; [IP] is substituted
```

A dropped packet looks the same to a visitor as a server that is down, which
costs a site with real users in support requests. When enabled, a temporarily
blocked address reaching the web port is redirected to a small responder that
serves a page explaining what happened.

Things worth knowing:

- **HTTP only.** A TLS client expects a handshake and would report a
  certificate error rather than render a page, so HTTPS traffic from a blocked
  address is left to drop. This is a limitation of the approach.
- **Temporary blocks only.** A permanently denied address stays dropped,
  because a permanent block is a decision that does not want a conversation.
- **The notice is served; the block still stands.** Nothing here lets a visitor
  remove their own block.
- The responder never reads a path, parameter or header from the request. It
  answers every request on its port with the same page.
- The redirect lives in the nat table and is removed when the firewall stops.

## Outbound Mail Tracking

```
RELAY_TRACK = "1"
RELAY_LIMIT = "100"    # messages per account per hour
```

Counts messages leaving the host per account and per sending script. A
compromised site almost always shows itself here first: the account is real,
the credentials are real, nothing in the firewall or the login logs looks
wrong, and the only visible symptom is the volume.

Attribution prefers the authenticated account (`A=` in the Exim log), falling
back to the Unix account (`U=`). The sending script's directory (`cwd=`) is
carried alongside, so a report can name the file rather than only the account.

Only message *arrivals* are counted, so a message to twenty recipients counts
once. Inbound mail and system senders are not counted.

Current counts appear in `hostguard -s`.

## Load Average Alerting

```
LOAD_ALERT = "1"
LOAD_LIMIT = "10"
LOAD_INTERVAL = "300"
```

Reports load that *stays* high, not load that spikes. A busy host spikes
constantly (a backup, a mail queue run, a package update), and alerting on the
spike trains you to ignore the alert. The report includes the ten highest-CPU
processes at the time.

## Security Check

```bash
hostguard --security
```

Reviews the settings that decide how exposed the host is: testing mode left on,
IPv6 present but unfiltered, risky ports open, `PermitRootLogin yes`, empty SSH
passwords, world-writable directories missing the sticky bit, configuration
files readable by other users, and subsystems left off.

Set `SECURITY_ALERT = "1"` to run it daily and report anything above low
severity. It is also a page in WHM.

**It reports; it never changes anything.** Every finding names the file that
holds the setting, so you can weigh it against how the host is actually used. A
finding is a question worth answering, not a fault, and some will be correct
for your server.

## Security Presets

```bash
hostguard --preset low
hostguard --preset medium
hostguard --preset high
```

| Preset | Suits |
|--------|-------|
| `low` | A host with many legitimate users who mistype passwords, or one still being set up. Relaxed thresholds, short blocks, reporting checks off. |
| `medium` | The shipped defaults, plus scan detection, bogon filtering and process reporting. A reasonable starting point. |
| `high` | Tight thresholds, long blocks, every reporting check on, distributed attack detection enabled. Expect more false positives and more mail. |

A preset only writes the settings it names, so anything you have tuned by hand
and that is not part of the preset survives. **No preset touches `TCP_IN`,
`TCP_OUT`, `UDP_IN` or `UDP_OUT`**: guessing which ports a host needs is how a
preset locks someone out of their own server.

Reload afterwards:

```bash
hostguard -r
```

## Temporary Allows

An address allowed for a bounded period, which expires on its own without
touching `allow.conf`. This is what a dynamic address, a contractor who needs
access for an afternoon, or a one-off migration wants.

```bash
hostguard -ta 203.0.113.50 7200 "contractor, this afternoon"
hostguard -la                      # list active temporary allows
hostguard -tar 203.0.113.50        # revoke early
```

Temporary allows sit beside permanent ones and are equally final: an address
allowed this way is not then examined by the deny list, the block lists or the
country rules. They survive a firewall reload with the time they have left,
rather than being extended.

Requires `LF_IPSET = "1"`.

## Server Clustering

Propagates blocks between HostGuard Pro servers, so an address that attacks one
member is refused by all of them.

### Setup

On one member, generate the shared secret and copy it to every other:

```bash
openssl rand -hex 32 > /etc/hostguard/cluster.key
chmod 600 /etc/hostguard/cluster.key
chown root:root /etc/hostguard/cluster.key
```

**The key is refused, not merely reported, when it is not safe to use.** The
cluster stops rather than running on a key that cannot be trusted:

| State | Result |
|-------|--------|
| Readable or writable by group or other (any of `0077`) | refused |
| Owned by an account other than root | refused |
| Shorter than 16 characters | refused |
| Absent or empty | cluster inactive |
| Mode `0600` or `0400`, root-owned, 16+ characters | accepted |

This key is the whole of the cluster's security. Anyone holding it can tell
every member to block or allow any address, so on a shared host a readable key
means every account on the machine can do that. Carrying on with a warning
would leave the warning as the only protection, and a log line repeated every
minute is not protection. `ssh` refuses a private key with loose permissions
for the same reason.

`hostguard --cluster list` names the exact problem and the command that fixes
it:

```
Key:      INSECURE_MODE
          /etc/hostguard/cluster.key is mode 0644; anyone who can read it can
          forge cluster messages. Run: chmod 600 /etc/hostguard/cluster.key
```

On every member, list the others in `/etc/hostguard/cluster.conf`:

```
203.0.113.10        # web01
203.0.113.11        # web02
```

And in `hostguard.conf`:

```
CLUSTER_ENABLE = "1"
CLUSTER_PORT = "7654"
CLUSTER_BIND = "203.0.113.10"    # this member's own interface
CLUSTER_WINDOW = "300"
```

Open the port to members only, never to the internet. Add each member to the
allowlist and restrict the port with an advanced filter in `allow.conf`:

```
tcp|in|d=7654|s=203.0.113.11
```

Then:

```bash
hostguard -r
hostguard --cluster list     # confirm configuration
hostguard --cluster ping     # confirm members are reachable
```

### How it works

A message is a single authenticated line over TCP:

```
HG1|<timestamp>|<action>|<address>|<reason>|<hmac>
```

Three things must hold before a message is acted on: the sender is a configured
member, the HMAC over the contents verifies, and the timestamp is inside
`CLUSTER_WINDOW` seconds of now. The secret is never sent. The last check is
what stops a message captured today from being replayed next week, which is
why **members need roughly synchronised clocks**. Run NTP.

Only `DENY`, `TEMPDENY`, `ALLOW`, `UNBLOCK` and `PING` are accepted. A member
cannot ask another to run a command, change its configuration or read a file;
the protocol has no way to express any of those. A member applies what it is
told and does not pass it on, so a block cannot loop around the cluster.

### What a broadcast costs the daemon

Every member is contacted at once, over non-blocking sockets watched by a
single `select`, and `CLUSTER_TIMEOUT` bounds the broadcast as a whole rather
than each member in turn. `CLUSTER_MAX_PARALLEL` caps how many connections are
open at any moment; members past that start as earlier ones finish, still
inside the one deadline.

This matters because of who is calling. A broadcast happens inside `block_ip`,
on the daemon's main loop, during the flood that produced the block - and the
loop is meanwhile not reading the logs the next block would come from. Sending
in turn cost `CLUSTER_TIMEOUT` for each unreachable member, so a six-member
cluster with three hosts down stalled the daemon for fifteen seconds every time
it blocked an address. It is now five, whatever the size of the cluster.

Delivery remains best effort. A member that is down is logged and skipped: a
cluster that stopped blocking locally because a peer was offline would be worse
than one briefly out of step.

### IPv4 and IPv6

Both are supported. A member is reached over whichever family its address
belongs to, and `CLUSTER_BIND` takes a comma-separated list so a dual-stack
host can listen on both:

```
CLUSTER_BIND = "203.0.113.10,2001:db8::10"
```

One socket is opened per address rather than relying on a single IPv6 socket
also accepting IPv4, because whether it does depends on the kernel's
`IPV6_V6ONLY` default and is the kind of difference that shows up only on
someone else's machine.

Members are compared as addresses, not as text, so `2001:db8::1` and
`2001:0db8:0000:0000:0000:0000:0000:0001` are the same member. A connection
arriving on a v6 socket from a v4 address is reduced from `::ffff:203.0.113.1`
to `203.0.113.1` before it is matched, so it still matches the member list as
written.

### Manual operations

```bash
hostguard --cluster deny 198.51.100.9 "attacked web01"
hostguard --cluster allow 203.0.113.99 "office"
hostguard --cluster unblock 198.51.100.9
```

## Notifications

Every message HostGuard Pro sends passes through one engine with three guards,
because the events that most need reporting are exactly the ones that arrive in
floods.

```
NOTIFY_ENABLE = "1"              # master switch
NOTIFY_MAX_PER_HOUR = "20"       # ceiling per kind of notice, 0 = unlimited
NOTIFY_REPEAT_INTERVAL = "3600"  # suppress an identical notice for this long
```

Individual switches:

| Setting | Reports |
|---------|---------|
| `LF_EMAIL_ALERT` | Blocks and permanent promotions |
| `NOTIFY_SSH_LOGIN` | Every successful SSH login |
| `NOTIFY_SU_LOGIN` | `su` attempts, successful and failed |
| `NOTIFY_WHM_ROOT` | Root logins to WHM |
| `NOTIFY_ACCOUNT_MOD` | Account database changes |
| `LOAD_ALERT` | Sustained high load |
| `RELAY_ALERT` | Accounts sending too much mail |
| `PROC_ALERT` / `PROC_USAGE_ALERT` / `PROC_COUNT_ALERT` | Process findings |
| `FILE_ALERT` / `WATCH_ALERT` / `INTEGRITY_ALERT` | File findings |
| `SCAN_ALERT` | Port scans |
| `LOGIN_RATE_ALERT` | Addresses over the hourly login limit |
| `CLUSTER_ALERT` | Actions received from cluster members |
| `SECURITY_ALERT` | Daily security check findings |

Suppression state persists across daemon restarts, so restarting is not a way
around the ceilings.

### The counters are shared, not per process

The ceiling applies to the host. Several processes can send a notice: the
daemon does most of it, and the CLI and the WHM interface reach the same
reporting code through the process, file and security checks.

Each decision is taken with an exclusive lock held over the whole read, decide
and write, against what is on disk rather than against a copy held in memory.
Without that, each process enforced its own private ceiling and roughly that
many times the limit got out.

The lock is `alerts.state.lock`, deliberately a separate file from
`alerts.state`: the state is replaced by rename, and a lock taken on a file
that is about to be replaced belongs to the old inode and protects nothing.

If the lock cannot be taken, because the data directory is missing, read-only
or full, the limits fall back to being applied per process and an error names
the cause:

```
[ERROR] Cannot lock /var/lib/hostguard/alerts.state.lock: ... Notice limits are
being applied per process instead of per host, so more mail than
NOTIFY_MAX_PER_HOUR may be sent. Check that /var/lib/hostguard exists and is
writable.
```

Notices are still limited, just less tightly. They are not stopped: a host that
has developed a disk problem should not also stop reporting the attack that is
under way. Recipients are checked for the newline that would allow
header injection, and the message is piped to `sendmail` rather than passed on
a command line.

## Alert Templates

Every notice renders from a plain-text template in
`/usr/local/hostguard/tpl/`, one per kind:

| Template | Notice |
|----------|--------|
| `block_alert.txt` | An address was temporarily blocked |
| `perm_block_alert.txt` | An address was promoted to a permanent block |
| `ssh_login.txt` | A successful SSH login |
| `su_login.txt` | An `su` attempt, successful or failed |
| `whm_root.txt` | A root login to WHM |
| `login_rate.txt` | An address over the hourly login limit |
| `port_scan.txt` | A source blocked for scanning closed ports |
| `cluster_event.txt` | An action received from a cluster member |
| `suspicious_process.txt` | A process matching an exploit shape |
| `process_usage.txt` | A process over a CPU or memory ceiling |
| `process_count.txt` | An account running too many processes |
| `suspicious_file.txt` | A file found in a world-writable directory |
| `watch_change.txt` | A watched path changed |
| `integrity_change.txt` | A system binary changed |
| `account_change.txt` | The account database changed |
| `load_average.txt` | Load stayed above the limit |
| `relay_alert.txt` | An account sending too much mail |
| `security_check.txt` | Daily security check findings |

### Editing one

Placeholders are written `[NAME]` and are replaced when the notice is sent.
`[HOSTNAME]`, `[TIME]` and `[SUBJECT]` are available in every template; the
rest depend on the kind. The quickest way to see which a template accepts is
to read the one that ships, since every placeholder in it is one HostGuard Pro
supplies.

An unknown placeholder is left in the text as written rather than blanked, so
a typo shows up in the message instead of disappearing.

Templates are read at send time, so an edit takes effect on the next notice.
There is nothing to reload.

### What happens if a template is broken

A template that is missing, unreadable or empty falls back to built-in plain
text carrying the same facts. A notice is never lost because its template was
edited badly, and never sent empty.

To go back to the shipped wording for one template, delete it and reinstall,
or copy it from the `.dist` file if an upgrade left one.

### Upgrades

An upgrade compares each template with the version it is replacing:

- unchanged from the shipped version, it is updated in place
- edited locally, your version is kept and the new one is written alongside as
  `NAME.txt.dist`
- missing entirely, it is installed

So local wording survives an upgrade, and a template for a newly added notice
kind arrives without you having to ask for it.

## System Statistics

```
STATS_ENABLE = "1"
```

Samples load, CPU, memory, process count and active blocks once a minute,
keeping roughly a day. Shown as graphs on the Statistics page in WHM, drawn as
inline SVG: no third-party charting script runs inside an authenticated WHM
session.

## Turning Things On Safely

Every subsystem above ships off. A reasonable order:

1. Run `hostguard --security` and read the findings.
2. Run `hostguard --scan` and see what a normal day looks like on your host.
   Add anything expected to `procignore.conf`.
3. Enable the reporting checks (`PROC_SCAN`, `FILE_SCAN`, `INTEGRITY_ENABLE`)
   and live with the mail for a week.
4. Only then enable anything that acts: `SCAN_ENABLE`, `LOGIN_RATE_BLOCK`,
   `PROC_USAGE_KILL`, `GEO_ALLOW`.

The reason for the order is that every acting check has a false positive rate
you cannot know in advance, and the cost of finding it out in production is
paid by your users.

## Service Sandboxing

Both units run as root and are confined with systemd's sandboxing directives.
The daemon cannot stop being root: it drives iptables and ipset, reads every
authentication log, reads `/etc/shadow` to notice a changed password, and walks
`/proc` across every account. What the confinement does is reduce what a fault
in it can reach.

| | `hostguard` | `hostguardd` |
|---|---|---|
| Filesystem | read-only except its own paths | read-only except its own paths |
| Writable | `/etc/hostguard`, `/var/lib/hostguard`, `/var/log/hostguard`, `/etc/cron.d` | `/etc/hostguard/deny.conf`, `/etc/hostguard/allow.conf`, `/var/lib/hostguard`, `/var/log/hostguard`, `/run` |
| Capabilities | `NET_ADMIN`, `NET_RAW`, `DAC_READ_SEARCH` | those plus `KILL`, `SYS_PTRACE`, `SETUID`, `SETGID` |
| `/home` | inaccessible | read-only |
| `/tmp` | private | **shared, deliberately** |

`CAP_SYS_MODULE`, `CAP_SYS_BOOT`, `CAP_SYS_ADMIN` and `CAP_SYS_RAWIO` are
dropped from both.

### What the daemon can still write under /etc

Two files, not the directory: `deny.conf`, which it appends to when it promotes
an address to a permanent block, and `allow.conf`, which it appends to when a
cluster member sends an `ALLOW`. Those are the only writes it makes under
`/etc`, and the unit names them individually rather than the directory they are
in.

The difference is worth the awkwardness. With `/etc/hostguard` writable, a
fault in this daemon could rewrite `hostguard.conf` - which carries
`PRE_SCRIPT`, `POST_SCRIPT` and `BLOCK_REPORT`, every one of them a command
this service runs as root on the next reload - or replace `cluster.key`,
`patterns.conf` or `watch.conf`. None of that is anything the daemon needs to
do, and all of it survives a restart, which is what separates a fault from an
incident.

Both files must exist for the service to start: systemd cannot bind-mount a
path that is not there, and the unit fails with `No such file or directory`
rather than starting unprotected. The installer creates them. If one is
deleted:

```bash
touch /etc/hostguard/deny.conf && chmod 600 /etc/hostguard/deny.conf
```

**What is left.** `deny.conf` is security policy, and the daemon can still
append to it - that is what an automatic permanent block *is*. A fault in the
daemon can therefore still add addresses to the deny list persistently. Closing
that would mean moving the mutable half of the policy out of `/etc` entirely:
the daemon writing its promotions to `/var/lib/hostguard` and a separate,
tightly scoped step merging them into `deny.conf`. That is a change to where
the files live and to what an administrator edits, so it is named here as the
remaining step rather than made quietly.

### Two directives that are set the way they are on purpose

**`PrivateTmp=no` on the daemon.** Turning it on is the usual first step in
hardening a unit, and here it would break file scanning without any sign of it.
`FILE_SCAN` exists to find payloads dropped in `/tmp`, `/var/tmp` and
`/dev/shm`. A private namespace means it scans an empty directory and reports
nothing for as long as it is enabled. The setting is written out explicitly so
it is not tidied away later.

**`/etc/cron.d` writable by the firewall unit.** With `TESTING=1` the CLI
installs `/etc/cron.d/hostguard_testing`, the entry that clears the firewall
every few minutes so a bad ruleset cannot lock you out permanently. Without
that path the safety net silently fails to install, which is the worst thing to
lose.

### Checking it

```bash
systemd-analyze security hostguardd.service
systemd-analyze security hostguard.service
```

A confinement problem does not stop the service. It starts, and one feature
quietly stops working, so check the specific things after an upgrade:

```bash
hostguard --scan                       # finds files in the real /tmp
hostguard -a 203.0.113.9 "test"        # writes /etc/hostguard/allow.conf
hostguard -tr 203.0.113.9
journalctl -u hostguardd | grep -i 'permission denied\|read-only'
```

An `EROFS` or `EPERM` in the journal after an upgrade almost always means a
path or capability is missing from the unit rather than a bug in the daemon.

### If a hook needs more

`PRE_SCRIPT`, `POST_SCRIPT` and `BLOCK_REPORT` run inside the same confinement
as the service that calls them. A hook that writes outside the paths above,
signals a process, or relies on a setuid helper needs the relevant line relaxed
in the unit:

```bash
systemctl edit hostguardd.service
```

```ini
[Service]
ReadWritePaths=/var/lib/myhook
```

Relax the specific line rather than deleting the section. An override file
survives an upgrade; edits to the shipped unit do not.

## Starting and Stopping the Daemon

There are three ways to reach the daemon, and they now converge on one:

```bash
systemctl start hostguardd          # systemd directly
hostguard --start-daemon            # the CLI
# WHM > HostGuard Pro > Services    # the buttons, which call the CLI
```

**Where systemd owns the unit, all three go through systemd.** The CLI checks
whether systemd is pid 1, the unit is installed, and `systemctl` exists; if so
it hands over rather than starting the daemon itself. Only on a host without
systemd does it start the process directly.

That matters for three reasons, each of which used to be a way for the two to
disagree:

**A daemon started directly is outside the unit's sandbox.** Everything in
`hostguardd.service` (`ProtectSystem`, `ReadWritePaths`, `CapabilityBoundingSet`)
applies to the cgroup systemd creates. Starting the process from the CLI put it
outside that cgroup, so none of the confinement applied, and nothing said so.

**A daemon stopped directly comes back.** The unit carries
`Restart=on-failure`. Signalling the process out from under systemd looked like
a failure, so systemd restarted it moments later and the stop appeared not to
have worked.

**Two daemons could run at once.** `systemctl start` did not consult the pid
file, so starting the unit while a CLI-started daemon was running produced a
second one. Both tailed the same logs, both blocked, and both wrote
`tempblock.dat`, `alerts.state` and `block_history.dat`.

### The daemon refuses to be a second instance

Whatever starts it, the daemon takes an exclusive lock on
`/var/lib/hostguard/hostguardd.lock` and holds it for its lifetime. A second
one exits rather than starting:

```
HostGuard Pro daemon is already running (PID 4127).
Refusing to start a second one: two daemons would block the same addresses and
write the same state files.
```

The lock is a separate file from the pid file, because the pid file is
rewritten on every start and a lock on a file about to be replaced protects
nothing.

### Checking which mechanism is in force

```bash
hostguard -s
```

```
Daemon:    RUNNING (PID 4127)
Managed:   systemd (unit is active)
```

or, on a host without systemd:

```
Managed:   directly, without systemd
           the unit sandbox does not apply to a daemon started this way
```

## Systemd Services

```bash
# Firewall
systemctl start hostguard
systemctl stop hostguard
systemctl restart hostguard
systemctl status hostguard

# Daemon
systemctl start hostguardd
systemctl stop hostguardd
systemctl restart hostguardd
systemctl status hostguardd
```

## Running Alongside Another Firewall

HostGuard Pro does not assume it owns this host's firewall.

It filters by inserting a jump at the top of `INPUT` and `OUTPUT` into its own
chains, which end in an explicit drop. **It does not set the `INPUT` or `OUTPUT`
default policies** - those chains' policies belong to whoever set them, which on
a host also running CSF, firewalld, ufw, shorewall or a hand-written policy is
not HostGuard Pro.

The one policy it does set is IPv4 `FORWARD`, from `FORWARD_POLICY`. Before
changing it, the previous value is recorded in
`/var/lib/hostguard/saved_policies`, and `hostguard --stop` puts that value
back. A policy with no record is left exactly as it is.

That matters most on a host running Docker, which owns `FORWARD` and relies on
it to keep its networks isolated. Setting it to `ACCEPT` on the way out - which
is what stopping used to do - removed that isolation until Docker next
rewrote its rules.

### Uninstalling on such a host

`uninstall.sh` looks for CSF, firewalld, ufw, shorewall, nftables, fail2ban and
Docker before it does anything, and names what it finds:

```
[WARN] Something else is managing this host's firewall:
  - CSF (ConfigServer Security & Firewall)
  - Docker (it owns the FORWARD policy and its own chains)

[WARN] Only HostGuard Pro's own chains, sets and rules will be removed.
```

It removes HostGuard Pro's chains, sets and rules, restores any policy in the
saved record, and changes no other default policy. Whatever else was filtering
this host before is still filtering it afterwards.

## Uninstallation

```bash
cd /usr/src/hostguard-pro
bash uninstall.sh
```

The uninstaller will:
1. Stop the services and remove HostGuard Pro's own chains, ipsets and rules,
   leaving every other firewall's rules and default policies alone (see
   *Running Alongside Another Firewall* above)
2. Remove systemd services
3. Remove the WHM plugin
4. Back up configuration to `/root/hostguard_backup/`
5. Remove all installed files

## File Reference

| Path | Purpose |
|------|---------|
| `/etc/hostguard/hostguard.conf` | Main configuration |
| `/etc/hostguard/allow.conf` | Allowlisted IPs |
| `/etc/hostguard/deny.conf` | Permanently denied IPs |
| `/etc/hostguard/ignore.conf` | Daemon-ignored IPs |
| `/etc/hostguard/blocklists.conf` | External block list definitions |
| `/etc/hostguard/patterns.conf` | Your own log failure patterns |
| `/etc/hostguard/watch.conf` | Paths watched for changes |
| `/etc/hostguard/cluster.conf` | Cluster members |
| `/etc/hostguard/cluster.key` | Cluster shared secret (mode 0600) |
| `/etc/hostguard/procignore.conf` | Process and file scan exceptions |
| `/usr/local/hostguard/bin/hostguard` | CLI tool |
| `/usr/local/hostguard/bin/hostguardd` | Login failure daemon |
| `/usr/local/hostguard/lib/` | Perl modules |
| `/usr/local/hostguard/tpl/` | Alert templates, one per notice kind |
| `/var/lib/hostguard/` | Runtime data (temp blocks, counters) |
| `/var/lib/hostguard/tempallow.dat` | Active temporary allows |
| `/var/lib/hostguard/blocklists/` | Cached external block lists |
| `/var/lib/hostguard/geo/` | Cached country zone files |
| `/var/lib/hostguard/integrity.db` | Binary integrity baseline |
| `/var/lib/hostguard/watch.db` | Watched path baseline |
| `/var/lib/hostguard/accounts.db` | Account database baseline |
| `/var/lib/hostguard/stats.rrd` | Sampled statistics for the graphs |
| `/var/log/hostguard/daemon.log` | Daemon log |
| `.../whostmgr/docroot/cgi/hostguard/hostguard.cgi` | WHM interface |
| `.../whostmgr/docroot/cgi/hostguard/hostguard.css` | WHM stylesheet |
