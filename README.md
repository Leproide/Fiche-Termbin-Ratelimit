<!--
SPDX-License-Identifier: GPL-3.0-or-later
termbin-ratelimit - README
Copyright (C) 2026 Leproide
Author: https://github.com/Leproide
-->

# Termbin/Fiche Ratelimit

A paste rate limiter for Fiche/Termbin (tcp/9999).

[Fiche Original](https://github.com/solusipse/fiche)

[Fiche Custom](https://github.com/Leproide/fiche)

[Termbin Reborn](https://github.com/Leproide/termbin-reborn)

It follows fiche's log and enforces per-IP sliding-window limits. Offenders are banned with nftables. Optionally, the pastes they sent during the flood are deleted. Each ban is reported to [IPThreat](https://ipthreat.net) with flags that match the abuse (DDos + Spam, not BruteForce).

## Contents

- [Why not IPBan](#why-not-ipban)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation and setup](#installation-and-setup)
- [Configuration](#configuration)
- [Rate limits](#rate-limits)
- [Public notice](#public-notice)
- [Paste deletion](#paste-deletion)
- [IPThreat reporting](#ipthreat-reporting)
- [Coexistence with IPBan / firewalld / Docker](#coexistence-with-ipban--firewalld--docker)
- [Managing bans](#managing-bans)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)
- [Layout](#layout)
- [License](#license)
- [Author](#author)

## Why not IPBan

IPBan treats every line that matches `FailedLoginRegex` as a failed login. fiche writes one line per paste, so:

- legitimate users get banned after N pastes in 24h, with no notion of rate;
- every IPThreat report is sent as **BruteForce**, which is wrong for a pastebin.

termbin-ratelimit runs on its own and coexists with IPBan without conflicts.

## How it works

1. It tails `fiche.log` and handles rotation and truncation. History is not replayed on startup.
2. It extracts the slug (paste ID), the timestamp and the IP from each line:
   ```
   mvl83hdcseh3211h -- Sun Oct  4 08:34:37 2026 -- 66.132.186.196 (196.186.132.66.censys-scanner.com)
   ```
3. Counting uses **the timestamp written by fiche**, not the time the line was read. Lines older than the longest window are ignored, so a re-read file (rotation, `sed -i`) is never mistaken for a burst.
4. It enforces the `TB_RULES` limits. Exceeding any active limit means a ban.
5. A ban adds the IP to the `banned4` set of a dedicated nftables table, with a timeout so it expires on its own.
6. With `TB_DELETE_PASTES=true`, the banned IP's pastes are deleted.
7. The IPThreat report is sent asynchronously and never blocks the tail loop.

## Requirements

- Linux with nftables (`nft`); works alongside firewalld with the nftables backend
- Python 3.8+ (standard library only)
- systemd
- root

## Installation and setup

```bash
tar xzf termbin-ratelimit.tar.gz && cd termbin-ratelimit
sudo ./setup.py          # or: sudo ./install.sh (wrapper)
```

The package can be extracted anywhere, including `/opt/termbin-ratelimit` itself.

Setup is interactive. It asks, in order:

| Prompt | Parameter |
|---|---|
| fiche log path | `TB_LOG_PATH` |
| Delete flood pastes on ban? (true/false) | `TB_DELETE_PASTES` |
| Paste directory (`fiche -o`) | `TB_PASTE_DIR` |
| Rule 1 / 2 / 3 (short, medium, long) | `TB_RULES` |
| Ban duration (seconds) | `TB_BAN_TIME` |
| Blocked port (`all` = every port) | `TB_BAN_PORT` |
| Whitelist (IP/CIDR, comma separated) | `TB_WHITELIST` |
| IPThreat API key | `TB_IPTHREAT_KEY` |

Every answer is validated, and an invalid one is asked again. When it finishes, setup installs the daemon in `/opt/termbin-ratelimit/` and the systemd unit, then enables and restarts the service and prints the last journal lines.

### Fresh install

Pressing Enter accepts the **default** from the `termbin-ratelimit.env` template. The config is created at `/etc/termbin-ratelimit.env` with mode `600`.

### Existing config (upgrade)

- Each prompt shows the **current value**. Pressing Enter keeps it.
- **Only the lines of the parameters you change are rewritten.** Comments, ordering and everything else stay untouched.
- Parameters introduced by newer versions that are missing from the config are appended with their defaults, under a `# Added by setup.py` block.
- A backup is made before any write: `/etc/termbin-ratelimit.env.bak-YYYYMMDD-HHMMSS`.
- If nothing changes, the file is not touched.

### API key

- If the config already has a key, it is **reused**. It is shown masked (`AVio…-617`) and Enter keeps it.
- If the config has no key, setup looks for `IPThreatApiKey` in `/opt/ipban/ipban.override.config`, then in `/opt/ipban/ipban.config`, and offers it.
- Paste a new key to replace it, or enter `-` to remove it (reporting disabled).

### Options

| Option | Effect |
|---|---|
| `-y`, `--yes` | Non-interactive: keeps existing values (or defaults) and only adds missing parameters. Useful to upgrade the code. |
| `--config-only` | Updates the config without installing or restarting the service |

Code-only upgrade, no prompts:

```bash
sudo ./setup.py --yes
```

## Configuration

File: `/etc/termbin-ratelimit.env`. It is managed by `setup.py`, but can also be edited by hand followed by `systemctl restart termbin-ratelimit`.

| Variable | Default | In setup | Description |
|---|---|---|---|
| `TB_LOG_PATH` | `/opt/termbin/logs/fiche.log` | ✔ | fiche log file |
| `TB_PASTE_DIR` | `/var/www/termbin/paste` | ✔ | fiche output directory (`fiche -o`) |
| `TB_DELETE_PASTES` | `false` | ✔ | `true` = delete flood pastes on ban |
| `TB_RULES` | `6/60,15/600,40/3600` | ✔ | Limits as `max/seconds`; `0` disables a rule |
| `TB_BAN_TIME` | `86400` | ✔ | Ban duration in seconds |
| `TB_BAN_PORT` | `9999` | ✔ | Blocked port (empty = all ports) |
| `TB_WHITELIST` | `127.0.0.1` | ✔ | IPs/CIDRs never banned, comma separated |
| `TB_IPTHREAT_KEY` | *(empty)* | ✔ | IPThreat API key; empty = reporting disabled |
| `TB_IPTHREAT_FLAGS` | `DDos,Spam` | | Flag names or integer bitmask |
| `TB_IPTHREAT_SYSTEM` | `Termbin` | | "System attacked" field (max 32 chars) |
| `TB_NFT_TABLE` | `termbin_ratelimit` | | nftables table (`inet` family) |
| `TB_DRY_RUN` | `0` | | `1` = log only: no ban, report or deletion |
| `TB_POLL_INTERVAL` | `0.5` | | Log polling interval (seconds) |
| `TB_LINE_REGEX` | *(fiche format)* | | Regex with groups `ip` (required), `ts` and `slug` (optional) |
| `TB_TS_FORMAT` | `%a %b %d %H:%M:%S %Y` | | `strptime` format of the `ts` group |

## Rate limits

Format: `max/seconds`. More than `max` pastes within `seconds` means a ban. Rules are independent: exceeding any one of them is enough.

### Recommended limits (default)

```
TB_RULES=6/60,15/600,40/3600
```

| Rule | Value | Ban on | What it catches |
|---|---|---|---|
| short | `6/60` | 7th paste within 1 minute | Bursts: scripts, scanners, loops |
| medium | `15/600` | 16th paste within 10 minutes | Steady floods just under the burst limit (~1.5/min) |
| long | `40/3600` | 41st paste within 1 hour | Slow, prolonged abuse |

Why three rules: a burst limit alone can be dodged by a bot pasting just under it. At 6/min that's about 360 pastes per hour and 8,600 per day, never banned. A real-world example is a client pasting every ~13 seconds (~4.6/min): the short rule never fires, the medium one stops it within about 10 minutes. Normal use (`cat file | nc termbin.example 9999`, a handful of logs) stays far below all three.

### Setting rules

In setup, each rule is entered as `max/seconds`:

| Input | Effect |
|---|---|
| `6/60` | sets the rule: ban on the 7th paste within 60s |
| `0` | disables the rule, keeping its current window (becomes `0/60`) |
| Enter | keeps the value shown in brackets |
| `6` | invalid: rejected and asked again |

Setup shows three rules. By hand you can define as many as you like (`5/10,6/60,15/600,40/3600`); setup will then show all of them.

If every rule is `0`, setup asks for confirmation, and the service stays up without banning anyone (`All rules disabled`).

At the end, setup prints a summary of the active limits.

### Things to consider

- **Shared IPs** (corporate NAT, universities, mobile CGNAT): one abuser gets everyone behind that IP banned and reported. Whitelist known shared ranges you trust.
- **Report = ban threshold**: a developer who accidentally runs a paste loop is banned for 24h, loses those pastes and is **publicly reported** as DDos/Spam. Tighter limits mean more false positives with public consequences.
- Before tightening limits in production, try them with `TB_DRY_RUN=1`.

## Public notice

Suggested notice for the termbin page, matching the default limits:

```
Rate limits (per IP):
  - max 6 pastes per minute
  - max 15 pastes per 10 minutes
  - max 40 pastes per hour
Exceeding any limit blocks your IP for 24 hours, deletes the pastes
sent during the flood and reports the address to IPThreat.
```

Keep it in sync with `TB_RULES`, `TB_BAN_TIME`, `TB_DELETE_PASTES` and the reporting status.

## Paste deletion

With `TB_DELETE_PASTES=true`, the banned IP's pastes recorded within the longest active window are removed when the ban is applied. The deleted path is `TB_PASTE_DIR/<slug>`, where the slug is the first field of the log line. It can be a directory (fiche layout `<slug>/index.txt`) or a single file.

Safeguards:

- only `[A-Za-z0-9_-]` slugs are accepted;
- the resolved path must be a direct child of `TB_PASTE_DIR`, so no traversal and no symlink escapes;
- with deletion enabled, setup rejects a non-existent `TB_PASTE_DIR`, and the daemon refuses to start;
- in dry-run mode it lists the pastes it would delete without touching them.

Pastes older than the longest window are not deleted. Deletions appear in the journal as `DELETED n/m pastes of <ip>`.

Check that slug and path match:

```bash
SLUG=$(tail -1 /opt/termbin/logs/fiche.log | awk '{print $1}')
ls -la /var/www/termbin/paste/$SLUG
```

## IPThreat reporting

Payload sent to `POST https://api.ipthreat.net/api/report` (header `X-API-KEY`):

```json
{
  "ip": "47.251.170.194",
  "flags": 36,
  "system": "Termbin",
  "notes": "Paste flood on termbin tcp/9999: 16 pastes in 600s",
  "ts": "2026-10-04T19:49:32Z",
  "count": 10
}
```

`count` is the number of pastes, capped at 10 (the API maximum). An IP already in the set is neither banned nor reported again.

| Flag | Value | | Flag | Value |
|---|---|---|---|---|
| Dns | 1 | | Hacking | 128 |
| Fraud | 2 | | BadBot | 256 |
| DDos | 4 | | Compromised | 512 |
| BruteForce | 8 | | Phishing | 1024 |
| Proxy | 16 | | Iot | 2048 |
| Spam | 32 | | PortScan | 4096 |
| Vpn | 64 | | AI | 8192 |

## Coexistence with IPBan / firewalld / Docker

- **Dedicated table** `inet termbin_ratelimit`. firewalld (nftables backend) only manages `inet firewalld` and leaves foreign tables alone on `--reload`. IPBan works inside firewalld.
- **No ordering conflicts.** In nftables a `drop` in any base chain is final, so firewalld/IPBan `accept` verdicts cannot override it.
- **`prerouting` hook, `mangle` priority (-150)**, before DNAT. It covers both a native fiche (INPUT path) and a Docker-published port (FORWARD path).
- **Remove fiche's `<LogFile>` block from `ipban.config`**, otherwise IPBan keeps banning and reporting as BruteForce in parallel.

Check:

```bash
firewall-cmd --reload
nft list table inet termbin_ratelimit      # must still be there
```

## Managing bans

```bash
nft list set inet termbin_ratelimit banned4                            # active bans + expiry
nft list table inet termbin_ratelimit                                  # dropped packet counter
nft delete element inet termbin_ratelimit banned4 { 1.2.3.4 }          # unban
nft add element inet termbin_ratelimit banned4 { 1.2.3.4 timeout 1d }  # manual ban (no report)
journalctl -u termbin-ratelimit -f | grep -E 'BANNED|DELETED|IPThreat'
```

Bans live in memory and **do not survive a reboot**: the service recreates an empty table.

## Testing

No ban, report or deletion. Use a documentation IP (`203.0.113.0/24`) and lines with the current time:

```bash
sed -i 's|^TB_DRY_RUN=.*|TB_DRY_RUN=1|' /etc/termbin-ratelimit.env
systemctl restart termbin-ratelimit && sleep 1

# N = short-rule max + 1 (default 7)
for i in $(seq 1 7); do
  printf '%s -- %s -- 203.0.113.10 (test.invalid)\n' \
    "$(tr -dc a-z0-9 </dev/urandom | head -c16)" \
    "$(LC_ALL=C date '+%a %b %e %T %Y')" >> /opt/termbin/logs/fiche.log
done

journalctl -u termbin-ratelimit -n 3 --no-pager   # expected: [DRY-RUN] would ban 203.0.113.10
sed -i 's|^TB_DRY_RUN=.*|TB_DRY_RUN=0|' /etc/termbin-ratelimit.env
systemctl restart termbin-ratelimit
```

With dry-run off and a key configured, a test sends a **real, public report** to IPThreat. Never test with your own IP.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `IPThreat off` in the startup log | `TB_IPTHREAT_KEY` empty in `/etc/termbin-ratelimit.env`; run `setup.py` again |
| `IPThreat report failed ... HTTP 401/403` | Wrong key or no reporting permission |
| `BANNED` with no `IPThreat report` line | Reporting was `off` when the ban happened |
| `All rules disabled` | Every rule in `TB_RULES` is `0` |
| `TB_PASTE_DIR not found` (service won't start) | Deletion enabled with a non-existent path: run `setup.py` |
| `DELETED 0/n pastes` | `TB_PASTE_DIR` doesn't match fiche's output dir, or the pastes were already gone |
| No bans despite traffic | Check that lines match `TB_LINE_REGEX` and that limits aren't too high |
| Your own IP gets banned | Add it to the whitelist via `setup.py` |
| Setup stops with "Nessun terminale" (no terminal) | No TTY available: use `--yes` |

## Uninstall

```bash
sudo ./uninstall.sh            # removes the service, the nftables table (lifts all bans) and /opt
sudo ./uninstall.sh --purge    # also removes /etc/termbin-ratelimit.env
```

## Layout

```
termbin-ratelimit/
├── termbin-ratelimit.py        # daemon
├── termbin-ratelimit.env       # config template / defaults -> /etc/termbin-ratelimit.env
├── termbin-ratelimit.service   # systemd unit
├── setup.py                    # interactive setup + install
├── install.sh                  # setup.py wrapper
├── uninstall.sh
├── LICENSE
└── README.md
```

## License

GNU General Public License v3.0 or later (GPL-3.0-or-later). See [LICENSE](LICENSE).

## Author

[https://github.com/Leproide](https://github.com/Leproide)
