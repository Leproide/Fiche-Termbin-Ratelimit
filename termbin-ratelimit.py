#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# termbin-ratelimit - Paste rate limiter for fiche/termbin (tcp/9999).
# Tails fiche.log, applies sliding-window rate limits per source IP,
# bans offenders via a dedicated nftables table and reports them to IPThreat.
#
# Copyright (C) 2026 Leproide
# Author: https://github.com/Leproide
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuration (environment variables, see termbin-ratelimit.env)
# ---------------------------------------------------------------------------

def env_str(name, default):
    return os.environ.get(name, default).strip()


def env_int(name, default):
    try:
        return int(env_str(name, str(default)))
    except ValueError:
        sys.exit(f"Invalid integer for {name}")


def env_bool(name, default=False):
    return env_str(name, "1" if default else "0").lower() in ("1", "true", "yes", "on")


# IPThreat flag bitmask values (https://ipthreat.net/bulkreportformat)
IPTHREAT_FLAG_VALUES = {
    "dns": 1, "fraud": 2, "ddos": 4, "bruteforce": 8, "proxy": 16,
    "spam": 32, "vpn": 64, "hacking": 128, "badbot": 256,
    "compromised": 512, "phishing": 1024, "iot": 2048,
    "portscan": 4096, "ai": 8192,
}


def parse_rules(spec):
    """'10/60,0/600,60/3600' -> [(10, 60), (60, 3600)]: max hits allowed per window (s).
    A rule with max 0 is disabled and skipped."""
    rules = []
    for part in filter(None, (p.strip() for p in spec.split(","))):
        try:
            limit, window = (int(x) for x in part.split("/"))
        except ValueError:
            sys.exit(f"Invalid rule '{part}' (expected hits/seconds)")
        if limit < 0 or window < 1:
            sys.exit(f"Invalid rule '{part}' (max >= 0, seconds >= 1)")
        if limit == 0:
            continue                      # 0 = rule disabled
        rules.append((limit, window))
    return rules


def parse_whitelist(spec):
    nets = []
    for item in filter(None, (p.strip() for p in spec.split(","))):
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            sys.exit(f"Invalid whitelist entry '{item}'")
    return nets


def parse_flags(spec):
    """Accepts an integer bitmask or comma-separated flag names."""
    if spec.isdigit():
        return int(spec)
    value = 0
    for name in filter(None, (p.strip().lower() for p in spec.split(","))):
        if name not in IPTHREAT_FLAG_VALUES:
            sys.exit(f"Unknown IPThreat flag '{name}'")
        value |= IPTHREAT_FLAG_VALUES[name]
    return value


LOG_PATH = env_str("TB_LOG_PATH", "/opt/termbin/logs/fiche.log")
# fiche line: "<slug> -- Sun Oct  4 08:34:37 2026 -- 1.2.3.4 (hostname)"
# Named groups: "ip" (required), "ts" (optional, event timestamp),
# "slug" (optional, paste id; needed for TB_DELETE_PASTES)
LINE_REGEX = re.compile(env_str(
    "TB_LINE_REGEX",
    r"^(?P<slug>\S+)\s--\s(?P<ts>.+?)\s--\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s\(",
))
# strptime format of the "ts" group (fiche writes local time, C locale)
TS_FORMAT = env_str("TB_TS_FORMAT", "%a %b %d %H:%M:%S %Y")
RULES = parse_rules(env_str("TB_RULES", "6/60,15/600,40/3600"))
BAN_TIME = env_int("TB_BAN_TIME", 86400)              # seconds, auto-expire
BAN_PORT = env_str("TB_BAN_PORT", "9999")             # empty = block all ports
NFT_TABLE = env_str("TB_NFT_TABLE", "termbin_ratelimit")
WHITELIST = parse_whitelist(env_str("TB_WHITELIST", "127.0.0.1"))
POLL_INTERVAL = float(env_str("TB_POLL_INTERVAL", "0.5"))
DRY_RUN = env_bool("TB_DRY_RUN")                      # log only, no ban/report/delete

# Delete the pastes created by a banned IP (those inside the tracked windows)
DELETE_PASTES = env_bool("TB_DELETE_PASTES")
PASTE_DIR = env_str("TB_PASTE_DIR", "/var/www/termbin/paste")
SLUG_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")         # safe paste id charset

IPTHREAT_KEY = env_str("TB_IPTHREAT_KEY", "")         # empty = reporting disabled
IPTHREAT_URL = env_str("TB_IPTHREAT_URL", "https://api.ipthreat.net/api/report")
IPTHREAT_FLAGS = parse_flags(env_str("TB_IPTHREAT_FLAGS", "DDos,Spam"))
IPTHREAT_SYSTEM = env_str("TB_IPTHREAT_SYSTEM", "Termbin")[:32]  # API limit: 32 chars

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("termbin-ratelimit")

# ---------------------------------------------------------------------------
# Firewall: dedicated nftables table, independent from firewalld/IPBan.
# - firewalld (nft backend) only manages "table inet firewalld" and does not
#   touch foreign tables on reload.
# - In nftables a DROP in any base chain is final, so firewalld/IPBan
#   "accept" verdicts cannot override it; no ordering conflicts.
# - Hook prerouting (priority -150, before DNAT) covers both a native fiche
#   (INPUT path) and a Docker-published port (FORWARD path).
# ---------------------------------------------------------------------------

def run(cmd, check=True, stdin=None):
    return subprocess.run(cmd, capture_output=True, text=True, check=check, input=stdin)


def firewall_setup():
    """Create table/set/chain idempotently; existing set entries are preserved."""
    port_match = f"tcp dport {BAN_PORT} " if BAN_PORT else ""
    ruleset = f"""
table inet {NFT_TABLE} {{
    set banned4 {{
        type ipv4_addr
        flags timeout
    }}
    chain prerouting {{
        type filter hook prerouting priority -150; policy accept;
    }}
}}
flush chain inet {NFT_TABLE} prerouting
add rule inet {NFT_TABLE} prerouting ip saddr @banned4 {port_match}counter drop
"""
    res = run(["nft", "-f", "-"], check=False, stdin=ruleset)
    if res.returncode != 0:
        sys.exit(f"nft setup failed: {res.stderr.strip()}")
    log.info("nftables table 'inet %s' ready (drop %s)", NFT_TABLE,
             f"tcp/{BAN_PORT}" if BAN_PORT else "all")


def is_banned(ip):
    return run(["nft", "get", "element", "inet", NFT_TABLE, "banned4", f"{{ {ip} }}"],
               check=False).returncode == 0


def ban(ip):
    res = run(["nft", "add", "element", "inet", NFT_TABLE, "banned4",
               f"{{ {ip} timeout {BAN_TIME}s }}"], check=False)
    if res.returncode != 0:
        log.error("nft ban failed for %s: %s", ip, res.stderr.strip())
        return False
    return True

# ---------------------------------------------------------------------------
# IPThreat reporting (async, never blocks the tail loop)
# ---------------------------------------------------------------------------

def report_ipthreat(ip, hits, window):
    payload = {
        "ip": ip,
        "flags": IPTHREAT_FLAGS,
        "system": IPTHREAT_SYSTEM,
        "notes": f"Paste flood on termbin tcp/{BAN_PORT or 'any'}: "
                 f"{hits} pastes in {window}s",
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": max(1, min(hits, 10)),   # API accepts 1-10
    }
    req = urllib.request.Request(
        IPTHREAT_URL,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "X-API-KEY": IPTHREAT_KEY,
            "User-Agent": "termbin-ratelimit/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            log.info("IPThreat report OK for %s (HTTP %s)", ip, resp.status)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:200]
        log.error("IPThreat report failed for %s: HTTP %s %s", ip, e.code, body)
    except Exception as e:  # network errors, timeouts
        log.error("IPThreat report failed for %s: %s", ip, e)

# ---------------------------------------------------------------------------
# Sliding-window rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, rules):
        self.rules = rules
        self.max_window = max(w for _, w in rules)
        self.hits = defaultdict(deque)

    def hit(self, ip, now, slug=None):
        """Record a hit; return (hits, limit, window) of the first violated rule, else None."""
        dq = self.hits[ip]
        dq.append((now, slug))
        while dq and now - dq[0][0] > self.max_window:
            dq.popleft()
        for limit, window in self.rules:
            count = sum(1 for t, _ in dq if now - t <= window)
            if count > limit:
                return count, limit, window
        return None

    def slugs(self, ip):
        """Paste ids recorded for ip within the largest window."""
        return [slug for _, slug in self.hits.get(ip, ()) if slug]

    def reset(self, ip):
        self.hits.pop(ip, None)

    def gc(self, now):
        """Drop IPs with no hits inside the largest window (bounds memory)."""
        stale = [ip for ip, dq in self.hits.items() if not dq or now - dq[-1][0] > self.max_window]
        for ip in stale:
            del self.hits[ip]

# ---------------------------------------------------------------------------
# Log follower (handles rotation and truncation)
# ---------------------------------------------------------------------------

def follow(path, stop):
    fh, inode, buf, first_open = None, None, "", True
    while not stop.is_set():
        if fh is None:
            try:
                fh = open(path, "r", encoding="utf-8", errors="replace")
            except FileNotFoundError:
                stop.wait(POLL_INTERVAL)
                continue
            inode = os.fstat(fh.fileno()).st_ino
            if first_open:
                fh.seek(0, os.SEEK_END)   # don't replay history at startup
                first_open = False
            buf = ""
            log.info("Following %s", path)

        chunk = fh.read()
        if chunk:
            buf += chunk
            *complete, buf = buf.split("\n")
            yield from complete
            continue

        # EOF: detect rotation (new inode / file gone) or truncation
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None
        if st is None or st.st_ino != inode:
            fh.close()
            fh = None              # reopen new file from the beginning
            continue
        if st.st_size < fh.tell():
            fh.seek(0)
            buf = ""
        stop.wait(POLL_INTERVAL)
    if fh:
        fh.close()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def match_group(match, name):
    """Named group value, or None if the custom regex doesn't define it."""
    try:
        return match.group(name)
    except IndexError:
        return None


def event_time(match, fallback):
    """Epoch of the log line's timestamp; fallback (now) if missing/unparsable."""
    try:
        ts = match.group("ts")
    except IndexError:
        return fallback
    if not ts:
        return fallback
    try:
        t = time.mktime(time.strptime(ts.strip(), TS_FORMAT))
    except (ValueError, OverflowError):
        return fallback
    return min(t, fallback)   # clamp clock skew / future timestamps


def is_whitelisted(addr):
    return any(addr in net for net in WHITELIST)


def delete_pastes(ip, slugs):
    """Remove paste files/dirs of a banned IP. Only direct children of PASTE_DIR."""
    base = os.path.realpath(PASTE_DIR)
    deleted = 0
    for slug in slugs:
        if not SLUG_RE.match(slug):
            log.warning("Skipping unsafe paste id %r from %s", slug, ip)
            continue
        path = os.path.join(base, slug)
        # Guard against symlink escape: must resolve to a direct child of PASTE_DIR
        if os.path.dirname(os.path.realpath(path)) != base:
            log.warning("Skipping %s: resolves outside %s", path, base)
            continue
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)       # fiche layout: <slug>/index.txt
            elif os.path.lexists(path):
                os.unlink(path)
            else:
                continue                  # already gone
            deleted += 1
        except OSError as e:
            log.error("Delete failed for %s: %s", path, e)
    log.warning("DELETED %d/%d pastes of %s", deleted, len(slugs), ip)


def handle_violation(ip, hits, limit, window, slugs):
    if DRY_RUN:
        log.warning("[DRY-RUN] would ban %s: %d pastes in %ds (limit %d)", ip, hits, window, limit)
        if DELETE_PASTES:
            log.warning("[DRY-RUN] would delete %d pastes of %s: %s",
                        len(slugs), ip, " ".join(slugs))
        return
    if is_banned(ip):
        return
    if not ban(ip):
        return
    log.warning("BANNED %s for %ds: %d pastes in %ds (limit %d)", ip, BAN_TIME, hits, window, limit)
    if DELETE_PASTES and slugs:
        delete_pastes(ip, slugs)
    if IPTHREAT_KEY:
        threading.Thread(target=report_ipthreat, args=(ip, hits, window), daemon=True).start()


def main():
    if not DRY_RUN and os.geteuid() != 0:
        sys.exit("Must run as root (nftables)")

    log.info("Rules: %s | ban %ds | port %s | IPThreat %s (flags=%d)",
             ", ".join(f">{l} in {w}s" for l, w in RULES) or "none", BAN_TIME, BAN_PORT or "all",
             "on" if IPTHREAT_KEY else "off", IPTHREAT_FLAGS)
    if DELETE_PASTES:
        if not os.path.isdir(PASTE_DIR):
            sys.exit(f"TB_PASTE_DIR not found: {PASTE_DIR}")
        log.info("Paste deletion on ban: enabled (%s)", PASTE_DIR)
    if not DRY_RUN:
        firewall_setup()

    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    if not RULES:
        # Every rule set to 0: nothing to enforce. Stay up (no systemd restart loop).
        log.warning("All rules disabled (TB_RULES): idle, no bans")
        stop.wait()
        log.info("Stopped")
        return

    limiter = RateLimiter(RULES)
    last_gc = time.time()

    for line in follow(LOG_PATH, stop):
        m = LINE_REGEX.search(line)
        if not m:
            continue
        ip = m.group("ip")
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if is_whitelisted(addr):
            continue

        # Use the event time from the log line, not the read time: a re-read
        # file (rotation, sed -i, truncation) must not look like a burst.
        wall = time.time()
        now = event_time(m, wall)
        if wall - now > limiter.max_window:
            continue   # older than every window: history, ignore
        slug = match_group(m, "slug")
        result = limiter.hit(ip, now, slug)
        if result:
            handle_violation(ip, *result, limiter.slugs(ip))
            limiter.reset(ip)

        if wall - last_gc > 300:
            limiter.gc(wall)
            last_gc = wall

    log.info("Stopped")


if __name__ == "__main__":
    main()
