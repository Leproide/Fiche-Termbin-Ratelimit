#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# termbin-ratelimit - interactive setup / installer.
# Fresh install: asks every parameter (Enter = default).
# Existing install: shows current values (Enter = keep), writes only the
# values you actually change, reuses the existing IPThreat key, adds any
# new parameter missing from an older config.
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

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(SRC_DIR, "termbin-ratelimit.env")
DAEMON_SRC = os.path.join(SRC_DIR, "termbin-ratelimit.py")
UNIT_SRC = os.path.join(SRC_DIR, "termbin-ratelimit.service")

APP_DIR = "/opt/termbin-ratelimit"
UNIT_FILE = "/etc/systemd/system/termbin-ratelimit.service"
SERVICE = "termbin-ratelimit"
# Overridable for testing only
ENV_FILE = os.environ.get("TBSETUP_ENV_FILE", "/etc/termbin-ratelimit.env")

# Where an existing IPThreat key can be borrowed from (first match wins)
IPBAN_CONFIGS = ["/opt/ipban/ipban.override.config", "/opt/ipban/ipban.config"]

RULE_SLOTS = 3
RULE_NAMES = ["breve", "media", "lunga"]

KEY_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

# ---------------------------------------------------------------------------
# Env file helpers
# ---------------------------------------------------------------------------

def read_env(path):
    """KEY=VALUE parser (comments/blank lines ignored, optional quotes stripped)."""
    values = {}
    if not os.path.isfile(path):
        return values
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = KEY_LINE_RE.match(line)
            if not m or line.lstrip().startswith("#"):
                continue
            val = m.group(2).strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            values[m.group(1)] = val
    return values


def update_env(path, updates):
    """Rewrite only the lines of the keys in `updates`; append missing keys.
    Comments, order and every other line are preserved. Atomic write, mode 600."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    done = set()
    for i, line in enumerate(lines):
        m = KEY_LINE_RE.match(line)
        if m and not line.lstrip().startswith("#") and m.group(1) in updates:
            key = m.group(1)
            lines[i] = f"{key}={updates[key]}\n"
            done.add(key)
    missing = [k for k in updates if k not in done]
    if missing:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(f"\n# Added by setup.py ({time.strftime('%Y-%m-%d')})\n")
        lines += [f"{k}={updates[k]}\n" for k in missing]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def ipban_key():
    """Borrow IPThreatApiKey from IPBan's config, if present."""
    rx = re.compile(r'key="IPThreatApiKey"\s+value="([^"]*)"')
    for path in IPBAN_CONFIGS:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                m = rx.search(fh.read())
        except OSError:
            continue
        if m and m.group(1).strip():
            return m.group(1).strip(), path
    return "", None


def mask(key):
    if not key:
        return "(nessuna, report disattivato)"
    return key[:4] + "…" + key[-4:] if len(key) > 12 else "****"

# ---------------------------------------------------------------------------
# Validators: return the normalized value or raise ValueError
# ---------------------------------------------------------------------------

def v_file(raw):
    if not os.path.isfile(raw):
        print(f"  ! attenzione: {raw} non esiste (ancora)")
    return raw


def v_rule_factory(current):
    window = current.split("/")[1] if "/" in current else "60"

    def v_rule(raw):
        if raw == "0":                    # shorthand: disable, keep window
            return f"0/{window}"
        m = re.fullmatch(r"(\d+)\s*/\s*(\d+)", raw)
        if not m:
            raise ValueError("formato: max_paste/secondi (es. 6/60), oppure 0 per disattivare")
        limit, secs = int(m.group(1)), int(m.group(2))
        if secs < 1:
            raise ValueError("i secondi devono essere >= 1")
        return f"{limit}/{secs}"
    return v_rule


def v_int_range(lo, hi):
    def v(raw):
        if not raw.isdigit() or not lo <= int(raw) <= hi:
            raise ValueError(f"intero tra {lo} e {hi}")
        return str(int(raw))
    return v


def v_port(raw):
    if raw.lower() in ("all", "tutte", "*"):
        return ""
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        raise ValueError("porta 1-65535 oppure 'all'")
    return str(int(raw))


def v_whitelist(raw):
    items = [p.strip() for p in raw.split(",") if p.strip()]
    for item in items:
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(f"'{item}' non è un IP/CIDR valido")
    return ",".join(items)


def v_bool(raw):
    r = raw.lower()
    if r in ("true", "1", "y", "yes", "s", "si", "sì"):
        return "true"
    if r in ("false", "0", "n", "no"):
        return "false"
    raise ValueError("true/false")


def v_key(raw):
    if raw == "-":
        return ""                          # explicit removal
    if re.search(r"\s", raw):
        raise ValueError("la chiave non può contenere spazi")
    return raw

# ---------------------------------------------------------------------------
# Prompting
# ---------------------------------------------------------------------------

INTERACTIVE = True


def ask(label, current, validator, shown=None):
    """Enter keeps `current`; invalid input is re-asked."""
    if not INTERACTIVE:
        return current
    shown = current if shown is None else shown
    while True:
        try:
            raw = input(f"{label} [{shown}]: ").strip()
        except EOFError:
            print()
            return current
        if raw == "":
            return current
        try:
            return validator(raw)
        except ValueError as e:
            print(f"  ✗ {e}")


def confirm(question, default=False):
    if not INTERACTIVE:
        return default
    hint = "S/n" if default else "s/N"
    raw = input(f"{question} [{hint}]: ").strip().lower()
    return default if raw == "" else raw in ("s", "si", "sì", "y", "yes")

# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def collect(cur):
    """Ask every parameter; returns the full desired config."""
    new = dict(cur)

    print("\n— Percorsi —")
    new["TB_LOG_PATH"] = ask("Log di fiche", cur["TB_LOG_PATH"], v_file)
    new["TB_DELETE_PASTES"] = ask("Cancellare i paste del flood al ban? (true/false)",
                                  cur["TB_DELETE_PASTES"], v_bool)

    def v_paste_dir(raw):
        if not os.path.isdir(raw):
            if new["TB_DELETE_PASTES"] == "true":
                raise ValueError(f"{raw} non esiste (obbligatoria con la cancellazione attiva)")
            print(f"  ! attenzione: {raw} non esiste")
        return raw.rstrip("/") or "/"

    while True:
        new["TB_PASTE_DIR"] = ask("Directory dei paste (fiche -o)", cur["TB_PASTE_DIR"], v_paste_dir)
        if new["TB_DELETE_PASTES"] != "true" or os.path.isdir(new["TB_PASTE_DIR"]):
            break
        print(f"  ✗ {new['TB_PASTE_DIR']} non esiste: inserisci il percorso corretto")
        if not INTERACTIVE:
            sys.exit("TB_DELETE_PASTES=true ma TB_PASTE_DIR non esiste")

    print("\n— Soglie (max_paste/secondi; più di max paste nella finestra = ban; 0 = disattiva) —")
    existing = [r.strip() for r in cur["TB_RULES"].split(",") if r.strip()]
    defaults = [r.strip() for r in DEFAULTS["TB_RULES"].split(",") if r.strip()]
    slots = existing + defaults[len(existing):RULE_SLOTS]
    rules = []
    for i, current in enumerate(slots):
        name = RULE_NAMES[i] if i < len(RULE_NAMES) else str(i + 1)
        rules.append(ask(f"Regola {i + 1} ({name})", current, v_rule_factory(current)))
    active = [r for r in rules if not r.startswith("0/")]
    if not active:
        print("  ! tutte le soglie sono a 0: il servizio non banna nessuno")
        if not confirm("Confermi?", default=False):
            return collect(cur)
    new["TB_RULES"] = ",".join(rules)

    print("\n— Ban —")
    new["TB_BAN_TIME"] = ask("Durata ban (secondi)", cur["TB_BAN_TIME"], v_int_range(1, 31536000))
    new["TB_BAN_PORT"] = ask("Porta bloccata ('all' = tutte)", cur["TB_BAN_PORT"], v_port,
                             shown=cur["TB_BAN_PORT"] or "all")
    new["TB_WHITELIST"] = ask("Whitelist (IP/CIDR, virgole)", cur["TB_WHITELIST"], v_whitelist)

    print("\n— IPThreat —")
    new["TB_IPTHREAT_KEY"] = ask("API key (invio = mantieni, '-' = rimuovi)",
                                 cur["TB_IPTHREAT_KEY"], v_key, shown=mask(cur["TB_IPTHREAT_KEY"]))
    return new


def describe_rules(spec):
    out = []
    for r in spec.split(","):
        limit, secs = (int(x) for x in r.split("/"))
        out.append(f"  {r:>10}  disattivata" if limit == 0
                   else f"  {r:>10}  ban al paste n.{limit + 1} entro {secs}s")
    return "\n".join(out)


def install_file(src, dst, mode):
    """Copy src -> dst, skipping when they are the same file
    (package extracted directly into the install directory)."""
    if not (os.path.exists(dst) and os.path.samefile(src, dst)):
        shutil.copy2(src, dst)
    os.chmod(dst, mode)


def install_service():
    os.makedirs(APP_DIR, mode=0o755, exist_ok=True)
    install_file(DAEMON_SRC, os.path.join(APP_DIR, "termbin-ratelimit.py"), 0o755)
    install_file(UNIT_SRC, UNIT_FILE, 0o644)
    for cmd in (["systemctl", "daemon-reload"],
                ["systemctl", "enable", SERVICE],
                ["systemctl", "restart", SERVICE]):
        subprocess.run(cmd, check=True, capture_output=True)
    time.sleep(2)
    subprocess.run(["journalctl", "-u", SERVICE, "-n", "6", "--no-pager"])


def main():
    global INTERACTIVE, DEFAULTS
    ap = argparse.ArgumentParser(description="termbin-ratelimit setup")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="non interattivo: mantiene i valori esistenti (o i default)")
    ap.add_argument("--config-only", action="store_true",
                    help="aggiorna solo la config, senza installare/riavviare il servizio")
    args = ap.parse_args()
    INTERACTIVE = not args.yes
    if INTERACTIVE and not sys.stdin.isatty():
        sys.exit("Nessun terminale: usa --yes per la modalità non interattiva")

    if os.geteuid() != 0 and "TBSETUP_ENV_FILE" not in os.environ:
        sys.exit("Esegui come root")
    if not args.config_only and not shutil.which("nft"):
        sys.exit("nft non trovato (apt install nftables)")

    DEFAULTS = read_env(TEMPLATE)
    exists = os.path.isfile(ENV_FILE)
    existing = read_env(ENV_FILE)
    cur = {**DEFAULTS, **existing}

    # Reuse key: existing env first, then IPBan's config
    if not cur.get("TB_IPTHREAT_KEY"):
        key, src = ipban_key()
        if key:
            cur["TB_IPTHREAT_KEY"] = key
            print(f"API key IPThreat trovata in {src}: verrà riutilizzata")

    if exists:
        print(f"Config esistente: {ENV_FILE}\nInvio = mantieni il valore attuale.")
    else:
        print(f"Nuova installazione: {ENV_FILE}\nInvio = valore di default.")

    new = collect(cur)

    if exists:
        # only what differs from the file, plus parameters missing from an older config
        updates = {k: v for k, v in new.items() if existing.get(k) != v}
    else:
        shutil.copy2(TEMPLATE, ENV_FILE)
        os.chmod(ENV_FILE, 0o600)
        updates = {k: v for k, v in new.items() if DEFAULTS.get(k) != v}

    print("\n— Soglie attive —")
    print(describe_rules(new["TB_RULES"]))

    if updates:
        if exists:
            backup = f"{ENV_FILE}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
            shutil.copy2(ENV_FILE, backup)
            os.chmod(backup, 0o600)
            print(f"\nBackup: {backup}")
        update_env(ENV_FILE, updates)
        print("Modificati:")
        for k, v in updates.items():
            print(f"  {k}={mask(v) if k == 'TB_IPTHREAT_KEY' else v}")
    else:
        print("\nNessuna modifica alla config.")

    if args.config_only:
        print("\nSolo config aggiornata. Applica con: systemctl restart termbin-ratelimit")
        return
    print("\nInstallazione servizio…")
    install_service()


DEFAULTS = {}

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAnnullato, nessuna modifica scritta.")
        sys.exit(130)
