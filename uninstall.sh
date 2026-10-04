#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# termbin-ratelimit uninstaller
# Copyright (C) 2026 Leproide
# Author: https://github.com/Leproide
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See LICENSE.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

TABLE=$(grep -oP '^TB_NFT_TABLE=\K.*' /etc/termbin-ratelimit.env 2>/dev/null || true)
TABLE=${TABLE:-termbin_ratelimit}

systemctl disable --now termbin-ratelimit 2>/dev/null || true
rm -f /etc/systemd/system/termbin-ratelimit.service
systemctl daemon-reload
nft delete table inet "$TABLE" 2>/dev/null && echo "nftables table removed (all bans lifted)" || true
rm -rf /opt/termbin-ratelimit

# Config is kept unless --purge is given (contains the API key)
if [[ ${1:-} == "--purge" ]]; then
    rm -f /etc/termbin-ratelimit.env
    echo "Config removed"
else
    echo "Config kept: /etc/termbin-ratelimit.env (use --purge to remove)"
fi
