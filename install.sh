#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# termbin-ratelimit installer (wrapper for setup.py)
# Copyright (C) 2026 Leproide
# Author: https://github.com/Leproide
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See LICENSE.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 ./setup.py "$@"
