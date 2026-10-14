#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
# Compatibility entry point: no old Git history is imported.
exec python3 "$(dirname "${BASH_SOURCE[0]}")/import-current-progress.py" "$@"
