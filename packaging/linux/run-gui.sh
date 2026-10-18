#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# No fallback to server CLI, systemd or remote access.
set -eu
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
gui="$package_dir/bin/rdp-server-desktop"
if [ ! -f "$gui" ] || [ ! -x "$gui" ] || [ -L "$gui" ]; then
    printf '%s\n' 'RDP Server GUI unavailable; no listener was started.' >&2
    exit 1
fi
exec "$gui" "$@"
