#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Open only the bundled R7 GUI. This does not activate a listener or X11 input.
set -eu
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
gui="$package_dir/bin/rdp-server-desktop"
if [ ! -f "$gui" ] || [ ! -x "$gui" ] || [ -L "$gui" ]; then
    printf '%s\n' 'RDP Server GUI unavailable; no listener was started.' >&2
    exit 1
fi
# Private permissions on any subsequently created per-user GUI configuration.
umask 077
# Bundle-relative Qt/XCB closure works after ordinary ZIP extraction, no FUSE.
LD_LIBRARY_PATH="$package_dir/lib"
QT_QPA_PLATFORM_PLUGIN_PATH="$package_dir/plugins/platforms"
export LD_LIBRARY_PATH QT_QPA_PLATFORM_PLUGIN_PATH
exec "$gui" "$@"
