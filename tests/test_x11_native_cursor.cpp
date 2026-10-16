// SPDX-License-Identifier: GPL-3.0-or-later

#include "../src/x11/x11_cursor_tracker.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <xcb/xcb.h>

int main()
{
    // An invalid native FD produces a failed XCB object, not a live X
    // connection. No DISPLAY lookup, remote input, or cursor image read.
    xcb_connection_t *connection = xcb_connect_to_fd(-1, nullptr);
    assert(connection != nullptr);
    assert(xcb_connection_has_error(connection) != 0);

    X11CursorTracker cursor(*connection, XCB_WINDOW_NONE);
    assert(!cursor.valid());
    assert(std::string_view(cursor.failureReason()) ==
           "XFixes cursor connection is already failed");
    assert(!cursor.hasImage());
    assert(!cursor.refresh());

    // Cancellation must clear the borrowed connection before the
    // XCB owner destroys it; all later access stays independent of XCB.
    cursor.disconnect();
    xcb_disconnect(connection);
    cursor.disconnect();
    assert(!cursor.valid());
    assert(std::string_view(cursor.failureReason()) ==
           "XFixes cursor tracker is disconnected");
    assert(!cursor.pending());
    assert(!cursor.hasImage());
    assert(cursor.pixels().empty());
    assert(cursor.mask().empty());
    assert(cursor.widthPixels() == 0 && cursor.heightPixels() == 0);
    assert(cursor.hotspotX() == 0 && cursor.hotspotY() == 0);
    assert(cursor.refreshFailureReason() == nullptr);
    assert(cursor.refreshErrorCode() == 0);
    assert(cursor.refreshConnectionError() == 0);
    assert(!cursor.takeUnsupportedCursorWarning());
    assert(!cursor.takeRefreshFailureWarning());

    xcb_generic_event_t event{};
    event.response_type = 1;
    cursor.handle(event);
    assert(!cursor.handles(event));
    assert(!cursor.pending());
    assert(!cursor.refresh());
    assert(cursor.pixels().empty());
    cursor.acknowledge();
    assert(!cursor.pending());
    return 0;
}
