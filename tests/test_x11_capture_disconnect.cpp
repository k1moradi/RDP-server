// SPDX-License-Identifier: GPL-3.0-or-later

#include "../src/x11/x11_shared_memory_capture.h"

#include <cassert>
#include <memory>
#include <string_view>

#include <xcb/xcb.h>

// No DISPLAY access, X server, capture, credentials or remote input.
// An invalid native descriptor gives a deterministic failed XCB object.
int main()
{
    xcb_connection_t *connection = xcb_connect_to_fd(-1, nullptr);
    assert(connection != nullptr);
    assert(xcb_connection_has_error(connection) != 0);

    auto capture = std::make_unique<X11SharedMemoryCapture>(
        *connection, 1, 1, 24, PixelSize{1920, 1080}, 1024);
    assert(!capture->valid());
    assert(std::string_view(capture->failureReason()) ==
           "X11 connection is already failed");
    assert(!capture->capture({0, 0, 4, 4}).valid());

    // The R5 session owner must cancel XShm before disconnecting XCB.
    // Cancellation and destruction must not dereference a freed parent.
    capture->disconnect();
    xcb_disconnect(connection);
    capture->disconnect();
    assert(!capture->valid());
    assert(std::string_view(capture->failureReason()) ==
           "XShm capture is disconnected");
    assert(!capture->capture({0, 0, 4, 4}).valid());
    assert(!capture->capture({-1, 0, 4, 4}).valid());
    assert(std::string_view(capture->failureReason()) ==
           "XShm capture is disconnected");
    capture.reset();
    return 0;
}
