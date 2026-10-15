// SPDX-License-Identifier: GPL-3.0-or-later

#include "../src/x11/x11_capture_layout.h"

#include <cassert>
#include <cstdint>
#include <limits>

#if defined(RDP_SERVER_HAVE_NATIVE_XSHM)
#include "../src/x11/x11_shared_memory_capture.h"

#include <string_view>
#include <xcb/xcb.h>
#endif

int main()
{
    using std::uint64_t;
    static_assert(captureArenaPixels({0, 1080}, 1000) == 0);
    static_assert(captureArenaPixels({1920, 0}, 1000) == 0);
    static_assert(captureArenaPixels({1920, 1080}, 0) == 0);
    static_assert(captureArenaPixels({1920, 1080}, 1) == 1920);
    static_assert(captureArenaPixels({1920, 1080}, 1919) == 1920);
    static_assert(captureArenaPixels({1920, 1080}, 1920) == 1920);
    static_assert(captureArenaPixels({1920, 1080}, 1921) == 1921);
    static_assert(captureArenaPixels({1920, 1080}, 2073600) == 2073600);
    static_assert(captureArenaPixels({1920, 1080},
                                     std::numeric_limits<uint64_t>::max()) ==
                  2073600);
    static_assert(captureArenaPixels({65535, 65535}, 1) == 65535);
    static_assert(captureArenaPixels({65535, 65535},
                                     std::numeric_limits<uint64_t>::max()) ==
                  4294836225ULL);

#if defined(RDP_SERVER_HAVE_NATIVE_XSHM)
    // No DISPLAY lookup, X server or live desktop: -1 is an invalid fd.
    xcb_connection_t *connection = xcb_connect_to_fd(-1, nullptr);
    assert(connection != nullptr);
    assert(xcb_connection_has_error(connection) != 0);
    {
        X11SharedMemoryCapture capture(*connection, 1, 1, 24,
                                       {1920, 1080}, 1024);
        assert(!capture.valid());
        assert(std::string_view(capture.failureReason()) ==
               "X11 connection is already failed");
        assert(!capture.capture({0, 0, 4, 4}).valid());
    }
    xcb_disconnect(connection);
#endif
    return 0;
}
