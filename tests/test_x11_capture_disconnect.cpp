// SPDX-License-Identifier: GPL-3.0-or-later

#include "../src/x11/x11_shared_memory_capture.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string_view>

#include <xcb/xcb.h>

namespace
{

struct XcbConnectionDeleter final
{
    void operator()(xcb_connection_t *connection) const noexcept
    {
        if (connection != nullptr)
        {
            xcb_disconnect(connection);
        }
    }
};

using XcbConnection =
    std::unique_ptr<xcb_connection_t, XcbConnectionDeleter>;

XcbConnection
connectDisplay(const char *display, int &screenNumber)
{
    XcbConnection connection{xcb_connect(display, &screenNumber)};
    assert(connection != nullptr);
    assert(screenNumber >= 0);
    assert(xcb_connection_has_error(connection.get()) == 0);
    return connection;
}

xcb_screen_t *
screenFor(xcb_connection_t &connection, int screenNumber)
{
    const xcb_setup_t *setup = xcb_get_setup(&connection);
    assert(setup != nullptr);

    xcb_screen_iterator_t iterator = xcb_setup_roots_iterator(setup);
    for (int index = 0; index < screenNumber && iterator.rem > 0; ++index)
    {
        xcb_screen_next(&iterator);
    }
    assert(iterator.rem > 0);
    assert(iterator.data != nullptr);
    return iterator.data;
}

void
roundTrip(xcb_connection_t &connection)
{
    xcb_generic_error_t *error = nullptr;
    const auto cookie = xcb_get_input_focus(&connection);
    xcb_get_input_focus_reply_t *reply =
        xcb_get_input_focus_reply(&connection, cookie, &error);
    assert(error == nullptr);
    std::free(error);
    assert(reply != nullptr);
    std::free(reply);
    assert(xcb_connection_has_error(&connection) == 0);
}

void
requireSmallCapture(X11SharedMemoryCapture &capture)
{
    // Keep the borrowed XShm view inside this scope so no pixel span survives
    // the destructor/disconnect boundary being exercised by the caller.
    const FramebufferView frame = capture.capture({0, 0, 4, 4});
    assert(frame.valid());
    assert(frame.widthPixels == 4U);
    assert(frame.heightPixels == 4U);
    assert(frame.strideBytes == 16U);
    assert(frame.pixels.size() == 64U);
}

void
connectionDenialsAndCancellation()
{
    // No DISPLAY access, X server, capture, credentials or remote input.
    // An invalid native descriptor gives a deterministic failed XCB object.
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
}

void
destructorRetirement()
{
    const char *display = std::getenv("DISPLAY");
    assert(display != nullptr);
    assert(display[0] != '\0');

    int screenNumber = -1;
    XcbConnection owner = connectDisplay(display, screenNumber);
    xcb_screen_t *screen = screenFor(*owner, screenNumber);
    assert(screen->root != XCB_WINDOW_NONE);
    assert(screen->root_visual != XCB_NONE);
    assert(screen->root_depth == 24U);
    const PixelSize bounds{
        screen->width_in_pixels,
        screen->height_in_pixels,
    };
    assert(bounds.widthPixels == 1280U);
    assert(bounds.heightPixels == 720U);

    constexpr std::uint64_t kMaximumCapturePixels = 4096U;

    // Ordinary scope exit must detach the real server-side XShm segment and
    // release the local SysV mapping while the borrowed XCB owner is live.
    {
        X11SharedMemoryCapture capture(
            *owner, screen->root, screen->root_visual, screen->root_depth,
            bounds, kMaximumCapturePixels);
        assert(capture.valid());
        requireSmallCapture(capture);
    }

    roundTrip(*owner);

    // A replacement child must be able to attach and capture immediately on
    // the exact same XCB owner after destructor-driven retirement.
    {
        X11SharedMemoryCapture replacement(
            *owner, screen->root, screen->root_visual, screen->root_depth,
            bounds, kMaximumCapturePixels);
        assert(replacement.valid());
        requireSmallCapture(replacement);

        // Exercise the successful explicit path as well: it must retire the
        // active native resources, be idempotent, and leave the parent alive.
        replacement.disconnect();
        assert(!replacement.valid());
        assert(std::string_view(replacement.failureReason()) ==
               "XShm capture is disconnected");
        assert(!replacement.capture({0, 0, 4, 4}).valid());
        replacement.disconnect();
    }

    roundTrip(*owner);

    // Prove explicit retirement also leaves the borrowed owner reusable for a
    // fresh child generation; its destructor must then retire cleanly again.
    {
        X11SharedMemoryCapture afterExplicitDisconnect(
            *owner, screen->root, screen->root_visual, screen->root_depth,
            bounds, kMaximumCapturePixels);
        assert(afterExplicitDisconnect.valid());
        requireSmallCapture(afterExplicitDisconnect);
    }

    roundTrip(*owner);
}

} // namespace

int
main(int argc, char **argv)
{
    if (argc == 1)
    {
        connectionDenialsAndCancellation();
        return 0;
    }

    assert(argc == 2);
    const std::string_view behavior{argv[1]};
    if (behavior == "destructor-retirement")
    {
        destructorRetirement();
        return 0;
    }

    assert(false && "unknown XShm capture behavior");
    return 1;
}
