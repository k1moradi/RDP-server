// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11/x11_desktop_resources.h"

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string_view>
#include <thread>

#include <xcb/xcb.h>

namespace
{

struct XcbConnectionDeleter
{
    void operator()(xcb_connection_t *connection) const noexcept
    {
        if (connection != nullptr)
        {
            xcb_disconnect(connection);
        }
    }
};

using XcbConnection = std::unique_ptr<xcb_connection_t, XcbConnectionDeleter>;

constexpr std::uint64_t kCaptureArenaPixels = 256U * 1024U;

const char *
syntheticDisplay()
{
    const char *display = std::getenv("DISPLAY");
    assert(display != nullptr && display[0] != '\0');
    return display;
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
    assert(iterator.rem > 0 && iterator.data != nullptr);
    return iterator.data;
}

void
connectionDenial()
{
    X11DesktopResources resources("not-a-valid-x11-display", 4096);
    assert(!resources.valid());
    assert(resources.failureReason() != nullptr);
    assert(resources.fileDescriptor() == -1);
    assert((resources.sourceGeometry() == PixelSize{}));
    assert(!resources.randrAvailable());
    assert(!resources.damagePending());
    assert(resources.damageNotificationCount() == 0);

    bool workMayRemain = true;
    assert(resources.processEvents(8, &workMayRemain, true) ==
           ConnectionStatus::Failed);
    assert(!workMayRemain);

    resources.disconnect();
    assert(!resources.valid());
    resources.disconnect();
    assert(!resources.valid());
}

void
syntheticXvfbLifecycle()
{
    const char *display = syntheticDisplay();

    // A failed child construction must cancel the already-open display before
    // another resource owner is created on the same synthetic X server.
    {
        X11DesktopResources rejected(display, 0);
        assert(!rejected.valid());
        assert(rejected.failureReason() != nullptr);
        assert(rejected.fileDescriptor() == -1);
    }

    {
        X11DesktopResources resources(display, kCaptureArenaPixels);
        assert(resources.valid());
        assert(resources.failureReason() == nullptr);
        assert(resources.fileDescriptor() >= 0);
        const PixelSize geometry = resources.sourceGeometry();
        assert(geometry.widthPixels == 1280);
        assert(geometry.heightPixels == 720);

        bool workMayRemain = true;
        assert(resources.processEvents(8, &workMayRemain, false) ==
               ConnectionStatus::Ok);
        assert(!workMayRemain);

        resources.disconnect();
        assert(!resources.valid());
        assert(resources.fileDescriptor() == -1);
        assert((resources.sourceGeometry() == PixelSize{}));
        resources.disconnect();
    }

    // Exercise destructor-driven ordered cancellation after a second complete
    // resource construction. No real desktop or user input is involved.
    X11DesktopResources resources(display, kCaptureArenaPixels);
    assert(resources.valid());
}

void
syntheticXvfbEventRouting()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    assert(resources.valid());

    int helperScreenNumber = -1;
    XcbConnection helper(xcb_connect(display, &helperScreenNumber));
    assert(helper != nullptr);
    assert(helperScreenNumber >= 0);
    assert(xcb_connection_has_error(helper.get()) == 0);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    const std::uint64_t notificationCountBefore =
        resources.damageNotificationCount();

    const xcb_void_cookie_t clearCookie = xcb_clear_area_checked(
        helper.get(), 0, helperScreen->root, 0, 0, 32, 32);
    xcb_generic_error_t *clearError =
        xcb_request_check(helper.get(), clearCookie);
    assert(clearError == nullptr);
    std::free(clearError);
    assert(xcb_flush(helper.get()) > 0);

    bool routedDamage = false;
    for (std::size_t attempt = 0; attempt < 250; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(8, &workMayRemain, true) ==
               ConnectionStatus::Ok);
        if (resources.damageNotificationCount() > notificationCountBefore)
        {
            routedDamage = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    assert(routedDamage);
    assert(resources.damagePending());
    assert(resources.valid());
    resources.disconnect();
}

} // namespace

int
main(int argc, char **argv)
{
    if (argc == 1)
    {
        connectionDenial();
        return 0;
    }
    assert(argc == 2);
    const std::string_view behavior(argv[1]);
    if (behavior == "lifecycle")
    {
        syntheticXvfbLifecycle();
        return 0;
    }
    if (behavior == "event-routing")
    {
        syntheticXvfbEventRouting();
        return 0;
    }

    assert(false && "unknown X11 desktop resource behavior");
    return 1;
}
