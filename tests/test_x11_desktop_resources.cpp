// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11/x11_desktop_resources.h"

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string_view>
#include <thread>

#include <xcb/randr.h>
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

XcbConnection
connectHelper(const char *display, int &screenNumber)
{
    XcbConnection connection(xcb_connect(display, &screenNumber));
    assert(connection != nullptr);
    assert(screenNumber >= 0);
    assert(xcb_connection_has_error(connection.get()) == 0);
    return connection;
}

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
disableRandrCrtcsAndResize(xcb_connection_t &connection,
                           xcb_window_t root,
                           PixelSize geometry) noexcept
{
    xcb_generic_error_t *resourcesError = nullptr;
    const auto resourcesCookie =
        xcb_randr_get_screen_resources_current(&connection, root);
    xcb_randr_get_screen_resources_current_reply_t *resources =
        xcb_randr_get_screen_resources_current_reply(
            &connection, resourcesCookie, &resourcesError);
    assert(resourcesError == nullptr);
    std::free(resourcesError);
    assert(resources != nullptr);

    const int crtcCount =
        xcb_randr_get_screen_resources_current_crtcs_length(resources);
    xcb_randr_crtc_t *crtcs =
        xcb_randr_get_screen_resources_current_crtcs(resources);
    assert(crtcCount >= 0);
    for (int index = 0; index < crtcCount; ++index)
    {
        xcb_generic_error_t *configError = nullptr;
        const auto configCookie = xcb_randr_set_crtc_config(
            &connection, crtcs[index], resources->timestamp,
            resources->config_timestamp, 0, 0, XCB_NONE,
            XCB_RANDR_ROTATION_ROTATE_0, 0, nullptr);
        xcb_randr_set_crtc_config_reply_t *config =
            xcb_randr_set_crtc_config_reply(
                &connection, configCookie, &configError);
        assert(configError == nullptr);
        std::free(configError);
        assert(config != nullptr);
        assert(config->status == XCB_RANDR_SET_CONFIG_SUCCESS);
        std::free(config);
    }
    std::free(resources);

    const xcb_void_cookie_t resizeCookie =
        xcb_randr_set_screen_size_checked(
            &connection, root,
            static_cast<std::uint16_t>(geometry.widthPixels),
            static_cast<std::uint16_t>(geometry.heightPixels),
            geometry.widthPixels / 4, geometry.heightPixels / 4);
    xcb_generic_error_t *resizeError =
        xcb_request_check(&connection, resizeCookie);
    assert(resizeError == nullptr);
    std::free(resizeError);
    assert(xcb_flush(&connection) > 0);
}

void
clearSyntheticRoot(xcb_connection_t &connection, xcb_window_t root) noexcept
{
    const xcb_void_cookie_t clearCookie = xcb_clear_area_checked(
        &connection, 0, root, 0, 0, 32, 32);
    xcb_generic_error_t *clearError =
        xcb_request_check(&connection, clearCookie);
    assert(clearError == nullptr);
    std::free(clearError);
    assert(xcb_flush(&connection) > 0);
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
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    const std::uint64_t notificationCountBefore =
        resources.damageNotificationCount();

    clearSyntheticRoot(*helper, helperScreen->root);

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

void
syntheticXvfbRandrRebuild()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    assert(resources.valid());
    assert(resources.randrAvailable());
    const int originalDescriptor = resources.fileDescriptor();
    assert(originalDescriptor >= 0);
    assert((resources.sourceGeometry() == PixelSize{1280, 720}));

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    constexpr PixelSize resizedGeometry{1024, 600};
    disableRandrCrtcsAndResize(
        *helper, helperScreen->root, resizedGeometry);

    bool rebuilt = false;
    for (std::size_t attempt = 0; attempt < 250; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(8, &workMayRemain, true) ==
               ConnectionStatus::Ok);
        if (resources.sourceGeometry() == resizedGeometry)
        {
            rebuilt = true;
            assert(workMayRemain);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    assert(rebuilt);
    assert(resources.valid());
    assert(resources.fileDescriptor() == originalDescriptor);

    const std::uint64_t notificationsAfterResize =
        resources.damageNotificationCount();
    clearSyntheticRoot(*helper, helperScreen->root);

    bool routedPostResizeDamage = false;
    for (std::size_t attempt = 0; attempt < 250; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(8, &workMayRemain, true) ==
               ConnectionStatus::Ok);
        if (resources.damageNotificationCount() > notificationsAfterResize)
        {
            routedPostResizeDamage = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    assert(routedPostResizeDamage);
    assert(resources.damagePending());
    assert(resources.valid());
    assert(resources.fileDescriptor() == originalDescriptor);
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
    if (behavior == "randr-rebuild")
    {
        syntheticXvfbRandrRebuild();
        return 0;
    }

    assert(false && "unknown X11 desktop resource behavior");
    return 1;
}
