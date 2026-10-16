// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11/x11_desktop_resources.h"

#include <cassert>
#include <chrono>
#include <cstdio>
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

void
requireValidResources(const X11DesktopResources &resources,
                      const char *constructionPhase) noexcept
{
    const bool isValid = resources.valid();
    if (!isValid)
    {
        const char *reason = resources.failureReason();
        std::fprintf(
            stderr,
            "X11 desktop resource construction failed during %s: %s\n",
            constructionPhase,
            reason != nullptr ? reason : "no failure reason");
    }
    assert(isValid);
}

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
warpSyntheticPointer(xcb_connection_t &connection, xcb_window_t root,
                     X11PointerPosition position) noexcept
{
    const xcb_void_cookie_t warpCookie = xcb_warp_pointer_checked(
        &connection, XCB_NONE, root, 0, 0, 0, 0,
        static_cast<std::int16_t>(position.x),
        static_cast<std::int16_t>(position.y));
    xcb_generic_error_t *warpError =
        xcb_request_check(&connection, warpCookie);
    assert(warpError == nullptr);
    std::free(warpError);
    assert(xcb_flush(&connection) > 0);
}

class PointerRoutingObservationSink final : public X11EventSink
{
public:
    PointerRoutingObservationSink(X11DesktopResources &resources,
                                  X11PointerPosition expected) noexcept
        : resources_(resources), expected_(expected)
    {
    }

    void handle(const xcb_generic_event_t &) noexcept override
    {
        X11PointerPosition observed{};
        if (resources_.pendingPointerPosition(observed) &&
            observed == expected_)
        {
            observedAfterPointerRoute_ = true;
        }
    }

    [[nodiscard]] bool observedAfterPointerRoute() const noexcept
    {
        return observedAfterPointerRoute_;
    }

private:
    X11DesktopResources &resources_;
    X11PointerPosition expected_{};
    bool observedAfterPointerRoute_{false};
};

bool
waitForPointerPosition(X11DesktopResources &resources,
                       X11PointerPosition expected,
                       X11EventSink *additionalEventSink = nullptr) noexcept
{
    for (std::size_t attempt = 0; attempt < 250; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(
                   16, &workMayRemain, true, additionalEventSink) ==
               ConnectionStatus::Ok);
        X11PointerPosition observed{};
        if (resources.pendingPointerPosition(observed) &&
            observed == expected)
        {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
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
    assert(!resources.pointerPositionAvailable());
    assert(resources.pointerPositionFailureReason() != nullptr);
    X11PointerPosition position{};
    assert(!resources.pendingPointerPosition(position));
    assert(!resources.shouldForwardPointerPosition(position));
    resources.acknowledgePointerPosition(position, true);

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
        assert(std::string_view(rejected.failureReason()) ==
               "XShm capture arena size is invalid");
        assert(rejected.fileDescriptor() == -1);
    }

    {
        X11DesktopResources resources(display, kCaptureArenaPixels);
        requireValidResources(resources, "failed-owner recovery");
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
    requireValidResources(resources, "post-disconnect recovery");
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
syntheticXvfbR4ReadBoundary()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    assert(resources.valid());

    // R4 may synchronously borrow one bounded BGRX capture from the existing
    // XShm arena; no frame scheduler or persistent framebuffer owner is added.
    const FramebufferView frame = resources.capture({0, 0, 32, 16});
    assert(frame.valid());
    assert(frame.widthPixels == 32);
    assert(frame.heightPixels == 16);
    assert(frame.strideBytes == 32U * 4U);
    assert(frame.pixels.size() == frame.strideBytes * frame.heightPixels);
    assert(resources.valid());

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);
    clearSyntheticRoot(*helper, helperScreen->root);

    bool routedDamage = false;
    for (std::size_t attempt = 0; attempt < 250; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(8, &workMayRemain, true) ==
               ConnectionStatus::Ok);
        if (resources.damagePending())
        {
            routedDamage = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    assert(routedDamage);

    DamageRegion damage;
    assert(resources.snapshotDamage(damage));
    assert(!damage.rectangles().empty());
    assert(damage.intersects({0, 0, 32, 32}));
    assert(!resources.damagePending());
    DamageRegion emptyDamage;
    assert(resources.snapshotDamage(emptyDamage));
    assert(emptyDamage.rectangles().empty());

    // XFixes starts pending so R4 can fetch the initial cursor exactly once.
    assert(resources.cursorPending());
    assert(resources.refreshCursor());
    assert(resources.cursorRefreshFailureReason() == nullptr);
    assert(resources.cursorRefreshErrorCode() == 0);
    assert(!resources.takeCursorRefreshFailureWarning());
    assert(!resources.takeUnsupportedCursorWarning());

    const X11CursorImageView cursor = resources.cursorImage();
    assert(cursor.valid());
    assert(cursor.widthPixels == 32);
    assert(cursor.heightPixels == 32);
    assert(cursor.pixels.size() >= 32U * 32U * 4U);
    assert(cursor.mask.size() >= 32U * 32U / 8U);
    resources.acknowledgeCursor();
    assert(!resources.cursorPending());

    // Borrowed views must be consumed before owner teardown.
    resources.disconnect();
    assert(!resources.valid());
    assert(!resources.snapshotDamage(damage));
    assert(!resources.capture({0, 0, 1, 1}).valid());
    assert(!resources.refreshCursor());
    assert(!resources.cursorImage().valid());
}

void
syntheticXvfbPointerCapabilityDenials()
{
    X11DesktopResources rejected("not-a-valid-x11-display", 4096);
    assert(!rejected.pointerPositionAvailable());
    assert(rejected.pointerPositionFailureReason() != nullptr);
    X11PointerPosition rejectedPosition{10, 20};
    assert(!rejected.pendingPointerPosition(rejectedPosition));
    assert(!rejected.shouldForwardPointerPosition(rejectedPosition));
    rejected.acknowledgePointerPosition(rejectedPosition, true);

    X11DesktopResources resources(syntheticDisplay(), kCaptureArenaPixels);
    requireValidResources(resources, "pointer capability");
#if defined(RDP_TEST_XINPUT_POINTER)
    assert(resources.pointerPositionAvailable());
    assert(resources.pointerPositionFailureReason() == nullptr);

    X11PointerPosition first{};
    if (resources.pendingPointerPosition(first))
    {
        X11PointerPosition repeated{};
        assert(resources.pendingPointerPosition(repeated));
        assert(repeated == first);
        resources.acknowledgePointerPosition(first, false);
        assert(!resources.pendingPointerPosition(repeated));
    }
#else
    assert(!resources.pointerPositionAvailable());
    assert(resources.pointerPositionFailureReason() != nullptr);
#endif

    resources.disconnect();
    assert(!resources.pointerPositionAvailable());
    assert(resources.pointerPositionFailureReason() != nullptr);
    X11PointerPosition stale{5, 5};
    assert(!resources.pendingPointerPosition(stale));
    assert(!resources.shouldForwardPointerPosition(stale));
    resources.acknowledgePointerPosition(stale, true);
}

#if defined(RDP_TEST_XINPUT_POINTER)
void
syntheticXvfbPointerEventRouting()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "pointer event routing");
    assert(resources.pointerPositionAvailable());

    X11PointerPosition initial{};
    if (resources.pendingPointerPosition(initial))
    {
        resources.acknowledgePointerPosition(initial, false);
    }

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);

    constexpr X11PointerPosition target{321, 222};
    PointerRoutingObservationSink observation(resources, target);
    warpSyntheticPointer(*helper, helperScreen->root, target);

    assert(waitForPointerPosition(resources, target, &observation));
    assert(observation.observedAfterPointerRoute());
    assert(resources.shouldForwardPointerPosition(target));

    X11PointerPosition repeated{};
    assert(resources.pendingPointerPosition(repeated));
    assert(repeated == target);
    resources.acknowledgePointerPosition(target, false);
    assert(!resources.pendingPointerPosition(repeated));
    resources.disconnect();
}

void
syntheticXvfbPointerRandrRebuild()
{
    const char *display = syntheticDisplay();
    X11DesktopResources resources(display, kCaptureArenaPixels);
    requireValidResources(resources, "pointer RandR rebuild");
    assert(resources.pointerPositionAvailable());
    assert(resources.randrAvailable());
    const int originalDescriptor = resources.fileDescriptor();

    X11PointerPosition initial{};
    if (resources.pendingPointerPosition(initial))
    {
        resources.acknowledgePointerPosition(initial, false);
    }

    int helperScreenNumber = -1;
    XcbConnection helper = connectHelper(display, helperScreenNumber);
    xcb_screen_t *helperScreen = screenFor(*helper, helperScreenNumber);

    constexpr X11PointerPosition forwardedLocal{400, 300};
    warpSyntheticPointer(*helper, helperScreen->root, forwardedLocal);
    assert(waitForPointerPosition(resources, forwardedLocal));
    assert(resources.shouldForwardPointerPosition(forwardedLocal));
    resources.acknowledgePointerPosition(forwardedLocal, true);

    constexpr X11PointerPosition staleGeneration{1200, 700};
    warpSyntheticPointer(*helper, helperScreen->root, staleGeneration);
    assert(waitForPointerPosition(resources, staleGeneration));

    constexpr PixelSize resizedGeometry{1024, 600};
    disableRandrCrtcsAndResize(
        *helper, helperScreen->root, resizedGeometry);

    bool rebuilt = false;
    for (std::size_t attempt = 0; attempt < 250; ++attempt)
    {
        bool workMayRemain = false;
        assert(resources.processEvents(16, &workMayRemain, true) ==
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
    assert(resources.pointerPositionAvailable());
    assert(resources.fileDescriptor() == originalDescriptor);

    X11PointerPosition current{};
    if (resources.pendingPointerPosition(current))
    {
        assert(current != staleGeneration);
        assert(current.x >= 0);
        assert(current.y >= 0);
        assert(static_cast<std::uint32_t>(current.x) <
               resizedGeometry.widthPixels);
        assert(static_cast<std::uint32_t>(current.y) <
               resizedGeometry.heightPixels);
        assert(resources.shouldForwardPointerPosition(current));
        resources.acknowledgePointerPosition(current, false);
    }
    resources.disconnect();
}
#endif

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
    if (behavior == "pointer-capability-denials")
    {
        syntheticXvfbPointerCapabilityDenials();
        return 0;
    }
#if defined(RDP_TEST_XINPUT_POINTER)
    if (behavior == "pointer-event-routing")
    {
        syntheticXvfbPointerEventRouting();
        return 0;
    }
    if (behavior == "pointer-randr-rebuild")
    {
        syntheticXvfbPointerRandrRebuild();
        return 0;
    }
#endif
    if (behavior == "r4-read-boundary")
    {
        syntheticXvfbR4ReadBoundary();
        return 0;
    }

    assert(false && "unknown X11 desktop resource behavior");
    return 1;
}
