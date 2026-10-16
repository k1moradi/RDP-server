// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11/x11_pointer_position_tracker.h"

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <memory>
#include <string_view>

#include <xcb/xcb.h>
#include <xcb/xinput.h>

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

constexpr std::int64_t kFixedPointOne = 1LL << 16;
static_assert(sizeof(xcb_input_motion_event_t) >=
              sizeof(xcb_ge_generic_event_t));
static_assert((sizeof(xcb_input_motion_event_t) -
               sizeof(xcb_ge_generic_event_t)) %
                  sizeof(std::uint32_t) ==
              0);
constexpr std::uint32_t kMinimumMotionExtraWords =
    static_cast<std::uint32_t>(
        (sizeof(xcb_input_motion_event_t) -
         sizeof(xcb_ge_generic_event_t)) /
        sizeof(std::uint32_t));

const char *
syntheticDisplay()
{
    const char *display = std::getenv("DISPLAY");
    assert(display != nullptr && display[0] != '\0');
    return display;
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

xcb_input_motion_event_t
motionEvent(xcb_connection_t &connection, xcb_window_t root,
            std::int64_t rootXFixed, std::int64_t rootYFixed) noexcept
{
    const xcb_query_extension_reply_t *extension =
        xcb_get_extension_data(&connection, &xcb_input_id);
    assert(extension != nullptr && extension->present);

    xcb_input_motion_event_t motion{};
    motion.response_type = XCB_GE_GENERIC;
    motion.extension = extension->major_opcode;
    motion.length = kMinimumMotionExtraWords;
    motion.event_type = XCB_INPUT_MOTION;
    motion.root = root;
    motion.root_x = static_cast<decltype(motion.root_x)>(rootXFixed);
    motion.root_y = static_cast<decltype(motion.root_y)>(rootYFixed);
    return motion;
}

void
routeMotion(X11PointerPositionTracker &tracker,
            const xcb_input_motion_event_t &motion) noexcept
{
    tracker.handle(
        reinterpret_cast<const xcb_generic_event_t &>(motion));
}

void
clearInitialPosition(X11PointerPositionTracker &tracker) noexcept
{
    X11PointerPosition initial{};
    if (tracker.pendingPosition(initial))
    {
        tracker.acknowledge(initial, false);
    }
    assert(!tracker.pendingPosition(initial));
}

struct LiveTrackerFixture
{
    int screenNumber{-1};
    XcbConnection connection{};
    xcb_screen_t *screen{};
    PixelSize geometry{};

    LiveTrackerFixture()
        : connection(connectHelper(syntheticDisplay(), screenNumber)),
          screen(screenFor(*connection, screenNumber)),
          geometry{screen->width_in_pixels, screen->height_in_pixels}
    {
        assert(geometry.widthPixels != 0 && geometry.heightPixels != 0);
    }
};

void
disconnectCancellation()
{
    int failedScreen = -1;
    XcbConnection failedConnection(
        xcb_connect("not-a-valid-x11-display", &failedScreen));
    assert(failedConnection != nullptr);
    assert(xcb_connection_has_error(failedConnection.get()) != 0);

    X11PointerPositionTracker failed(
        *failedConnection, static_cast<xcb_window_t>(1), {640, 480});
    assert(!failed.valid());
    assert(failed.failureReason() != nullptr);
    X11PointerPosition position{};
    assert(!failed.pendingPosition(position));
    assert(!failed.shouldForward(position));
    assert(!failed.shouldAcceptRemoteMotion(position));
    failed.noteRemotePointerPosition(position);
    failed.acknowledge(position, true);
    failed.disconnect();
    failed.disconnect();
    assert(!failed.valid());
    assert(!failed.pendingPosition(position));

    const char *display = std::getenv("DISPLAY");
    if (display == nullptr || display[0] == '\0')
    {
        return;
    }

    LiveTrackerFixture fixture;
    X11PointerPositionTracker tracker(
        *fixture.connection, fixture.screen->root, fixture.geometry);
    assert(tracker.valid());
    tracker.disconnect();
    tracker.disconnect();
    assert(!tracker.valid());
    assert(!tracker.pendingPosition(position));
    assert(!tracker.shouldForward(position));
    assert(!tracker.shouldAcceptRemoteMotion(position));
    assert(xcb_connection_has_error(fixture.connection.get()) == 0);

    X11PointerPositionTracker replacement(
        *fixture.connection, fixture.screen->root, fixture.geometry);
    assert(replacement.valid());
    replacement.disconnect();
    assert(xcb_connection_has_error(fixture.connection.get()) == 0);
}

void
motionCoalescing()
{
    LiveTrackerFixture fixture;
    X11PointerPositionTracker tracker(
        *fixture.connection, fixture.screen->root, fixture.geometry);
    assert(tracker.valid());
    clearInitialPosition(tracker);

    auto ignored = motionEvent(
        *fixture.connection, fixture.screen->root,
        10 * kFixedPointOne, 20 * kFixedPointOne);
    ignored.response_type = XCB_MOTION_NOTIFY;
    routeMotion(tracker, ignored);
    X11PointerPosition position{};
    assert(!tracker.pendingPosition(position));

    const xcb_query_extension_reply_t *extension =
        xcb_get_extension_data(fixture.connection.get(), &xcb_input_id);
    assert(extension != nullptr && extension->present);
    ignored.response_type = XCB_GE_GENERIC;
    ignored.extension = static_cast<std::uint8_t>(
        extension->major_opcode == 0xffU
            ? 0xfeU
            : static_cast<unsigned int>(extension->major_opcode) + 1U);
    routeMotion(tracker, ignored);
    assert(!tracker.pendingPosition(position));

    ignored.extension = extension->major_opcode;
    ignored.event_type = XCB_INPUT_BUTTON_PRESS;
    routeMotion(tracker, ignored);
    assert(!tracker.pendingPosition(position));

    const auto fractional = motionEvent(
        *fixture.connection, fixture.screen->root,
        31 * kFixedPointOne + kFixedPointOne / 2,
        -kFixedPointOne / 2);
    routeMotion(tracker, fractional);
    assert(tracker.pendingPosition(position));
    assert((position == X11PointerPosition{31, 0}));

    const auto clipped = motionEvent(
        *fixture.connection, fixture.screen->root,
        5000 * kFixedPointOne, 5000 * kFixedPointOne);
    routeMotion(tracker, clipped);
    assert(tracker.pendingPosition(position));
    assert(position.x ==
           static_cast<std::int32_t>(fixture.geometry.widthPixels - 1U));
    assert(position.y ==
           static_cast<std::int32_t>(fixture.geometry.heightPixels - 1U));

    const auto latest = motionEvent(
        *fixture.connection, fixture.screen->root,
        87 * kFixedPointOne, 66 * kFixedPointOne);
    routeMotion(tracker, latest);
    assert(tracker.pendingPosition(position));
    assert((position == X11PointerPosition{87, 66}));
    tracker.disconnect();
}

void
remoteEchoSuppression()
{
    LiveTrackerFixture fixture;
    X11PointerPositionTracker tracker(
        *fixture.connection, fixture.screen->root, fixture.geometry);
    assert(tracker.valid());
    clearInitialPosition(tracker);

    constexpr X11PointerPosition localA{100, 120};
    routeMotion(
        tracker,
        motionEvent(*fixture.connection, fixture.screen->root,
                    static_cast<std::int64_t>(localA.x) * kFixedPointOne,
                    static_cast<std::int64_t>(localA.y) * kFixedPointOne));
    X11PointerPosition pending{};
    assert(tracker.pendingPosition(pending) && pending == localA);
    assert(tracker.shouldForward(localA));
    tracker.acknowledge(localA, true);
    assert(!tracker.pendingPosition(pending));

    assert(!tracker.shouldAcceptRemoteMotion(localA));
    routeMotion(
        tracker,
        motionEvent(*fixture.connection, fixture.screen->root,
                    static_cast<std::int64_t>(localA.x) * kFixedPointOne,
                    static_cast<std::int64_t>(localA.y) * kFixedPointOne));
    assert(tracker.pendingPosition(pending) && pending == localA);
    assert(!tracker.shouldForward(localA));
    tracker.acknowledge(localA, false);

    constexpr X11PointerPosition remoteB{220, 240};
    assert(tracker.shouldAcceptRemoteMotion(remoteB));
    tracker.noteRemotePointerPosition(remoteB);
    routeMotion(
        tracker,
        motionEvent(*fixture.connection, fixture.screen->root,
                    static_cast<std::int64_t>(remoteB.x) * kFixedPointOne,
                    static_cast<std::int64_t>(remoteB.y) * kFixedPointOne));
    assert(tracker.pendingPosition(pending) && pending == remoteB);
    assert(!tracker.shouldForward(remoteB));
    tracker.acknowledge(remoteB, false);

    constexpr X11PointerPosition localC{330, 350};
    constexpr X11PointerPosition localD{440, 460};
    routeMotion(
        tracker,
        motionEvent(*fixture.connection, fixture.screen->root,
                    static_cast<std::int64_t>(localC.x) * kFixedPointOne,
                    static_cast<std::int64_t>(localC.y) * kFixedPointOne));
    routeMotion(
        tracker,
        motionEvent(*fixture.connection, fixture.screen->root,
                    static_cast<std::int64_t>(localD.x) * kFixedPointOne,
                    static_cast<std::int64_t>(localD.y) * kFixedPointOne));
    assert(tracker.pendingPosition(pending) && pending == localD);
    assert(tracker.shouldForward(localD));

    tracker.acknowledge(localD, false);
    routeMotion(
        tracker,
        motionEvent(*fixture.connection, fixture.screen->root,
                    static_cast<std::int64_t>(localD.x) * kFixedPointOne,
                    static_cast<std::int64_t>(localD.y) * kFixedPointOne));
    assert(tracker.shouldForward(localD));

    tracker.acknowledge(localD, true);
    routeMotion(
        tracker,
        motionEvent(*fixture.connection, fixture.screen->root,
                    static_cast<std::int64_t>(localD.x) * kFixedPointOne,
                    static_cast<std::int64_t>(localD.y) * kFixedPointOne));
    assert(!tracker.shouldForward(localD));

    constexpr X11PointerPosition remoteE{550, 500};
    assert(tracker.shouldAcceptRemoteMotion(remoteE));
    tracker.disconnect();

    // Remote requests are clamped before XTEST reaches the root. Echo
    // authority must use that actual injected coordinate, including the
    // int16 wire limit, rather than retaining the untrusted request value.
    constexpr PixelSize wideGeometry{65535, 65535};
    X11PointerPositionTracker wideTracker(
        *fixture.connection, fixture.screen->root, wideGeometry);
    assert(wideTracker.valid());
    clearInitialPosition(wideTracker);

    constexpr std::int32_t maximumInjectedCoordinate =
        std::numeric_limits<std::int16_t>::max();
    constexpr X11PointerPosition injectedMaximum{
        maximumInjectedCoordinate, maximumInjectedCoordinate};
    routeMotion(
        wideTracker,
        motionEvent(*fixture.connection, fixture.screen->root,
                    static_cast<std::int64_t>(injectedMaximum.x) *
                        kFixedPointOne,
                    static_cast<std::int64_t>(injectedMaximum.y) *
                        kFixedPointOne));
    assert(wideTracker.pendingPosition(pending));
    assert(pending == injectedMaximum);
    wideTracker.acknowledge(injectedMaximum, true);

    constexpr X11PointerPosition untrustedMaximum{
        std::numeric_limits<std::int32_t>::max(),
        std::numeric_limits<std::int32_t>::max()};
    assert(!wideTracker.shouldAcceptRemoteMotion(untrustedMaximum));

    // Once remote authority is active, the native echo at the clamped
    // coordinate must be suppressed as the same remote movement.
    constexpr X11PointerPosition distinctRemote{10, 10};
    assert(wideTracker.shouldAcceptRemoteMotion(distinctRemote));
    wideTracker.noteRemotePointerPosition(untrustedMaximum);
    routeMotion(
        wideTracker,
        motionEvent(*fixture.connection, fixture.screen->root,
                    static_cast<std::int64_t>(injectedMaximum.x) *
                        kFixedPointOne,
                    static_cast<std::int64_t>(injectedMaximum.y) *
                        kFixedPointOne));
    assert(wideTracker.pendingPosition(pending));
    assert(pending == injectedMaximum);
    assert(!wideTracker.shouldForward(injectedMaximum));
    wideTracker.disconnect();
}

void
malformedEventBounds()
{
    LiveTrackerFixture fixture;
    X11PointerPositionTracker tracker(
        *fixture.connection, fixture.screen->root, fixture.geometry);
    assert(tracker.valid());
    clearInitialPosition(tracker);

    const xcb_query_extension_reply_t *extension =
        xcb_get_extension_data(fixture.connection.get(), &xcb_input_id);
    assert(extension != nullptr && extension->present);

    xcb_ge_generic_event_t truncated{};
    truncated.response_type = XCB_GE_GENERIC;
    truncated.extension = extension->major_opcode;
    truncated.event_type = XCB_INPUT_MOTION;
    truncated.length = 0;
    const auto &truncatedGeneric =
        reinterpret_cast<const xcb_generic_event_t &>(truncated);
    assert(!tracker.handles(truncatedGeneric));
    tracker.handle(truncatedGeneric);
    X11PointerPosition pending{};
    assert(!tracker.pendingPosition(pending));

    const auto wrongRoot = motionEvent(
        *fixture.connection, static_cast<xcb_window_t>(
                                 fixture.screen->root + 1U),
        10 * kFixedPointOne, 20 * kFixedPointOne);
    assert(!tracker.handles(
        reinterpret_cast<const xcb_generic_event_t &>(wrongRoot)));

    const auto complete = motionEvent(
        *fixture.connection, fixture.screen->root,
        10 * kFixedPointOne, 20 * kFixedPointOne);
    assert(tracker.handles(
        reinterpret_cast<const xcb_generic_event_t &>(complete)));
    routeMotion(tracker, complete);
    assert(tracker.pendingPosition(pending));
    assert((pending == X11PointerPosition{10, 20}));
    tracker.disconnect();
}

} // namespace

int
main(int argc, char **argv)
{
    assert(argc == 2);
    const std::string_view behavior(argv[1]);
    if (behavior == "disconnect-cancellation")
    {
        disconnectCancellation();
        return 0;
    }
    if (behavior == "motion-coalescing")
    {
        motionCoalescing();
        return 0;
    }
    if (behavior == "remote-echo-suppression")
    {
        remoteEchoSuppression();
        return 0;
    }
    if (behavior == "malformed-event-bounds")
    {
        malformedEventBounds();
        return 0;
    }

    assert(false && "unknown XI2 pointer tracker behavior");
    return 1;
}
