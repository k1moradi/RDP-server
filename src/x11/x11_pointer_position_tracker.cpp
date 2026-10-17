// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_pointer_position_tracker.h"

#include <algorithm>
#include <cstdlib>
#include <limits>

#include <xcb/xinput.h>

namespace
{

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

bool
checkRequest(xcb_connection_t *connection, xcb_void_cookie_t cookie) noexcept
{
    xcb_generic_error_t *error = xcb_request_check(connection, cookie);
    if (error == nullptr)
    {
        return true;
    }
    std::free(error);
    return false;
}

[[nodiscard]] constexpr bool
sequenceAtOrAfter(std::uint32_t sequence, std::uint32_t floor) noexcept
{
    // XCB reconstructs a 32-bit sequence from the wire's 16-bit serial.
    // The event queue is bounded far below half the serial space, so modular
    // subtraction distinguishes recent post-floor events from stale ones.
    constexpr std::uint32_t kHalfSequenceRange =
        std::uint32_t{1} << 31U;
    return static_cast<std::uint32_t>(sequence - floor) <
           kHalfSequenceRange;
}

} // namespace

X11PointerPositionTracker::X11PointerPositionTracker(
    xcb_connection_t &connection, xcb_window_t rootWindow,
    PixelSize sourceGeometry) noexcept
    : connection_(&connection), rootWindow_(rootWindow),
      sourceGeometry_(sourceGeometry)
{
    if (xcb_connection_has_error(connection_) != 0 ||
        rootWindow_ == XCB_WINDOW_NONE || sourceGeometry_.widthPixels == 0 ||
        sourceGeometry_.heightPixels == 0)
    {
        failureReason_ = "X11 pointer geometry or connection is invalid";
        return;
    }

    const xcb_query_extension_reply_t *extension =
        xcb_get_extension_data(connection_, &xcb_input_id);
    if (extension == nullptr || !extension->present)
    {
        failureReason_ = "XInput2 extension is unavailable";
        return;
    }
    majorOpcode_ = extension->major_opcode;

    xcb_generic_error_t *versionError = nullptr;
    const xcb_input_xi_query_version_cookie_t versionCookie =
        xcb_input_xi_query_version(connection_, 2, 0);
    xcb_input_xi_query_version_reply_t *version =
        xcb_input_xi_query_version_reply(connection_, versionCookie,
                                         &versionError);
    if (versionError != nullptr || version == nullptr ||
        version->major_version < 2)
    {
        std::free(versionError);
        std::free(version);
        failureReason_ = "XInput2 version 2.0 negotiation failed";
        return;
    }
    std::free(versionError);
    std::free(version);

    struct
    {
        xcb_input_event_mask_t header{};
        std::uint32_t mask{};
    } selectedMask;
    selectedMask.header.deviceid = XCB_INPUT_DEVICE_ALL_MASTER;
    selectedMask.header.mask_len = 1;
    selectedMask.mask = XCB_INPUT_XI_EVENT_MASK_MOTION;
    const xcb_void_cookie_t selectionCookie =
        xcb_input_xi_select_events_checked(
            connection_, rootWindow_, 1, &selectedMask.header);
    if (!checkRequest(connection_, selectionCookie))
    {
        failureReason_ = "XInput2 root motion subscription failed";
        return;
    }
    generationSequenceFloor_ = selectionCookie.sequence;
    subscribed_ = true;

    xcb_generic_error_t *pointerError = nullptr;
    const xcb_query_pointer_cookie_t pointerCookie =
        xcb_query_pointer(connection_, rootWindow_);
    xcb_query_pointer_reply_t *pointer =
        xcb_query_pointer_reply(connection_, pointerCookie, &pointerError);
    if (pointerError == nullptr && pointer != nullptr && pointer->same_screen)
    {
        queuePosition(pointer->root_x, pointer->root_y);
    }
    std::free(pointerError);
    std::free(pointer);

    if (xcb_connection_has_error(connection_) != 0 ||
        xcb_flush(connection_) <= 0)
    {
        failureReason_ = "XInput2 pointer setup failed";
        return;
    }
    failureReason_ = nullptr;
}

X11PointerPositionTracker::~X11PointerPositionTracker() noexcept
{
    disconnect();
}

bool
X11PointerPositionTracker::valid() const noexcept
{
    return failureReason_ == nullptr && connection_ != nullptr &&
           rootWindow_ != XCB_WINDOW_NONE &&
           sourceGeometry_.widthPixels != 0 &&
           sourceGeometry_.heightPixels != 0 && majorOpcode_ != 0 &&
           subscribed_ && xcb_connection_has_error(connection_) == 0;
}

const char *
X11PointerPositionTracker::failureReason() const noexcept
{
    return failureReason_;
}

bool
X11PointerPositionTracker::handles(
    const xcb_generic_event_t &event) const noexcept
{
    const auto responseType =
        static_cast<std::uint8_t>(event.response_type & 0x7fU);
    if (responseType != XCB_GE_GENERIC || !valid())
    {
        return false;
    }
    if (!sequenceAtOrAfter(event.full_sequence, generationSequenceFloor_))
    {
        // RandR can leave an old XI2 motion queued after the replacement
        // tracker subscribes. Do not let extension/root identity cross the
        // geometry-generation boundary.
        return false;
    }

    const auto &generic =
        reinterpret_cast<const xcb_ge_generic_event_t &>(event);
    if (generic.extension != majorOpcode_ ||
        generic.event_type != XCB_INPUT_MOTION ||
        generic.length < kMinimumMotionExtraWords)
    {
        return false;
    }

    // XGE length counts 32-bit words beyond the generic event header. Do not
    // touch the XI2 motion fields until the fixed motion record is present.
    const auto &motion =
        reinterpret_cast<const xcb_input_motion_event_t &>(event);
    return motion.root == rootWindow_;
}

void
X11PointerPositionTracker::handle(const xcb_generic_event_t &event) noexcept
{
    if (!handles(event))
    {
        return;
    }
    const auto &motion =
        reinterpret_cast<const xcb_input_motion_event_t &>(event);
    queuePosition(motion.root_x / kFixedPointOne,
                  motion.root_y / kFixedPointOne);
}

void
X11PointerPositionTracker::noteRemotePointerPosition(
    X11PointerPosition position) noexcept
{
    if (!valid())
    {
        return;
    }
    remotePosition_ = injectedRemotePosition(position);
    hasRemotePosition_ = true;

    // The peer now knows the pointer at this remote position. A later native
    // return to the previously forwarded local coordinate is not a duplicate
    // of what the peer currently sees.
    lastForwardedPosition_ = {};
    hasForwardedPosition_ = false;
}

bool
X11PointerPositionTracker::pendingPosition(
    X11PointerPosition &position) const noexcept
{
    if (!valid() || !hasPendingPosition_)
    {
        return false;
    }
    position = pendingPosition_;
    return true;
}

bool
X11PointerPositionTracker::shouldForward(
    X11PointerPosition position) const noexcept
{
    return valid() &&
           !(hasRemotePosition_ && position == remotePosition_) &&
           !(hasForwardedPosition_ && position == lastForwardedPosition_);
}

bool
X11PointerPositionTracker::shouldAcceptRemoteMotion(
    X11PointerPosition position) noexcept
{
    if (!valid())
    {
        return false;
    }
    if (!localPointerAuthorityActive_)
    {
        return true;
    }

    const X11PointerPosition injectedPosition =
        injectedRemotePosition(position);
    if ((hasRemotePosition_ && injectedPosition == remotePosition_) ||
        injectedPosition == localPointerAuthorityPosition_)
    {
        return false;
    }

    // A distinct coordinate is new remote activity; transfer authority back
    // immediately without a timeout or a delayed pointer jump.
    localPointerAuthorityActive_ = false;
    return true;
}

void
X11PointerPositionTracker::acknowledge(X11PointerPosition position,
                                       bool forwarded) noexcept
{
    if (!valid() || !hasPendingPosition_ || pendingPosition_ != position)
    {
        return;
    }
    hasPendingPosition_ = false;
    if (forwarded)
    {
        // A successfully published local position supersedes any older
        // remote-echo coordinate. If the pointer later returns there, that is
        // a new native observation rather than the stale remote echo.
        remotePosition_ = {};
        hasRemotePosition_ = false;
        lastForwardedPosition_ = position;
        hasForwardedPosition_ = true;
        localPointerAuthorityPosition_ = position;
        localPointerAuthorityActive_ = true;
    }
}

void
X11PointerPositionTracker::disconnect() noexcept
{
    const char *reason = failureReason_ == nullptr
                             ? "XInput2 pointer tracker is disconnected"
                             : failureReason_;

    // XISelectEvents replaces this client's mask for the device/window pair.
    // A zero motion mask retires our subscription while the original borrowed
    // connection is still valid. Cancellation failures are non-recoverable
    // only for this observer and must not dereference the owner afterwards.
    if (subscribed_ && connection_ != nullptr &&
        rootWindow_ != XCB_WINDOW_NONE &&
        xcb_connection_has_error(connection_) == 0)
    {
        struct
        {
            xcb_input_event_mask_t header{};
            std::uint32_t mask{};
        } selectedMask;
        selectedMask.header.deviceid = XCB_INPUT_DEVICE_ALL_MASTER;
        selectedMask.header.mask_len = 0;
        selectedMask.mask = 0;
        (void)checkRequest(
            connection_,
            xcb_input_xi_select_events_checked(
                connection_, rootWindow_, 1, &selectedMask.header));
    }

    connection_ = nullptr;
    rootWindow_ = XCB_WINDOW_NONE;
    sourceGeometry_ = {};
    majorOpcode_ = 0;
    generationSequenceFloor_ = 0;
    pendingPosition_ = {};
    remotePosition_ = {};
    lastForwardedPosition_ = {};
    localPointerAuthorityPosition_ = {};
    hasPendingPosition_ = false;
    hasRemotePosition_ = false;
    hasForwardedPosition_ = false;
    localPointerAuthorityActive_ = false;
    subscribed_ = false;
    failureReason_ = reason;
}

X11PointerPosition
X11PointerPositionTracker::injectedRemotePosition(
    X11PointerPosition position) const noexcept
{
    // XTEST stores root X/Y as int16. Mirror X11InputController::coordinate()
    // so echo suppression records the coordinate native injection can
    // actually produce, not an untrusted out-of-range request.
    const std::uint32_t maximumX = std::min<std::uint32_t>(
        sourceGeometry_.widthPixels - 1U,
        static_cast<std::uint32_t>(std::numeric_limits<std::int16_t>::max()));
    const std::uint32_t maximumY = std::min<std::uint32_t>(
        sourceGeometry_.heightPixels - 1U,
        static_cast<std::uint32_t>(std::numeric_limits<std::int16_t>::max()));
    return {
        std::clamp(position.x, 0, static_cast<std::int32_t>(maximumX)),
        std::clamp(position.y, 0, static_cast<std::int32_t>(maximumY)),
    };
}

void
X11PointerPositionTracker::queuePosition(std::int64_t x,
                                         std::int64_t y) noexcept
{
    if (sourceGeometry_.widthPixels == 0 || sourceGeometry_.heightPixels == 0)
    {
        return;
    }
    const std::int64_t maximumX =
        static_cast<std::int64_t>(sourceGeometry_.widthPixels) - 1;
    const std::int64_t maximumY =
        static_cast<std::int64_t>(sourceGeometry_.heightPixels) - 1;
    pendingPosition_ = {
        static_cast<std::int32_t>(std::clamp<std::int64_t>(x, 0, maximumX)),
        static_cast<std::int32_t>(std::clamp<std::int64_t>(y, 0, maximumY)),
    };
    hasPendingPosition_ = true;
}
