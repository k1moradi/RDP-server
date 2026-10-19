// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_desktop_resources.h"

#include <atomic>
#include <limits>
#include <variant>

namespace
{

// Capture epochs must not restart at 1 for a replacement X11 owner. An old
// borrow from a retired owner could otherwise match a new owner with the
// same geometry and the same underlying logind session generation.
// Allocation occurs only on construction/RandR, never on the capture hot path.
// Relaxed ordering suffices: the serialized XCB owner publishes its resources.
[[nodiscard]] std::uint64_t allocateNativeCaptureGeneration() noexcept
{
    static std::atomic<std::uint64_t> nextGeneration{1U};
    std::uint64_t candidate = nextGeneration.load(std::memory_order_relaxed);
    while (candidate != 0U)
    {
        if (nextGeneration.compare_exchange_weak(
                candidate, candidate + 1U, std::memory_order_relaxed,
                std::memory_order_relaxed))
        {
            return candidate;
        }
    }
    // Exhaustion is terminal; never wrap into a live or retired generation.
    return 0U;
}

class X11DesktopResourceEventSink final : public X11EventSink
{
public:
    X11DesktopResourceEventSink(
        X11CursorTracker &cursor, X11DamageTracker &damage,
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
        X11PointerPositionTracker *pointerPosition,
#endif
        X11EventSink *additionalEventSink) noexcept
        : cursor_(cursor),
          damage_(damage),
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
          pointerPosition_(pointerPosition),
#endif
          additionalEventSink_(additionalEventSink)
    {
    }

    void handle(const xcb_generic_event_t &event) noexcept override
    {
        // Core MappingNotify invalidates cached keysym->keycode mappings and
        // modifier/side-button interpretations. Do not rebind held keys
        // inside an admitted session or deliver later native events.
        if ((event.response_type & 0x7fU) == XCB_MAPPING_NOTIFY)
        {
            mappingChanged_ = true;
            return;
        }
        if (mappingChanged_)
        {
            return;
        }
        cursor_.handle(event);
        damage_.handle(event);
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
        if (pointerPosition_ != nullptr)
        {
            pointerPosition_->handle(event);
        }
#endif
        if (additionalEventSink_ != nullptr)
        {
            additionalEventSink_->handle(event);
        }
    }

    [[nodiscard]] bool mappingChanged() const noexcept
    {
        return mappingChanged_;
    }

private:
    bool mappingChanged_{false};
    X11CursorTracker &cursor_;
    X11DamageTracker &damage_;
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
    X11PointerPositionTracker *pointerPosition_{};
#endif
    X11EventSink *additionalEventSink_{};
};

} // namespace

X11DesktopResources::X11DesktopResources(
    std::string_view displayName,
    std::uint64_t maximumCapturePixels) noexcept
    : display_(displayName), maximumCapturePixels_(maximumCapturePixels)
{
    if (!display_.valid())
    {
        fail("X11 desktop display connection failed");
        cancelNativeResources();
        return;
    }

    xcb_connection_t *connection = display_.nativeConnection();
    const PixelSize geometry = display_.sourceGeometry();
    if (connection == nullptr || geometry.widthPixels == 0 ||
        geometry.heightPixels == 0)
    {
        fail("X11 desktop display geometry is invalid");
        cancelNativeResources();
        return;
    }

    capture_.emplace(*connection, display_.rootWindow(), display_.rootVisual(),
                     display_.rootDepth(), geometry, maximumCapturePixels_);
    if (!capture_->valid())
    {
        fail(capture_->failureReason());
        cancelNativeResources();
        return;
    }

    cursor_.emplace(*connection, display_.rootWindow());
    if (!cursor_->valid())
    {
        fail(cursor_->failureReason());
        cancelNativeResources();
        return;
    }

    damage_.emplace(*connection, display_.rootWindow(), geometry);
    if (!damage_->valid())
    {
        fail(damage_->failureReason());
        cancelNativeResources();
        return;
    }

    input_.emplace(*connection, display_.rootWindow(), geometry);
    if (!input_->valid())
    {
        fail(input_->failureReason());
        cancelNativeResources();
        return;
    }

    if (!initializePointerPositionTracker(*connection, geometry))
    {
        cancelNativeResources();
        return;
    }

    // A generation is unique across consecutive native owners in this process,
    // not merely among RandR rebuilds inside one owner.
    captureGeneration_ = allocateNativeCaptureGeneration();
    if (captureGeneration_ == 0U)
    {
        fail("X11 native capture generation exhausted");
        cancelNativeResources();
        return;
    }
    resourceGeometry_ = geometry;
    failureReason_ = nullptr;
}

X11DesktopResources::~X11DesktopResources() noexcept
{
    disconnect();
}

bool
X11DesktopResources::valid() const noexcept
{
    return failureReason_ == nullptr && display_.valid() &&
           childrenValid() && captureGeneration_ != 0 &&
           resourceGeometry_ == display_.sourceGeometry();
}

const char *
X11DesktopResources::failureReason() const noexcept
{
    return failureReason_;
}

int
X11DesktopResources::fileDescriptor() const noexcept
{
    return valid() ? display_.fileDescriptor() : -1;
}

xcb_connection_t *
X11DesktopResources::nativeConnection() const noexcept
{
    return valid() ? display_.nativeConnection() : nullptr;
}

xcb_window_t
X11DesktopResources::rootWindow() const noexcept
{
    return valid() ? display_.rootWindow() : xcb_window_t{};
}

PixelSize
X11DesktopResources::sourceGeometry() const noexcept
{
    return valid() ? resourceGeometry_ : PixelSize{};
}

std::uint64_t
X11DesktopResources::captureGeneration() const noexcept
{
    return valid() ? captureGeneration_ : 0;
}

X11NativeGeometryObservation
X11DesktopResources::observeNativeGeometry(
    std::uint64_t nativeSessionGeneration) const noexcept
{
    if (!valid() || nativeSessionGeneration == 0)
    {
        return {};
    }
    return {resourceGeometry_, captureGeneration_, nativeSessionGeneration};
}

bool
X11DesktopResources::nativeGeometryIsCurrent(
    const X11NativeGeometryObservation &observation,
    std::uint64_t currentNativeSessionGeneration) const noexcept
{
    return observation.valid() && currentNativeSessionGeneration != 0 &&
           observation.nativeSessionGeneration == currentNativeSessionGeneration &&
           valid() && observation.captureGeneration == captureGeneration_ &&
           observation.pixelGeometry == resourceGeometry_;
}

bool
X11DesktopResources::randrAvailable() const noexcept
{
    return valid() && display_.randrAvailable();
}

bool
X11DesktopResources::damagePending() const noexcept
{
    return valid() && damage_->hasPendingDamage();
}

std::uint64_t
X11DesktopResources::damageNotificationCount() const noexcept
{
    return valid() ? damage_->notificationCount() : 0;
}

bool
X11DesktopResources::snapshotDamage(DamageRegion &damageRegion) noexcept
{
    std::uint64_t ignoredGeneration = 0;
    return snapshotDamage(damageRegion, ignoredGeneration);
}

bool
X11DesktopResources::snapshotDamage(
    DamageRegion &damageRegion,
    std::uint64_t &captureGeneration) noexcept
{
    damageRegion.clear();
    captureGeneration = 0;
    if (!valid())
    {
        return false;
    }
    if (!damage_->snapshot(damageRegion))
    {
        const char *reason = damage_->failureReason();
        damageRegion.clear();
        fail(reason);
        cancelNativeResources();
        return false;
    }
    captureGeneration = captureGeneration_;
    return true;
}

FramebufferView
X11DesktopResources::capture(Rectangle rectangle) noexcept
{
    return capture(captureGeneration(), rectangle);
}

FramebufferView
X11DesktopResources::capture(
    std::uint64_t expectedGeneration,
    Rectangle rectangle) noexcept
{
    if (!valid() || expectedGeneration == 0 ||
        expectedGeneration != captureGeneration_)
    {
        return {};
    }

    const FramebufferView frame = capture_->capture(rectangle);
    if (!frame.valid())
    {
        const char *reason = capture_->failureReason();
        fail(reason);
        cancelNativeResources();
        return {};
    }
    return frame;
}

bool
X11DesktopResources::consumeR4Frame(
    std::uint64_t expectedGeneration,
    X11R4BgraFrameConsumer consumer) noexcept
{
    if (!valid() || expectedGeneration == 0 ||
        expectedGeneration != captureGeneration_ ||
        consumer.context == nullptr || consumer.consume == nullptr)
    {
        return false;
    }

    const PixelSize geometry = resourceGeometry_;
    const std::size_t widthPixels = geometry.widthPixels;
    if (widthPixels > std::numeric_limits<std::size_t>::max() / 4U)
    {
        return false;
    }
    const std::size_t expectedStride = widthPixels * 4U;
    if (expectedStride == 0 ||
        geometry.heightPixels >
            std::numeric_limits<std::size_t>::max() / expectedStride)
    {
        return false;
    }

    const FramebufferView framebuffer = capture(
        expectedGeneration,
        {0, 0, geometry.widthPixels, geometry.heightPixels});
    if (!framebuffer.valid() ||
        framebuffer.widthPixels != geometry.widthPixels ||
        framebuffer.heightPixels != geometry.heightPixels ||
        framebuffer.strideBytes != expectedStride ||
        framebuffer.pixels.size() !=
            expectedStride * geometry.heightPixels)
    {
        return false;
    }

    const bool consumed =
        consumer.consume(consumer.context, framebuffer, expectedGeneration);
    return consumed && valid() &&
           captureGeneration_ == expectedGeneration &&
           resourceGeometry_ == geometry;
}

bool
X11DesktopResources::consumeR4Frame(
    const X11NativeGeometryObservation &observation,
    std::uint64_t currentNativeSessionGeneration,
    X11R4BgraFrameConsumer consumer) noexcept
{
    if (!nativeGeometryIsCurrent(observation, currentNativeSessionGeneration))
    {
        return false;
    }

    // Existing callback owns the only temporary XShm pixel borrow and
    // synchronously checks capture generation again after consumption.
    return consumeR4Frame(observation.captureGeneration, consumer);
}

bool
X11DesktopResources::cursorPending() const noexcept
{
    return valid() && cursor_->pending();
}

bool
X11DesktopResources::refreshCursor() noexcept
{
    if (!valid())
    {
        return false;
    }
    if (!cursor_->pending())
    {
        return true;
    }
    if (!cursor_->refresh() || !cursor_->valid())
    {
        const char *reason = cursor_->failureReason();
        fail(reason);
        cancelNativeResources();
        return false;
    }
    return true;
}

X11CursorImageView
X11DesktopResources::cursorImage() const noexcept
{
    if (!valid() || !cursor_->hasImage())
    {
        return {};
    }

    X11CursorImageView view{
        cursor_->pixels(),
        cursor_->mask(),
        cursor_->widthPixels(),
        cursor_->heightPixels(),
        cursor_->hotspotX(),
        cursor_->hotspotY(),
    };
    return view.valid() ? view : X11CursorImageView{};
}

bool
X11DesktopResources::takeCursorRefreshFailureWarning() noexcept
{
    return valid() && cursor_->takeRefreshFailureWarning();
}

const char *
X11DesktopResources::cursorRefreshFailureReason() const noexcept
{
    return valid() ? cursor_->refreshFailureReason() : nullptr;
}

std::uint8_t
X11DesktopResources::cursorRefreshErrorCode() const noexcept
{
    return valid() ? cursor_->refreshErrorCode() : 0;
}

bool
X11DesktopResources::takeUnsupportedCursorWarning() noexcept
{
    return valid() && cursor_->takeUnsupportedCursorWarning();
}

void
X11DesktopResources::acknowledgeCursor() noexcept
{
    if (valid())
    {
        cursor_->acknowledge();
    }
}

bool
X11DesktopResources::pointerPositionAvailable() const noexcept
{
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
    return valid() && pointerPosition_.has_value() &&
           pointerPosition_->valid();
#else
    return false;
#endif
}

const char *
X11DesktopResources::pointerPositionFailureReason() const noexcept
{
    if (failureReason_ != nullptr)
    {
        return failureReason_;
    }
    return pointerPositionAvailable() ? nullptr
                                      : pointerPositionFailureReason_;
}

bool
X11DesktopResources::pendingPointerPosition(
    X11PointerPosition &position) const noexcept
{
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
    return pointerPositionAvailable() &&
           pointerPosition_->pendingPosition(position);
#else
    (void)position;
    return false;
#endif
}

bool
X11DesktopResources::shouldForwardPointerPosition(
    X11PointerPosition position) const noexcept
{
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
    return pointerPositionAvailable() &&
           pointerPosition_->shouldForward(position);
#else
    (void)position;
    return false;
#endif
}

void
X11DesktopResources::acknowledgePointerPosition(
    X11PointerPosition position, bool forwarded) noexcept
{
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
    if (pointerPositionAvailable())
    {
        pointerPosition_->acknowledge(position, forwarded);
    }
#else
    (void)position;
    (void)forwarded;
#endif
}

bool
X11DesktopResources::handleAuthorizedInput(
    std::uint64_t expectedGeneration,
    const X11InputEvent &event) noexcept
{
    // The capture epoch is also the one geometry-bound XTEST-owner epoch.
    // Recheck beside native injection so no caller can treat the scalar as
    // authority or accidentally target a replacement RandR generation.
    if (!valid() || expectedGeneration == 0 ||
        expectedGeneration != captureGeneration_)
    {
        return false;
    }

#if defined(RDP_SERVER_X11_XINPUT_POINTER)
    if (const auto *pointerMove = std::get_if<X11PointerMoveInput>(&event);
        pointerMove != nullptr && pointerPositionAvailable())
    {
        const X11PointerPosition position{pointerMove->x, pointerMove->y};
        if (!pointerPosition_->shouldAcceptRemoteMotion(position))
        {
            // A locally forwarded native move can be echoed back by the RDP
            // peer. Suppress only that motion; a distinct remote coordinate
            // transfers authority back immediately.
            return true;
        }
        if (!input_->handle(event))
        {
            const char *reason = input_->failureReason();
            fail(reason);
            cancelNativeResources();
            return false;
        }
        pointerPosition_->noteRemotePointerPosition(position);
        return true;
    }
#endif

    if (!input_->handle(event))
    {
        const char *reason = input_->failureReason();
        fail(reason);
        cancelNativeResources();
        return false;
    }
    return true;
}

ConnectionStatus
X11DesktopResources::processEvents(std::size_t eventBudget,
                                  bool *workMayRemain,
                                  bool socketReadable,
                                  X11EventSink *additionalEventSink) noexcept
{
    if (workMayRemain != nullptr)
    {
        *workMayRemain = false;
    }
    if (failureReason_ != nullptr || !display_.valid() || !childrenValid() ||
        resourceGeometry_ != display_.sourceGeometry())
    {
        if (failureReason_ == nullptr)
        {
            fail("X11 desktop resources became invalid before event dispatch");
        }
        cancelNativeResources();
        return ConnectionStatus::Failed;
    }

    X11DesktopResourceEventSink eventSink(
        *cursor_, *damage_,
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
        pointerPosition_.has_value() ? &*pointerPosition_ : nullptr,
#endif
        additionalEventSink);
    const ConnectionStatus status = display_.processEvents(
        eventSink, eventBudget, workMayRemain, socketReadable);
    if (eventSink.mappingChanged())
    {
        if (workMayRemain != nullptr)
        {
            *workMayRemain = false;
        }
        // MappingNotify is not a display authorization. All existing held
        // XTEST keys are retired without a compensating native release:
        // their old physical keycodes may refer to different keys now.
        fail("X11 input mapping changed during the admitted session");
        cancelNativeResources(InputRetirementMode::SuppressNativeInput);
        return ConnectionStatus::Failed;
    }
    if (status == ConnectionStatus::Failed)
    {
        if (workMayRemain != nullptr)
        {
            *workMayRemain = false;
        }
        fail("X11 desktop event dispatch failed");
        cancelNativeResources();
        return ConnectionStatus::Failed;
    }

    const PixelSize observedGeometry = display_.sourceGeometry();
    if (observedGeometry != resourceGeometry_)
    {
        if (!rebuildGeometryBoundResources(observedGeometry))
        {
            if (workMayRemain != nullptr)
            {
                *workMayRemain = false;
            }
            return ConnectionStatus::Failed;
        }

        // The display drain stops immediately after a valid RandR screen
        // change. Service any events queued behind it only after the new
        // geometry-bound generation is fully committed.
        if (workMayRemain != nullptr)
        {
            *workMayRemain = true;
        }
    }
    if (!childrenValid())
    {
        if (workMayRemain != nullptr)
        {
            *workMayRemain = false;
        }
        fail("X11 desktop child resource failed during event dispatch");
        cancelNativeResources();
        return ConnectionStatus::Failed;
    }

    return ConnectionStatus::Ok;
}

void
X11DesktopResources::disconnect() noexcept
{
    const bool wasHealthy = failureReason_ == nullptr;
    // A graceful caller may release held input only while R2 is still live;
    // terminal capture/event/injection failure uses the suppressing default.
    cancelNativeResources(InputRetirementMode::ReleaseHeldState);
    if (wasHealthy)
    {
        failureReason_ = "X11 desktop resources are disconnected";
    }
}

void
X11DesktopResources::retireAfterAuthorizationLoss() noexcept
{
    const bool wasHealthy = failureReason_ == nullptr;
    cancelNativeResources(InputRetirementMode::SuppressNativeInput);
    if (wasHealthy)
    {
        failureReason_ =
            "X11 desktop resources retired after authorization loss";
    }
}

void
X11DesktopResources::fail(const char *reason) noexcept
{
    failureReason_ = reason != nullptr ? reason : "X11 desktop resource failure";
}

void
X11DesktopResources::cancelGeometryBoundResources(
    InputRetirementMode inputRetirementMode) noexcept
{
    // Input always retires first. Graceful/RandR retirement may release held
    // state while authority is current; authorization loss must never emit a
    // cleanup XTEST request.
    if (input_)
    {
        if (inputRetirementMode == InputRetirementMode::SuppressNativeInput)
        {
            input_->retireWithoutNativeInput();
        }
        else
        {
            input_->disconnect();
        }
        input_.reset();
    }
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
    if (pointerPosition_)
    {
        pointerPosition_->disconnect();
    }
#endif
    pointerPosition_.reset();
    if (damage_)
    {
        damage_->disconnect();
        damage_.reset();
    }
    if (capture_)
    {
        capture_->disconnect();
        capture_.reset();
    }
    resourceGeometry_ = {};
}

bool
X11DesktopResources::rebuildGeometryBoundResources(
    PixelSize geometry) noexcept
{
    xcb_connection_t *connection = display_.nativeConnection();
    if (connection == nullptr || geometry.widthPixels == 0 ||
        geometry.heightPixels == 0)
    {
        fail("X11 desktop resize geometry is invalid");
        cancelNativeResources();
        return false;
    }

    if (captureGeneration_ == 0U)
    {
        fail("X11 desktop capture generation cannot advance");
        cancelNativeResources();
        return false;
    }
    const std::uint64_t nextCaptureGeneration =
        allocateNativeCaptureGeneration();
    if (nextCaptureGeneration == 0U)
    {
        fail("X11 native capture generation exhausted");
        cancelNativeResources();
        return false;
    }

    // Commit-or-revoke transaction: no public call can observe the interval
    // between old-generation cancellation and complete new construction.
    cancelGeometryBoundResources();

    capture_.emplace(*connection, display_.rootWindow(), display_.rootVisual(),
                     display_.rootDepth(), geometry, maximumCapturePixels_);
    if (!capture_->valid())
    {
        fail(capture_->failureReason());
        cancelNativeResources();
        return false;
    }

    damage_.emplace(*connection, display_.rootWindow(), geometry);
    if (!damage_->valid())
    {
        fail(damage_->failureReason());
        cancelNativeResources();
        return false;
    }

    input_.emplace(*connection, display_.rootWindow(), geometry);
    if (!input_->valid())
    {
        fail(input_->failureReason());
        cancelNativeResources();
        return false;
    }

    if (!initializePointerPositionTracker(*connection, geometry))
    {
        cancelNativeResources();
        return false;
    }

    resourceGeometry_ = geometry;
    captureGeneration_ = nextCaptureGeneration;
    return true;
}

bool
X11DesktopResources::initializePointerPositionTracker(
    xcb_connection_t &connection, PixelSize geometry) noexcept
{
#if defined(RDP_SERVER_X11_XINPUT_POINTER)
    pointerPosition_.emplace(connection, display_.rootWindow(), geometry);
    if (pointerPosition_->valid())
    {
        pointerPositionFailureReason_ = nullptr;
        return true;
    }

    pointerPositionFailureReason_ = pointerPosition_->failureReason();
    const bool sharedConnectionFailed =
        xcb_connection_has_error(&connection) != 0;
    pointerPosition_->disconnect();
    pointerPosition_.reset();

    // Missing XI2/version/subscription is feature-local. A failed shared XCB
    // transport is not: the sole owner must revoke the complete aggregate.
    if (sharedConnectionFailed)
    {
        fail(pointerPositionFailureReason_ != nullptr
                 ? pointerPositionFailureReason_
                 : "XInput2 pointer observer lost the X11 connection");
        return false;
    }
    return true;
#else
    (void)connection;
    (void)geometry;
    pointerPosition_.reset();
    pointerPositionFailureReason_ =
        "XInput2 pointer observation is unavailable in this build";
    return true;
#endif
}

void
X11DesktopResources::cancelNativeResources(
    InputRetirementMode inputRetirementMode) noexcept
{
    cancelGeometryBoundResources(inputRetirementMode);

    // Cursor is not geometry-bound, but it still borrows the same connection.
    if (cursor_)
    {
        cursor_->disconnect();
        cursor_.reset();
    }

    display_.disconnect();
}

bool
X11DesktopResources::childrenValid() const noexcept
{
    return capture_.has_value() && capture_->valid() &&
           cursor_.has_value() && cursor_->valid() &&
           damage_.has_value() && damage_->valid() &&
           input_.has_value() && input_->valid();
}
