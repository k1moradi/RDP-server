// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>

#include "x11_cursor_tracker.h"
#include "x11_damage_tracker.h"
#include "x11_display_connection.h"
#include "x11_input_controller.h"
#include "x11_pointer_position_tracker.h"
#include "x11_shared_memory_capture.h"

class X11AuthorizedInputRoute;

// R5 -> R4 borrow-only framebuffer boundary. captureGeneration is native
// revocation provenance, not R4 presentation or session authorization.
// The framebuffer is valid only during consume().
struct X11R4BgraFrameConsumer final
{
    void *context{};
    bool (*consume)(void *context, const FramebufferView &framebuffer,
                    std::uint64_t captureGeneration) noexcept{};
};

struct X11CursorImageView final
{
    std::span<const std::byte> pixels{};
    std::span<const std::byte> mask{};
    std::uint32_t widthPixels{};
    std::uint32_t heightPixels{};
    std::int32_t hotspotX{};
    std::int32_t hotspotY{};

    [[nodiscard]] bool valid() const noexcept
    {
        if (widthPixels == 0 || heightPixels == 0 ||
            hotspotX < 0 || hotspotY < 0 ||
            static_cast<std::uint32_t>(hotspotX) >= widthPixels ||
            static_cast<std::uint32_t>(hotspotY) >= heightPixels)
        {
            return false;
        }
        const std::uint64_t area =
            static_cast<std::uint64_t>(widthPixels) * heightPixels;
        if (area > std::numeric_limits<std::size_t>::max() / 4U)
        {
            return false;
        }
        const std::size_t pixelBytes =
            static_cast<std::size_t>(area) * 4U;
        const std::size_t maskBytes =
            static_cast<std::size_t>(area / 8U + (area % 8U != 0 ? 1U : 0U));
        return pixels.size() >= pixelBytes && mask.size() >= maskBytes;
    }
};

/**
 * Own one Linux/X11 native desktop resource set under one XCB connection.
 *
 * This is a resource/lifetime boundary, not an authorization decision.
 * R2/R3 must independently admit the OS desktop before a runtime constructs
 * this object. The current server executable does not link this adapter.
 *
 * Thread safety: construct, service, query and disconnect on the same
 * serialized XCB owner thread. No child object or borrowed XCB handle may
 * outlive this owner.
 */
class X11DesktopResources final
{
public:
    X11DesktopResources(std::string_view displayName,
                        std::uint64_t maximumCapturePixels) noexcept;
    ~X11DesktopResources() noexcept;

    X11DesktopResources(const X11DesktopResources &) = delete;
    X11DesktopResources &operator=(const X11DesktopResources &) = delete;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] const char *failureReason() const noexcept;
    [[nodiscard]] int fileDescriptor() const noexcept;
    // Borrowed native identity for same-thread child adapters. Both become
    // invalid at disconnect and must never be closed or retained separately.
    [[nodiscard]] xcb_connection_t *nativeConnection() const noexcept;
    [[nodiscard]] xcb_window_t rootWindow() const noexcept;
    [[nodiscard]] PixelSize sourceGeometry() const noexcept;
    [[nodiscard]] std::uint64_t captureGeneration() const noexcept;
    [[nodiscard]] bool randrAvailable() const noexcept;
    [[nodiscard]] bool damagePending() const noexcept;
    [[nodiscard]] std::uint64_t damageNotificationCount() const noexcept;

    // Synchronous R4-facing reads. Framebuffer/cursor spans borrow storage
    // owned by this aggregate and are valid only until the next corresponding
    // refresh/capture, RandR rebuild, or disconnect. These methods schedule
    // nothing and confer no R2/R3 authorization.
    [[nodiscard]] bool snapshotDamage(DamageRegion &damageRegion) noexcept;
    [[nodiscard]] bool snapshotDamage(
        DamageRegion &damageRegion,
        std::uint64_t &captureGeneration) noexcept;
    [[nodiscard]] FramebufferView capture(Rectangle rectangle) noexcept;
    [[nodiscard]] FramebufferView capture(
        std::uint64_t expectedGeneration,
        Rectangle rectangle) noexcept;
    // Full-current-surface borrow. The callback must synchronously consume or
    // convert pixels and must not reenter this X11 owner.
    [[nodiscard]] bool consumeR4Frame(
        std::uint64_t expectedGeneration,
        X11R4BgraFrameConsumer consumer) noexcept;
    [[nodiscard]] bool cursorPending() const noexcept;
    [[nodiscard]] bool refreshCursor() noexcept;
    [[nodiscard]] X11CursorImageView cursorImage() const noexcept;
    [[nodiscard]] bool takeCursorRefreshFailureWarning() noexcept;
    [[nodiscard]] const char *cursorRefreshFailureReason() const noexcept;
    [[nodiscard]] std::uint8_t cursorRefreshErrorCode() const noexcept;
    [[nodiscard]] bool takeUnsupportedCursorWarning() noexcept;
    void acknowledgeCursor() noexcept;

    // Latest native pointer observation. Querying does not acknowledge it;
    // R4 reports whether publication actually completed via acknowledge.
    [[nodiscard]] bool pointerPositionAvailable() const noexcept;
    [[nodiscard]] const char *pointerPositionFailureReason() const noexcept;
    [[nodiscard]] bool pendingPointerPosition(
        X11PointerPosition &position) const noexcept;
    [[nodiscard]] bool shouldForwardPointerPosition(
        X11PointerPosition position) const noexcept;
    void acknowledgePointerPosition(X11PointerPosition position,
                                    bool forwarded) noexcept;

    /**
     * Route one bounded batch of XCB events to the owned cursor/damage
     * adapters. RandR geometry changes rebuild XShm/Damage/input against the
     * new bounds before any later queued event is serviced. Rebuild failure
     * revokes the complete native owner rather than exposing a partial mix.
     */
    [[nodiscard]] ConnectionStatus processEvents(
        std::size_t eventBudget = 128, bool *workMayRemain = nullptr,
        bool socketReadable = false,
        X11EventSink *additionalEventSink = nullptr) noexcept;

    // Idempotent graceful cancellation while native input authority remains
    // current. Child resources retire before the sole XCB connection owner.
    void disconnect() noexcept;

    // Terminal authorization-loss cancellation. Held input state is discarded
    // before every other X11 child, with no cleanup XTEST request.
    void retireAfterAuthorizationLoss() noexcept;

private:
    friend class X11AuthorizedInputRoute;

    enum class InputRetirementMode : std::uint8_t
    {
        ReleaseHeldState,
        SuppressNativeInput,
    };

    [[nodiscard]] bool handleAuthorizedInput(
        std::uint64_t expectedGeneration,
        const X11InputEvent &event) noexcept;
    void fail(const char *reason) noexcept;
    void cancelGeometryBoundResources(
        InputRetirementMode inputRetirementMode =
            InputRetirementMode::ReleaseHeldState) noexcept;
    [[nodiscard]] bool rebuildGeometryBoundResources(
        PixelSize geometry) noexcept;
    [[nodiscard]] bool initializePointerPositionTracker(
        xcb_connection_t &connection, PixelSize geometry) noexcept;
    // Fatal XCB/XShm/XTEST teardown must never emit cleanup input.
    // Only a still-authorized graceful disconnect opts in to releases.
    void cancelNativeResources(
        InputRetirementMode inputRetirementMode =
            InputRetirementMode::SuppressNativeInput) noexcept;
    [[nodiscard]] bool childrenValid() const noexcept;

    // Declaration order keeps the XCB connection alive until after child
    // members even if a future destructor path misses explicit cancellation.
    X11DisplayConnection display_;
    std::optional<X11SharedMemoryCapture> capture_{};
    std::optional<X11CursorTracker> cursor_{};
    std::optional<X11DamageTracker> damage_{};
    std::optional<X11PointerPositionTracker> pointerPosition_{};
    std::optional<X11InputController> input_{};
    PixelSize resourceGeometry_{};
    std::uint64_t captureGeneration_{};
    std::uint64_t maximumCapturePixels_{};
    const char *pointerPositionFailureReason_{
        "XInput2 pointer observation is unavailable in this build"};
    const char *failureReason_{"not initialized"};
};
