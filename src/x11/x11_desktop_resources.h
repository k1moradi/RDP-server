// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "x11_cursor_tracker.h"
#include "x11_damage_tracker.h"
#include "x11_display_connection.h"
#include "x11_input_controller.h"
#include "x11_shared_memory_capture.h"

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
    [[nodiscard]] bool randrAvailable() const noexcept;
    [[nodiscard]] bool damagePending() const noexcept;
    [[nodiscard]] std::uint64_t damageNotificationCount() const noexcept;

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

    // Idempotent ordered cancellation. Child resources are disconnected and
    // destroyed before the sole XCB connection owner is disconnected.
    void disconnect() noexcept;

private:
    void fail(const char *reason) noexcept;
    void cancelGeometryBoundResources() noexcept;
    [[nodiscard]] bool rebuildGeometryBoundResources(
        PixelSize geometry) noexcept;
    void cancelNativeResources() noexcept;
    [[nodiscard]] bool childrenValid() const noexcept;

    // Declaration order keeps the XCB connection alive until after child
    // members even if a future destructor path misses explicit cancellation.
    X11DisplayConnection display_;
    std::optional<X11SharedMemoryCapture> capture_{};
    std::optional<X11CursorTracker> cursor_{};
    std::optional<X11DamageTracker> damage_{};
    std::optional<X11InputController> input_{};
    PixelSize resourceGeometry_{};
    std::uint64_t maximumCapturePixels_{};
    const char *failureReason_{"not initialized"};
};
