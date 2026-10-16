// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

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
 * Thread safety: construct, query and disconnect on the same serialized XCB
 * owner thread. No child object or borrowed XCB handle may outlive this owner.
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
    [[nodiscard]] PixelSize sourceGeometry() const noexcept;
    [[nodiscard]] bool randrAvailable() const noexcept;

    // Idempotent ordered cancellation. Child resources are disconnected and
    // destroyed before the sole XCB connection owner is disconnected.
    void disconnect() noexcept;

private:
    void fail(const char *reason) noexcept;
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
    const char *failureReason_{"not initialized"};
};
