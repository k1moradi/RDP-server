// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include <xcb/xcb.h>

#include "../core/geometry.h"
#include "x11_event_dispatch.h"

/**
 * Own the XCB connection; its socket descriptor is borrowed and must
 * never be closed independently. The caller's event loop reports socket
 * readiness and drives bounded, nonblocking XCB dispatch on the same thread.
 */
class X11DisplayConnection final
{
public:
    explicit X11DisplayConnection(std::string_view displayName) noexcept;
    ~X11DisplayConnection() noexcept;

    X11DisplayConnection(const X11DisplayConnection &) = delete;
    X11DisplayConnection &operator=(const X11DisplayConnection &) = delete;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] bool randrAvailable() const noexcept;
    [[nodiscard]] xcb_connection_t *nativeConnection() const noexcept;
    [[nodiscard]] PixelSize sourceGeometry() const noexcept;
    [[nodiscard]] int screenNumber() const noexcept;
    [[nodiscard]] xcb_window_t rootWindow() const noexcept;
    [[nodiscard]] xcb_visualid_t rootVisual() const noexcept;
    [[nodiscard]] std::uint8_t rootDepth() const noexcept;
    // Borrowed XCB-owned descriptor; -1 on failure/disconnect.
    [[nodiscard]] int fileDescriptor() const noexcept;
    // Idempotent cancellation; invalidates descriptor and all native views.
    void disconnect() noexcept;

    /**
     * Drain queued events without blocking; read the XCB socket only when
     * the external event loop reports socketReadable. If workMayRemain is
     * set, schedule another nonblocking service iteration (even without a
     * fresh edge notification). All callbacks must return before teardown.
     *
     * A dispatch/connection failure invalidates public readiness immediately
     * but deliberately keeps the owned XCB connection allocated until
     * disconnect()/destruction. This lets an aggregate owner cancel every
     * child that borrows the connection before the sole XCB owner is freed.
     */
    // RandR may replace monitors without changing root pixel dimensions.
    // A same-call notification flag does not introduce another event owner.
    [[nodiscard]] ConnectionStatus processEvents(
        X11EventSink &eventSink, std::size_t eventBudget = 128,
        bool *workMayRemain = nullptr, bool socketReadable = false,
        bool *randrChanged = nullptr) noexcept;

private:
    void markFailedForOwnerTeardown() noexcept;
    void close() noexcept;

    xcb_connection_t *connection_{nullptr};
    int connectionFileDescriptor_{-1};
    int screenNumber_{-1};
    xcb_window_t rootWindow_{XCB_WINDOW_NONE};
    xcb_visualid_t rootVisual_{XCB_NONE};
    std::uint8_t rootDepth_{0};
    std::uint8_t randrFirstEvent_{0};
    PixelSize sourceGeometry_{};
    bool failed_{false};
};
