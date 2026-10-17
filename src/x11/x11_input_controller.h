// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include <xcb/xcb.h>

#include "../core/geometry.h"
#include "x11_input_event.h"

class X11InputController final
{
public:
    X11InputController(xcb_connection_t &connection, xcb_window_t rootWindow,
                       PixelSize bounds) noexcept;
    ~X11InputController() noexcept;

    X11InputController(const X11InputController &) = delete;
    X11InputController &operator=(const X11InputController &) = delete;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] const char *failureReason() const noexcept;

    // The request is already authorized by R2/R3; this native adapter does
    // not make or cache an authorization decision of its own.
    [[nodiscard]] bool handle(const X11InputEvent &event) noexcept;

    // Graceful retirement while input authority is still current: release held
    // native state before invalidating the borrowed XCB owner.
    void disconnect() noexcept;

    // Terminal authority-loss retirement. Discard held state without emitting
    // any XTEST request after R2/R3 permission has been revoked.
    void retireWithoutNativeInput() noexcept;

private:
    struct KeyMapping
    {
        xcb_keysym_t keysym{};
        xcb_keycode_t keycode{};
    };

    void fail(const char *reason) noexcept;
    void releaseAll() noexcept;
    void retireState(const char *reason) noexcept;
    [[nodiscard]] xcb_keycode_t keycodeFor(xcb_keysym_t keysym) const noexcept;
    [[nodiscard]] bool handleKey(const X11KeyInput &input) noexcept;
    [[nodiscard]] bool synchronizeLocks(const X11LockStateInput &input) noexcept;
    [[nodiscard]] bool handlePointerButton(
        const X11PointerButtonInput &input) noexcept;
    [[nodiscard]] bool handleScroll(const X11ScrollInput &input) noexcept;
    [[nodiscard]] bool emitScrollClicks(std::int32_t x, std::int32_t y,
                                        std::int32_t delta,
                                        std::int64_t &accumulator,
                                        std::uint8_t positiveButton,
                                        std::uint8_t negativeButton) noexcept;
    [[nodiscard]] bool fakeKey(xcb_keycode_t keycode, bool pressed) noexcept;
    [[nodiscard]] bool fakePointer(std::int32_t x, std::int32_t y) noexcept;
    [[nodiscard]] bool fakeButton(std::uint8_t type, std::uint8_t button,
                                  std::int32_t x, std::int32_t y,
                                  bool flush = true) noexcept;
    [[nodiscard]] bool fakeInput(std::uint8_t type, std::uint8_t detail,
                                 std::int16_t x, std::int16_t y,
                                 bool flush = true) noexcept;
    [[nodiscard]] bool flushInput() noexcept;
    [[nodiscard]] std::int16_t coordinate(std::int32_t value,
                                          std::uint32_t bound) const noexcept;
    [[nodiscard]] std::size_t keySlot(std::uint8_t scanCode,
                                      bool extended) const noexcept;

    xcb_connection_t *connection_{nullptr};
    xcb_window_t rootWindow_{XCB_WINDOW_NONE};
    PixelSize bounds_{};
    std::vector<KeyMapping> keyMappings_{};
    std::array<xcb_keycode_t, 256> latin1Keycodes_{};
    std::array<xcb_keycode_t, 256> functionKeycodes_{};
    bool hasDirectKeycodes_{false};
    std::array<xcb_keycode_t, 512> activeKeycodes_{};
    std::array<bool, 10> pressedButtons_{};
    std::array<xcb_keycode_t, 3> lockKeycodes_{};
    std::array<std::uint16_t, 3> lockMasks_{};
    std::int64_t verticalScrollRemainder_{};
    std::int64_t horizontalScrollRemainder_{};
    const char *failureReason_{"not initialized"};
};
