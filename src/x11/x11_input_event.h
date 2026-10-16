// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <variant>

/**
 * R5-native input requests consumed by the Linux/X11 adapter.
 *
 * These types do not grant desktop access. R3 remains responsible for
 * forwarding requests only after authentication and OS-session authorization.
 * keySymbol uses the X11 keysym numeric namespace and is therefore deliberately
 * native rather than part of the portable RDP protocol interface.
 */
struct X11KeyInput final
{
    std::uint32_t keySymbol{};
    std::uint8_t scanCode{};
    bool extended{};
    bool pressed{};
};

struct X11LockStateInput final
{
    bool capsLock{};
    bool numLock{};
    bool scrollLock{};
};

struct X11PointerMoveInput final
{
    std::int32_t x{};
    std::int32_t y{};
};

struct X11PointerButtonInput final
{
    std::int32_t x{};
    std::int32_t y{};
    std::uint8_t button{};
    bool pressed{};
};

enum class X11ScrollAxis : std::uint8_t
{
    Vertical,
    Horizontal,
};

struct X11ScrollInput final
{
    std::int32_t x{};
    std::int32_t y{};
    std::int32_t delta{};
    X11ScrollAxis axis{X11ScrollAxis::Vertical};
};

using X11InputEvent = std::variant<X11KeyInput, X11LockStateInput,
                                   X11PointerMoveInput,
                                   X11PointerButtonInput, X11ScrollInput>;
