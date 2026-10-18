// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_rdp_slow_path_input.h"

#include <cstdint>

std::optional<X11InputEvent> translateRdpSlowPathX11Input(
    const rdp_server::server::transport::RdpSlowPathInputEvent &event,
    PixelSize geometry) noexcept
{
    using Kind = rdp_server::server::transport::RdpSlowPathInputEventKind;

    if (geometry.widthPixels == 0U || geometry.heightPixels == 0U)
        return std::nullopt;

    switch (event.kind)
    {
    case Kind::Synchronize:
    {
        // TS_SYNC_EVENT: lock flags 1/2/4 are supported. Kana/unknown
        // bits need explicit native ownership semantics before enabling.
        if ((event.toggleFlags & ~std::uint32_t{0x07U}) != 0U)
            return std::nullopt;
        return X11LockStateInput{
            (event.toggleFlags & 0x04U) != 0U,
            (event.toggleFlags & 0x02U) != 0U,
            (event.toggleFlags & 0x01U) != 0U};
    }
    case Kind::Mouse:
    {
        // Coordinates come from R3's exact TS_POINTER_EVENT decode. XTEST
        // must not clamp a client-selected out-of-bounds location into an
        // otherwise authorized physical X11 desktop.
        if (event.xPos >= geometry.widthPixels ||
            event.yPos >= geometry.heightPixels)
            return std::nullopt;

        constexpr std::uint16_t move = 0x0800U;
        constexpr std::uint16_t down = 0x8000U;
        constexpr std::uint16_t left = 0x1000U;
        constexpr std::uint16_t right = 0x2000U;
        constexpr std::uint16_t middle = 0x4000U;
        const std::uint16_t flags = event.pointerFlags;
        if (flags == move)
            return X11PointerMoveInput{event.xPos, event.yPos};

        // Exactly one button, optionally DOWN; no synthetic composite
        // motion/button, wheel, unknown flags or ignored bits.
        const std::uint16_t buttonBits = flags & (left | right | middle);
        const std::uint16_t otherBits =
            flags & static_cast<std::uint16_t>(~(down | left | right | middle));
        if (otherBits != 0U ||
            (buttonBits != left && buttonBits != right &&
             buttonBits != middle))
            return std::nullopt;

        // RDP button1=left, button2=right, button3=middle. X11 core
        // button2=middle, button3=right.
        const std::uint8_t nativeButton = buttonBits == left
            ? 1U : (buttonBits == right ? 3U : 2U);
        return X11PointerButtonInput{
            event.xPos, event.yPos, nativeButton, (flags & down) != 0U};
    }
    case Kind::ExtendedMouse:
    {
        // MS-RDPBCGR TS_POINTERX_EVENT: these are distinct XBUTTON1/2
        // events, not ordinary RDP button 1/2. X11 core button numbers
        // 8/9 implement the conventional Back/Forward side buttons.
        // R3's negotiated MouseX feature and R2's input permission must
        // have been checked by the sole authenticated callback owner.
        if (event.xPos >= geometry.widthPixels ||
            event.yPos >= geometry.heightPixels)
            return std::nullopt;

        constexpr std::uint16_t down = 0x8000U;
        constexpr std::uint16_t xbutton1 = 0x0001U;
        constexpr std::uint16_t xbutton2 = 0x0002U;
        const std::uint16_t flags = event.pointerFlags;
        if ((flags & static_cast<std::uint16_t>(
                ~(down | xbutton1 | xbutton2))) != 0U)
            return std::nullopt;
        const std::uint16_t buttonBits = flags & (xbutton1 | xbutton2);
        if (buttonBits != xbutton1 && buttonBits != xbutton2)
            return std::nullopt;

        const std::uint8_t nativeButton =
            buttonBits == xbutton1 ? 8U : 9U;
        return X11PointerButtonInput{
            event.xPos, event.yPos, nativeButton, (flags & down) != 0U};
    }
    case Kind::Unused:
    case Kind::ScancodeKeyboard:
    case Kind::UnicodeKeyboard:
    case Kind::RelativeMouse:
        return std::nullopt;
    }
    return std::nullopt;
}
