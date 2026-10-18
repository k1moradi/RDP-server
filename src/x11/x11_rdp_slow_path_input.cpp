// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_rdp_slow_path_input.h"

#include <cstdint>

namespace
{
// US PC-101 scan-set-1 baseline; ISO/OEM keys remain denied. Current XCB mapping resolves these keysyms on each
// new native owner. E1, ambiguous OEM/IME keys and unknown flags deny.
[[nodiscard]] constexpr std::uint32_t keysymForSet1Scancode(
    std::uint16_t scanCode, bool extended) noexcept
{
    if (extended)
    {
        switch (scanCode)
        {
        case 0x1cU: return 0xff8dU;
        case 0x1dU: return 0xffe4U;
        case 0x35U: return 0xffafU;
        case 0x37U: return 0xff61U;
        case 0x38U: return 0xffeaU;
        case 0x47U: return 0xff50U;
        case 0x48U: return 0xff52U;
        case 0x49U: return 0xff55U;
        case 0x4bU: return 0xff51U;
        case 0x4dU: return 0xff53U;
        case 0x4fU: return 0xff57U;
        case 0x50U: return 0xff54U;
        case 0x51U: return 0xff56U;
        case 0x52U: return 0xff63U;
        case 0x53U: return 0xffffU;
        case 0x5bU: return 0xffebU;
        case 0x5cU: return 0xffecU;
        case 0x5dU: return 0xff67U;
        default: return 0U;
        }
    }
    switch (scanCode)
    {
        case 0x01U: return 0xff1bU;
        case 0x02U: return 0x0031U;
        case 0x03U: return 0x0032U;
        case 0x04U: return 0x0033U;
        case 0x05U: return 0x0034U;
        case 0x06U: return 0x0035U;
        case 0x07U: return 0x0036U;
        case 0x08U: return 0x0037U;
        case 0x09U: return 0x0038U;
        case 0x0aU: return 0x0039U;
        case 0x0bU: return 0x0030U;
        case 0x0cU: return 0x002dU;
        case 0x0dU: return 0x003dU;
        case 0x0eU: return 0xff08U;
        case 0x0fU: return 0xff09U;
        case 0x10U: return 0x0071U;
        case 0x11U: return 0x0077U;
        case 0x12U: return 0x0065U;
        case 0x13U: return 0x0072U;
        case 0x14U: return 0x0074U;
        case 0x15U: return 0x0079U;
        case 0x16U: return 0x0075U;
        case 0x17U: return 0x0069U;
        case 0x18U: return 0x006fU;
        case 0x19U: return 0x0070U;
        case 0x1aU: return 0x005bU;
        case 0x1bU: return 0x005dU;
        case 0x1cU: return 0xff0dU;
        case 0x1dU: return 0xffe3U;
        case 0x1eU: return 0x0061U;
        case 0x1fU: return 0x0073U;
        case 0x20U: return 0x0064U;
        case 0x21U: return 0x0066U;
        case 0x22U: return 0x0067U;
        case 0x23U: return 0x0068U;
        case 0x24U: return 0x006aU;
        case 0x25U: return 0x006bU;
        case 0x26U: return 0x006cU;
        case 0x27U: return 0x003bU;
        case 0x28U: return 0x0027U;
        case 0x29U: return 0x0060U;
        case 0x2aU: return 0xffe1U;
        case 0x2bU: return 0x005cU;
        case 0x2cU: return 0x007aU;
        case 0x2dU: return 0x0078U;
        case 0x2eU: return 0x0063U;
        case 0x2fU: return 0x0076U;
        case 0x30U: return 0x0062U;
        case 0x31U: return 0x006eU;
        case 0x32U: return 0x006dU;
        case 0x33U: return 0x002cU;
        case 0x34U: return 0x002eU;
        case 0x35U: return 0x002fU;
        case 0x36U: return 0xffe2U;
        case 0x37U: return 0xffaaU;
        case 0x38U: return 0xffe9U;
        case 0x39U: return 0x0020U;
        case 0x3aU: return 0xffe5U;
        case 0x3bU: return 0xffbeU;
        case 0x3cU: return 0xffbfU;
        case 0x3dU: return 0xffc0U;
        case 0x3eU: return 0xffc1U;
        case 0x3fU: return 0xffc2U;
        case 0x40U: return 0xffc3U;
        case 0x41U: return 0xffc4U;
        case 0x42U: return 0xffc5U;
        case 0x43U: return 0xffc6U;
        case 0x44U: return 0xffc7U;
        case 0x45U: return 0xff7fU;
        case 0x46U: return 0xff14U;
        case 0x47U: return 0xff95U;
        case 0x48U: return 0xff97U;
        case 0x49U: return 0xff9aU;
        case 0x4aU: return 0xffadU;
        case 0x4bU: return 0xff96U;
        case 0x4cU: return 0xff9dU;
        case 0x4dU: return 0xff98U;
        case 0x4eU: return 0xffabU;
        case 0x4fU: return 0xff9cU;
        case 0x50U: return 0xff99U;
        case 0x51U: return 0xff9bU;
        case 0x52U: return 0xff9eU;
        case 0x53U: return 0xff9fU;
        case 0x57U: return 0xffc8U;
        case 0x58U: return 0xffc9U;
    default: return 0U;
    }
}
} // namespace

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
        constexpr std::uint16_t wheelFlags = 0x0600U;
        // Wheel coordinate fields are intentionally ignored by the RDP
        // protocol. Only absolute motion/buttons require geometry bounds.
        if ((event.pointerFlags & wheelFlags) == 0U &&
            (event.xPos >= geometry.widthPixels ||
             event.yPos >= geometry.heightPixels))
            return std::nullopt;

        constexpr std::uint16_t move = 0x0800U;
        constexpr std::uint16_t down = 0x8000U;
        constexpr std::uint16_t left = 0x1000U;
        constexpr std::uint16_t right = 0x2000U;
        constexpr std::uint16_t middle = 0x4000U;
        const std::uint16_t flags = event.pointerFlags;

        constexpr std::uint16_t verticalWheel = 0x0200U;
        constexpr std::uint16_t horizontalWheel = 0x0400U;
        constexpr std::uint16_t wheelMask = 0x01ffU;
        constexpr std::uint16_t wheelSign = 0x0100U;
        if ((flags & (verticalWheel | horizontalWheel)) != 0U)
        {
            // MS-RDPBCGR TS_POINTER_EVENT: a signed 9-bit wheel
            // rotation. Sign-extension is essential: 0x188 means -120,
            // not +136. Vertical wins if both axis flags appear.
            // Other flags are ignored by the wheel interpretation.
            // Client wheel xPos/yPos MUST NOT affect the X11 cursor.
            const std::uint16_t wheelBits = flags & wheelMask;
            const std::int32_t rotation =
                (wheelBits & wheelSign) != 0U
                    ? static_cast<std::int32_t>(wheelBits) - 0x200
                    : static_cast<std::int32_t>(wheelBits);
            return X11ScrollInput{
                0, 0, rotation,
                (flags & verticalWheel) != 0U
                    ? X11ScrollAxis::Vertical
                    : X11ScrollAxis::Horizontal};
        }

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
    case Kind::ScancodeKeyboard:
    {
        // MS-RDPBCGR: DOWN means previously held; RELEASE means key-up.
        // E1 Pause uses a separate multi-event sequence, not an E0 key.
        constexpr std::uint16_t allowedFlags = 0xc100U;
        constexpr std::uint16_t extendedFlag = 0x0100U;
        constexpr std::uint16_t downFlag = 0x4000U;
        constexpr std::uint16_t releaseFlag = 0x8000U;
        if ((event.keyboardFlags & ~allowedFlags) != 0U)
            return std::nullopt;
        const bool extended = (event.keyboardFlags & extendedFlag) != 0U;
        const std::uint32_t keysym =
            keysymForSet1Scancode(event.keyCode, extended);
        if (keysym == 0U)
            return std::nullopt;
        return X11KeyInput{
            keysym, static_cast<std::uint8_t>(event.keyCode), extended,
            (event.keyboardFlags & releaseFlag) == 0U,
            (event.keyboardFlags & downFlag) != 0U};
    }
    case Kind::Unused:
    case Kind::UnicodeKeyboard:
    case Kind::RelativeMouse:
        return std::nullopt;
    }
    return std::nullopt;
}
