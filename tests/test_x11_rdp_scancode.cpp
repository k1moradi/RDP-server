// SPDX-License-Identifier: GPL-3.0-or-later
// R3-decoded keyboard events only. No XCB, credentials, native OS admission or XTEST.
#include "x11/x11_rdp_slow_path_input.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>

using rdp_server::server::transport::RdpSlowPathInputEvent;
using rdp_server::server::transport::RdpSlowPathInputEventKind;

int main()
{
    constexpr PixelSize geometry{1280U, 720U};
    RdpSlowPathInputEvent event{};
    event.kind = RdpSlowPathInputEventKind::ScancodeKeyboard;
    event.keyCode = 0x1eU;
    auto translated = translateRdpSlowPathX11Input(event, geometry);
    assert(translated && std::holds_alternative<X11KeyInput>(*translated));
    auto key = std::get<X11KeyInput>(*translated);
    assert(key.keySymbol == 0x61U && key.scanCode == 0x1eU);
    assert(!key.extended && key.pressed && !key.previouslyDown);

    event.keyboardFlags = 0x4000U; // DOWN means previously held
    translated = translateRdpSlowPathX11Input(event, geometry);
    assert(translated);
    key = std::get<X11KeyInput>(*translated);
    assert(key.pressed && key.previouslyDown);

    event.keyboardFlags = 0xc000U; // RELEASE and previous DOWN are independent
    translated = translateRdpSlowPathX11Input(event, geometry);
    assert(translated);
    key = std::get<X11KeyInput>(*translated);
    assert(!key.pressed && key.previouslyDown);

    event.keyboardFlags = 0x8000U;
    translated = translateRdpSlowPathX11Input(event, geometry);
    assert(translated && !std::get<X11KeyInput>(*translated).pressed &&
           !std::get<X11KeyInput>(*translated).previouslyDown);

    constexpr std::array<std::uint16_t, 4> modifiers{
        0x1dU, 0x2aU, 0x36U, 0x38U};
    constexpr std::array<std::uint32_t, 4> modifierKeysyms{
        0xffe3U, 0xffe1U, 0xffe2U, 0xffe9U};
    event.keyboardFlags = 0U;
    for (std::size_t index = 0; index < modifiers.size(); ++index)
    {
        event.keyCode = modifiers[index];
        translated = translateRdpSlowPathX11Input(event, geometry);
        assert(translated && std::get<X11KeyInput>(*translated).keySymbol ==
                                 modifierKeysyms[index]);
    }

    event.keyboardFlags = 0x0100U;
    for (const auto &[scanCode, keysym] :
         std::array<std::pair<std::uint16_t, std::uint32_t>, 5>{{
             {0x1dU, 0xffe4U}, {0x38U, 0xffeaU}, {0x48U, 0xff52U},
             {0x1cU, 0xff8dU}, {0x5bU, 0xffebU}}})
    {
        event.keyCode = scanCode;
        translated = translateRdpSlowPathX11Input(event, geometry);
        assert(translated && std::get<X11KeyInput>(*translated).keySymbol ==
                                 keysym);
        assert(std::get<X11KeyInput>(*translated).extended);
    }

    for (const std::uint16_t unsupportedFlags : {
         std::uint16_t{0x0200U}, std::uint16_t{0x0300U},
         std::uint16_t{0x0001U}, std::uint16_t{0x2000U}})
    {
        event.keyCode = 0x1dU;
        event.keyboardFlags = unsupportedFlags;
        assert(!translateRdpSlowPathX11Input(event, geometry));
    }
    event.keyboardFlags = 0U;
    for (const std::uint16_t unknownCode : {
         std::uint16_t{0U}, std::uint16_t{0x54U},
         std::uint16_t{0x56U}, std::uint16_t{0x59U},
         std::uint16_t{0x7fU}, std::uint16_t{0xe0U},
         std::uint16_t{0xffU}})
    {
        event.keyCode = unknownCode;
        assert(!translateRdpSlowPathX11Input(event, geometry));
    }
    event.keyboardFlags = 0x0100U;
    event.keyCode = 0x1eU; // Undefined E0-A combination
    assert(!translateRdpSlowPathX11Input(event, geometry));
    event.keyboardFlags = 0U;
    assert(!translateRdpSlowPathX11Input(event, {0U, 720U}));
    assert(!translateRdpSlowPathX11Input(event, {1280U, 0U}));

    event.kind = RdpSlowPathInputEventKind::UnicodeKeyboard;
    assert(!translateRdpSlowPathX11Input(event, geometry));
    event.kind = RdpSlowPathInputEventKind::RelativeMouse;
    assert(!translateRdpSlowPathX11Input(event, geometry));
}
