// SPDX-License-Identifier: GPL-3.0-or-later
// Decoded R3 TS_POINTERX_EVENT native translation, without X11/XTEST/admission.
#include "x11/x11_rdp_slow_path_input.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <variant>

int main()
{
    using rdp_server::server::transport::RdpSlowPathInputEvent;
    using rdp_server::server::transport::RdpSlowPathInputEventKind;

    constexpr PixelSize desktop{1280U, 720U};
    RdpSlowPathInputEvent event{};
    event.kind = RdpSlowPathInputEventKind::ExtendedMouse;
    event.xPos = 1279U;
    event.yPos = 719U;

    for (std::uint16_t bits : {std::uint16_t{1U}, std::uint16_t{2U}})
    {
        for (bool pressed : {false, true})
        {
            event.pointerFlags =
                static_cast<std::uint16_t>(bits | (pressed ? 0x8000U : 0U));
            auto result = translateRdpSlowPathX11Input(event, desktop);
            assert(result && std::holds_alternative<X11PointerButtonInput>(*result));
            const auto button = std::get<X11PointerButtonInput>(*result);
            assert(button.button == (bits == 1U ? 8U : 9U));
            assert(button.pressed == pressed);
            assert(button.x == 1279 && button.y == 719);
        }
    }

    // R3 may negotiate only one semantic XBUTTON per event. There is no
    // native MOVE/DOWN-only/ordinary-button/wheel/unknown-flags fallback.
    constexpr std::array<std::uint16_t, 12U> denied{
        0U, 0x8000U, 3U, 0x8003U, 4U, 0x0008U, 0x0101U,
        0x0201U, 0x0402U, 0x0801U, 0x1001U, 0x4002U};
    for (const auto flags : denied)
    {
        event.pointerFlags = flags;
        assert(!translateRdpSlowPathX11Input(event, desktop));
    }

    event.pointerFlags = 0x8001U;
    event.xPos = desktop.widthPixels;
    assert(!translateRdpSlowPathX11Input(event, desktop));
    event.xPos = 100;
    event.yPos = desktop.heightPixels;
    assert(!translateRdpSlowPathX11Input(event, desktop));
    event.yPos = 0U;
    assert(!translateRdpSlowPathX11Input(event, {0U, desktop.heightPixels}));
    assert(!translateRdpSlowPathX11Input(event, {desktop.widthPixels, 0U}));
    return 0;
}
