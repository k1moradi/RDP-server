// SPDX-License-Identifier: GPL-3.0-or-later
// Pure R3 decoded-event to R5 native scroll translation. No X11/XTEST,
// credentials, sessions, service or authorization are constructed.
#include "x11/x11_rdp_slow_path_input.h"

#include <cassert>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <variant>

using rdp_server::server::transport::RdpSlowPathInputEvent;
using rdp_server::server::transport::RdpSlowPathInputEventKind;

namespace
{
void expectWheel(std::uint16_t flags, std::int32_t expectedRotation,
                 X11ScrollAxis expectedAxis) noexcept
{
    RdpSlowPathInputEvent event{};
    event.kind = RdpSlowPathInputEventKind::Mouse;
    event.pointerFlags = flags;
    // Microsoft requires wheel-coordinate fields to be ignored. Neither
    // the translator nor XTEST button injection should move the pointer.
    event.xPos = std::numeric_limits<std::uint16_t>::max();
    event.yPos = std::numeric_limits<std::uint16_t>::max();

    const auto result = translateRdpSlowPathX11Input(event, {1280U, 720U});
    assert(result && std::holds_alternative<X11ScrollInput>(*result));
    const auto scroll = std::get<X11ScrollInput>(*result);
    assert(scroll.delta == expectedRotation);
    assert(scroll.axis == expectedAxis);
    assert(scroll.x == 0 && scroll.y == 0);
}

void testWheelSignExtensionAndAxis() noexcept
{
    constexpr auto v = X11ScrollAxis::Vertical;
    constexpr auto h = X11ScrollAxis::Horizontal;
    // WHEEL_NEGATIVE occupies bit 8 of a signed 9-bit rotation. +120 is
    // 0x078; -120 is 0x188 and must be sign-extended to -120.
    expectWheel(0x0278U, 120, v);
    expectWheel(0x0388U, -120, v);
    expectWheel(0x0478U, 120, h);
    expectWheel(0x0588U, -120, h);
    expectWheel(0x02ffU, 255, v);
    expectWheel(0x0300U, -256, v);
    expectWheel(0x0200U, 0, v);
    // The normative vertical-precedence rule wins if both axis bits are set.
    expectWheel(0x0678U, 120, v);
    expectWheel(0x0788U, -120, v);
    // Other flags on a wheel event are ignored rather than turning wheel
    // motion into pointer movement, a button down or a native denial.
    expectWheel(0xfa78U, 120, v);
    expectWheel(0xfc78U, 120, h);
    expectWheel(0xfe78U, 120, v);
}

void testWheelDenials() noexcept
{
    RdpSlowPathInputEvent event{};
    event.kind = RdpSlowPathInputEventKind::Mouse;
    event.pointerFlags = 0x0278U;
    assert(!translateRdpSlowPathX11Input(event, {0U, 720U}));
    assert(!translateRdpSlowPathX11Input(event, {1280U, 0U}));

    // The sign bit alone without WHEEL/HWHEEL is not a valid wheel event.
    for (const auto flags : {std::uint16_t{0x0100U},
                             std::uint16_t{0x0188U},
                             std::uint16_t{0x0001U}})
    {
        event.pointerFlags = flags;
        assert(!translateRdpSlowPathX11Input(event, {1280U, 720U}));
    }
}
} // namespace

int main()
{
    testWheelSignExtensionAndAxis();
    testWheelDenials();
    return 0;
}
