// SPDX-License-Identifier: GPL-3.0-or-later
// Pure decoding-to-native translation fixture: no X11, credentials or XTEST.
#include "x11/x11_rdp_slow_path_input.h"
#include "x11/x11_authorized_input_route.h"
#include "server/runtime/linux_runtime_connection.h"
#include "server/runtime/runtime_deployment_policy.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <variant>

using rdp_server::server::transport::RdpSlowPathInputEvent;
using rdp_server::server::transport::RdpSlowPathInputEventKind;
using rdp_server::server::runtime::LinuxRuntimeConnection;
using rdp_server::server::runtime::RuntimeDeploymentPolicy;

static_assert(std::is_invocable_r_v<bool,
    decltype(&X11AuthorizedInputRoute::dispatchAuthenticatedSlowPathTpkt),
    LinuxRuntimeConnection&, const RuntimeDeploymentPolicy&,
    X11DesktopResources&, std::uint64_t,
    std::span<const std::uint8_t>>);

int main()
{
    constexpr PixelSize desktop{1280U, 720U};
    RdpSlowPathInputEvent event{};
    event.kind = RdpSlowPathInputEventKind::Mouse;
    event.xPos = 1279;
    event.yPos = 719;

    event.pointerFlags = 0x0800U; // MS-RDPBCGR PTRFLAGS_MOVE
    auto result = translateRdpSlowPathX11Input(event, desktop);
    assert(result && std::holds_alternative<X11PointerMoveInput>(*result));
    auto motion = std::get<X11PointerMoveInput>(*result);
    assert(motion.x == 1279 && motion.y == 719);

    event.pointerFlags = 0x9000U; // LEFT | DOWN
    result = translateRdpSlowPathX11Input(event, desktop);
    assert(result && std::holds_alternative<X11PointerButtonInput>(*result));
    auto button = std::get<X11PointerButtonInput>(*result);
    assert(button.button == 1 && button.pressed);

    event.pointerFlags = 0x2000U; // RIGHT released
    result = translateRdpSlowPathX11Input(event, desktop);
    button = std::get<X11PointerButtonInput>(*result);
    assert(button.button == 3 && !button.pressed);

    event.pointerFlags = 0xc000U; // MIDDLE | DOWN
    result = translateRdpSlowPathX11Input(event, desktop);
    button = std::get<X11PointerButtonInput>(*result);
    assert(button.button == 2 && button.pressed);

    for (const std::uint16_t invalidFlags : {
         std::uint16_t{0U}, std::uint16_t{0x8000U},
         std::uint16_t{0x3000U}, std::uint16_t{0x1800U},
         std::uint16_t{0x0100U}, std::uint16_t{0x0088U}})
    {
        event.pointerFlags = invalidFlags;
        assert(!translateRdpSlowPathX11Input(event, desktop));
    }

    event.pointerFlags = 0x0800U;
    event.xPos = 1280;
    assert(!translateRdpSlowPathX11Input(event, desktop));
    event.xPos = 12;
    event.yPos = 720;
    assert(!translateRdpSlowPathX11Input(event, desktop));
    event.yPos = 17;
    assert(!translateRdpSlowPathX11Input(event, {0U, 720U}));
    assert(!translateRdpSlowPathX11Input(event, {1280U, 0U}));

    event.kind = RdpSlowPathInputEventKind::Synchronize;
    event.toggleFlags = 0x05U; // caps + scroll, no num
    result = translateRdpSlowPathX11Input(event, desktop);
    assert(result && std::holds_alternative<X11LockStateInput>(*result));
    auto locks = std::get<X11LockStateInput>(*result);
    assert(locks.capsLock && !locks.numLock && locks.scrollLock);
    event.toggleFlags = 0x08U; // Kana unsupported
    assert(!translateRdpSlowPathX11Input(event, desktop));

    for (const auto unsupported : {
        RdpSlowPathInputEventKind::UnicodeKeyboard,
        RdpSlowPathInputEventKind::RelativeMouse,
        RdpSlowPathInputEventKind::Unused})
    {
        event.kind = unsupported;
        assert(!translateRdpSlowPathX11Input(event, desktop));
    }
    // R3's Unused frame kind is a no-op handled inside the authenticated
    // gateway callback, never transformed into an unauthenticated XTEST.
    return 0;
}
