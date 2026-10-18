// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_serve_listener.h"

#include <cassert>
#include <cstdint>
#include <string_view>
#include <type_traits>

using namespace rdp_server::server::runtime;

static_assert(!std::is_copy_constructible_v<LinuxListenerOwner>);
static_assert(!std::is_move_constructible_v<LinuxListenerOwner>);
static_assert(!std::is_copy_assignable_v<LinuxListenerOwner>);
static_assert(!std::is_move_assignable_v<LinuxListenerOwner>);

int main(int argc, char** argv)
{
    if (argc != 2 || argv[1] == nullptr ||
        std::string_view{argv[1]} !=
            "linux-serve-loopback-listener-exact-endpoint-denials")
        return 2;

    // No network socket is created. The pure gate accepts only exact loopback
    // literals and valid ports; it cannot grant R2 admission or open a LAN bind.
    assert(isEligibleLinuxLoopbackListenerEndpoint("127.0.0.1", 3389U));
    assert(isEligibleLinuxLoopbackListenerEndpoint("::1", 3389U));
    assert(isEligibleLinuxLoopbackListenerEndpoint("127.0.0.1", 65535U));
    for (const std::string_view denied : {
             "", "localhost", "127.0.0.2", "0.0.0.0", "::",
             "[::1]", "::ffff:127.0.0.1", "192.168.1.2",
             "fe80::1", "127.0.0.1 ", "127.0.0.1:3389"})
    {
        assert(!isEligibleLinuxLoopbackListenerEndpoint(denied, 3389U));
    }
    assert(!isEligibleLinuxLoopbackListenerEndpoint("127.0.0.1", 0U));
    assert(!isEligibleLinuxLoopbackListenerEndpoint("::1", 0U));

    // Negative descriptor owner does not own/close a network object.
    LinuxListenerOwner noSocket{-1};
    assert(noSocket.descriptor() == -1);
    assert(noSocket.release() == -1);
    assert(noSocket.descriptor() == -1);
    return 0;
}
