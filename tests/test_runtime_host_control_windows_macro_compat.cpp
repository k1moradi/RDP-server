// SPDX-License-Identifier: GPL-3.0-or-later
// Reproduce the Win32/RPC legacy macro before the runtime header is parsed.
#define interface struct
#include "server/runtime/runtime_host_control.h"
#undef interface

#include <cassert>
#include <vector>

int main()
{
    const std::vector<rdp_server::server::runtime::RuntimeHostInterface>
        interfaces{};
    const auto recommended =
        rdp_server::server::runtime::recommendRuntimePrivateLanEndpoint(
            interfaces);
    assert(!recommended.valid());
    return 0;
}
