// SPDX-License-Identifier: GPL-3.0-or-later
#include <transport/tpkt_x224.h>

#include <array>
#include <cstdint>

int main()
{
    // Verify that an installed consumer compiles, links the real library,
    // and invokes a published C++23 protocol API. No network services.
    constexpr std::array<std::uint8_t, 11> legacyRequest{
        3, 0, 0, 11, 6, 0xe0, 0, 0, 0, 0, 0};
    const auto result =
        rdp_server::server::transport::parseConnectionRequest(legacyRequest);
    return result && !result.request.hasNegotiation ? 0 : 1;
}
