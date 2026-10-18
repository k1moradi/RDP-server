// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/transport/lan_listener.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

using namespace rdp_server::server::transport;
int main() {
    // Fail closed before native socket creation: never wildcard, public,
    // loopback or implicitly choose a network interface.
    for (const char *address : {"0.0.0.0", "::", "8.8.8.8", "2001:4860:4860::8888",
                                "127.0.0.1", "::1", "169.254.1.1"}) {
        auto result = openLanListener({"not-an-interface", address, 3389});
        assert(result.error == LanListenerError::InvalidSelection);
        assert(!result.listener.valid());
    }
    auto missing = openLanListener({"rdp-definitely-missing", "192.168.1.5", 3389});
    assert(missing.error == LanListenerError::InterfaceUnavailable);
    assert(!missing.listener.valid());
    auto zeroPort = openLanListener({"eth0", "192.168.1.5", 0});
    assert(zeroPort.error == LanListenerError::InvalidSelection);

#if !defined(_WIN32)
    // Discover a real UP, non-loopback RFC1918 address, if present in the
    // isolated runner. No synthetic interface or OS admission is fabricated.
    ifaddrs *interfaces = nullptr;
    assert(::getifaddrs(&interfaces) == 0);
    std::string name;
    std::string address;
    for (auto *entry = interfaces; entry; entry = entry->ifa_next) {
        if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET ||
            (entry->ifa_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING) ||
            (entry->ifa_flags & IFF_LOOPBACK)) continue;
        char numeric[INET_ADDRSTRLEN]{};
        const auto &native = *reinterpret_cast<const sockaddr_in *>(entry->ifa_addr);
        const auto value = ntohl(native.sin_addr.s_addr);
        if (!((value & 0xff000000U) == 0x0a000000U ||
              (value & 0xfff00000U) == 0xac100000U ||
              (value & 0xffff0000U) == 0xc0a80000U)) continue;
        if (::inet_ntop(AF_INET, &native.sin_addr, numeric, sizeof(numeric))) {
            name = entry->ifa_name;
            address = numeric;
            break;
        }
    }
    ::freeifaddrs(interfaces);
    if (!address.empty()) {
        // Obtain an ephemeral unused port from the same address without
        // advertising a service. Race remains possible; if acquired by a
        // different process, production correctly reports PortOccupied.
        const int probe = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        assert(probe >= 0);
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        assert(::inet_pton(AF_INET, address.c_str(), &endpoint.sin_addr) == 1);
        assert(::bind(probe, reinterpret_cast<const sockaddr *>(&endpoint),
                      sizeof(endpoint)) == 0);
        socklen_t bytes = sizeof(endpoint);
        assert(::getsockname(probe, reinterpret_cast<sockaddr *>(&endpoint), &bytes) == 0);
        const auto port = ntohs(endpoint.sin_port);
        ::close(probe);
        auto listener = openLanListener({name, address, port});
        if (listener.error == LanListenerError::None) {
            assert(listener.listener.valid());
            assert(listener.listener.boundEndpoint().port == port);
            assert(listener.listener.interfaceStillMatches());
            auto occupied = openLanListener({name, address, port});
            assert(occupied.error == LanListenerError::PortOccupied);
            // The existing production acceptor must accept nothing when
            // there are no queued connections.
            auto empty = acceptNonblockingTcpConnection(listener.listener.nativeSocket());
            assert(empty.outcome == TcpAcceptOutcome::WouldBlock);
            listener.listener.close();
            assert(!listener.listener.interfaceStillMatches());
        } else {
            assert(listener.error == LanListenerError::PortOccupied ||
                   listener.error == LanListenerError::InterfaceUnavailable);
        }
    }
#endif
}
