// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/transport/lan_listener.h"

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#if !defined(_WIN32)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
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
    assert(missing.listener.generation() == 0U);
    auto zeroPort = openLanListener({"eth0", "192.168.1.5", 0});
    assert(zeroPort.error == LanListenerError::InvalidSelection);
    assert(lanListenerErrorMessage(LanListenerError::InterfaceUnavailable) ==
           "Selected local interface unavailable");
    assert(lanListenerErrorMessage(LanListenerError::PortOccupied) ==
           "Requested LAN port is occupied");
    assert(lanListenerErrorMessage(LanListenerError::PermissionDenied) ==
           "Permission denied while opening LAN listener");
    assert(lanListenerErrorMessage(LanListenerError::CertificateMismatch) ==
           "TLS identity does not match the selected LAN endpoint");
    assert(lanListenerErrorMessage(LanListenerError::ListenerNotReady) ==
           "LAN listener is not ready");
    assert(lanListenerErrorMessage(LanListenerError::TerminalDisconnect) ==
           "LAN transport disconnected");
    assert(lanListenerErrorMessage(static_cast<LanListenerError>(255U)) ==
           "LAN listener failed");

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
            assert(listener.listener.interfaceName() == name);
            assert(listener.listener.interfaceIndex() == ::if_nametoindex(name.c_str()));
            assert(listener.listener.generation() != 0U);
            assert(listener.listener.interfaceStillMatches());
            auto occupied = openLanListener({name, address, port});
            assert(occupied.error == LanListenerError::PortOccupied);
            assert(occupied.listener.generation() == 0U);
            // The existing production acceptor must accept nothing when
            // there are no queued connections.
            auto empty = acceptNonblockingTcpConnection(listener.listener.nativeSocket());
            assert(empty.outcome == TcpAcceptOutcome::WouldBlock);
            // Native positive path: the SAME listening socket is borrowed by
            // R1's existing acceptor; TCP peer metadata is never OS admission.
            const int client = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            assert(client >= 0);
            assert(::connect(client, reinterpret_cast<const sockaddr *>(&endpoint),
                             sizeof(endpoint)) == 0);

            // connect() completion does not guarantee that a nonblocking
            // listener is already readable on every kernel/scheduler. Wait
            // for the real descriptor rather than weakening production
            // nonblocking accept semantics.
            pollfd ready{};
            ready.fd = static_cast<int>(listener.listener.nativeSocket());
            ready.events = POLLIN;
            int pollResult = -1;
            do {
                pollResult = ::poll(&ready, 1, 1000);
            } while (pollResult < 0 && errno == EINTR);
            assert(pollResult == 1);
            assert((ready.revents & POLLIN) != 0);

            auto accepted = acceptNonblockingTcpConnection(
                listener.listener.nativeSocket());
            assert(accepted.outcome == TcpAcceptOutcome::Accepted);
            assert(accepted.connection.valid());
            assert(accepted.connection.peerEndpoint().valid());
            assert(accepted.connection.peerEndpoint().family == TcpPeerAddressFamily::Ipv4);
            accepted.connection.close();
            ::close(client);
            listener.listener.close();
            assert(listener.listener.generation() == 0U);
            assert(!listener.listener.interfaceStillMatches());
        } else {
            assert(listener.error == LanListenerError::PortOccupied ||
                   listener.error == LanListenerError::InterfaceUnavailable);
        }
    }

    // Exercise the production IPv6 bind/getsockname/scope path when this
    // machine genuinely owns an eligible ULA or link-local address. Do not
    // invent an address or interface merely to make the positive case pass.
    assert(::getifaddrs(&interfaces) == 0);
    name.clear();
    address.clear();
    std::uint32_t selectedScope = 0U;
    for (auto *entry = interfaces; entry; entry = entry->ifa_next) {
        if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET6 ||
            (entry->ifa_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING) ||
            (entry->ifa_flags & IFF_LOOPBACK)) continue;
        const auto &native = *reinterpret_cast<const sockaddr_in6 *>(entry->ifa_addr);
        const auto *bytes = native.sin6_addr.s6_addr;
        const bool eligible = (bytes[0] & 0xfeU) == 0xfcU ||
            (bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0x80U);
        if (!eligible) continue;
        char numeric[INET6_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET6, &native.sin6_addr, numeric, sizeof(numeric))) {
            name = entry->ifa_name;
            address = numeric;
            selectedScope = ::if_nametoindex(name.c_str());
            break;
        }
    }
    ::freeifaddrs(interfaces);
    interfaces = nullptr;
    if (!address.empty()) {
        const int probe = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        assert(probe >= 0);
        int ipv6Only = 1;
        assert(::setsockopt(probe, IPPROTO_IPV6, IPV6_V6ONLY,
                            &ipv6Only, sizeof(ipv6Only)) == 0);
        sockaddr_in6 endpoint{};
        endpoint.sin6_family = AF_INET6;
        endpoint.sin6_scope_id = selectedScope;
        assert(::inet_pton(AF_INET6, address.c_str(), &endpoint.sin6_addr) == 1);
        assert(::bind(probe, reinterpret_cast<const sockaddr *>(&endpoint),
                      sizeof(endpoint)) == 0);
        socklen_t bytes = sizeof(endpoint);
        assert(::getsockname(probe, reinterpret_cast<sockaddr *>(&endpoint), &bytes) == 0);
        const auto port = ntohs(endpoint.sin6_port);
        ::close(probe);

        auto listener = openLanListener({name, address, port});
        if (listener.error == LanListenerError::None) {
            assert(listener.listener.valid());
            assert(listener.listener.interfaceName() == name);
            assert(listener.listener.interfaceIndex() == selectedScope);
            assert(listener.listener.generation() != 0U);
            const auto bound = listener.listener.boundEndpoint();
            assert(bound.family == TcpPeerAddressFamily::Ipv6);
            assert(bound.port == port);
            if (address.rfind("fe", 0) == 0 || address.rfind("FE", 0) == 0)
                assert(bound.ipv6ScopeId == selectedScope);
            assert(listener.listener.interfaceStillMatches());
        } else {
            assert(listener.error == LanListenerError::PortOccupied ||
                   listener.error == LanListenerError::InterfaceUnavailable);
        }
    }
#endif
}
