// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_serve_listener.h"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

namespace rdp_server::server::runtime
{

LinuxListenerOwner::~LinuxListenerOwner() noexcept
{
    if (descriptor_ >= 0)
        (void)::close(descriptor_);
}

[[nodiscard]] bool hasLinuxServeDescriptorBudget(
    unsigned acceptBudget) noexcept {
    struct rlimit descriptorLimit {};
    if (::getrlimit(RLIMIT_NOFILE, &descriptorLimit) != 0) {
        return false;
    }

    // Keep fixed headroom for stdio, the retained R2 keytab snapshot,
    // listener, accepted connection, logind watcher and TLS/runtime handles.
    constexpr rlim_t kDescriptorReserve = 8U;
    const rlim_t required =
        kDescriptorReserve + static_cast<rlim_t>(acceptBudget);
    return descriptorLimit.rlim_cur == RLIM_INFINITY ||
           descriptorLimit.rlim_cur >= required;
}

[[nodiscard]] int openVerifiedLinuxLoopbackListener(
    std::string_view listenAddress, std::uint16_t listenPort) noexcept {
    if (!isEligibleLinuxLoopbackListenerEndpoint(
            listenAddress, listenPort)) {
        return -1;
    }
    const bool ipv4 = listenAddress == "127.0.0.1";
    const bool ipv6 = !ipv4;

    const int addressFamily = ipv4 ? AF_INET : AF_INET6;
    const int descriptor = ::socket(
        addressFamily, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (descriptor < 0) {
        return -1;
    }

    LinuxListenerOwner failureOwner{descriptor};
    if (ipv6) {
        const int enabled = 1;
        if (::setsockopt(
                descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &enabled,
                sizeof(enabled)) != 0) {
            return -1;
        }
    }

    if (ipv4) {
        struct sockaddr_in requested {};
        requested.sin_family = AF_INET;
        requested.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        requested.sin_port = htons(listenPort);
        if (::bind(
                descriptor, reinterpret_cast<const sockaddr*>(&requested),
                sizeof(requested)) != 0) {
            return -1;
        }
    } else {
        struct sockaddr_in6 requested {};
        requested.sin6_family = AF_INET6;
        requested.sin6_addr = in6addr_loopback;
        requested.sin6_port = htons(listenPort);
        if (::bind(
                descriptor, reinterpret_cast<const sockaddr*>(&requested),
                sizeof(requested)) != 0) {
            return -1;
        }
    }

    if (::listen(descriptor, 1) != 0) {
        return -1;
    }

    int socketType = 0;
    int accepting = 0;
    socklen_t optionLength = sizeof(socketType);
    if (::getsockopt(
            descriptor, SOL_SOCKET, SO_TYPE, &socketType, &optionLength) != 0 ||
        optionLength != sizeof(socketType) || socketType != SOCK_STREAM) {
        return -1;
    }
    optionLength = sizeof(accepting);
    if (::getsockopt(
            descriptor, SOL_SOCKET, SO_ACCEPTCONN, &accepting,
            &optionLength) != 0 ||
        optionLength != sizeof(accepting) || accepting != 1) {
        return -1;
    }

    struct sockaddr_storage actual {};
    socklen_t actualLength = sizeof(actual);
    if (::getsockname(
            descriptor, reinterpret_cast<sockaddr*>(&actual),
            &actualLength) != 0) {
        return -1;
    }

    bool endpointMatches = false;
    if (ipv4 && actual.ss_family == AF_INET &&
        actualLength >= sizeof(sockaddr_in)) {
        const auto* bound =
            reinterpret_cast<const sockaddr_in*>(&actual);
        endpointMatches =
            bound->sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
            ntohs(bound->sin_port) == listenPort;
    } else if (ipv6 && actual.ss_family == AF_INET6 &&
               actualLength >= sizeof(sockaddr_in6)) {
        const auto* bound =
            reinterpret_cast<const sockaddr_in6*>(&actual);
        endpointMatches =
            std::memcmp(
                &bound->sin6_addr, &in6addr_loopback,
                sizeof(in6addr_loopback)) == 0 &&
            bound->sin6_scope_id == 0U &&
            ntohs(bound->sin6_port) == listenPort;
    }
    if (!endpointMatches) {
        return -1;
    }

    // Transfer ownership to the caller only after every socket property and
    // effective bound endpoint has been verified.
    return failureOwner.release();
}


} // namespace rdp_server::server::runtime
