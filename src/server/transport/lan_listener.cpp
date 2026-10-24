// SPDX-License-Identifier: GPL-3.0-or-later
#include "lan_listener.h"

#include <algorithm>
#include <atomic>
#include <array>
#include <cstring>
#include <limits>
#include <string>
#include <utility>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace rdp_server::server::transport {
namespace {
#if defined(_WIN32)
using NativeSocket = SOCKET;
constexpr NativeSocket invalidSocket = INVALID_SOCKET;
void closeSocket(NativeSocket socket) noexcept { ::closesocket(socket); }
#else
using NativeSocket = int;
constexpr NativeSocket invalidSocket = -1;
void closeSocket(NativeSocket socket) noexcept { ::close(socket); }
#endif

std::atomic<std::uint64_t> nextListenerGeneration{1U};
// Header inclusion may expose the Windows max macro before this .cpp can set
// NOMINMAX. Parenthesize the function name so this constant stays macro-proof.
constexpr std::uint64_t maximumListenerGeneration =
    (std::numeric_limits<std::uint64_t>::max)();

[[nodiscard]] std::uint64_t allocateListenerGeneration() noexcept
{
    std::uint64_t candidate =
        nextListenerGeneration.load(std::memory_order_relaxed);
    while (candidate != 0U &&
           candidate != maximumListenerGeneration)
    {
        const std::uint64_t replacement = candidate + 1U;
        if (nextListenerGeneration.compare_exchange_weak(
                candidate, replacement, std::memory_order_relaxed,
                std::memory_order_relaxed))
            return candidate;
    }
    return 0U;
}

// Restrict LAN opt-in to non-loopback, non-multicast, non-unspecified,
// non-public addresses. This is exposure policy, not peer trust.
bool allowedAddress(const sockaddr_storage &storage) noexcept {
    if (storage.ss_family == AF_INET) {
        const auto *address = reinterpret_cast<const sockaddr_in *>(&storage);
        const std::uint32_t value = ntohl(address->sin_addr.s_addr);
        return (value & 0xff000000U) == 0x0a000000U ||
               (value & 0xfff00000U) == 0xac100000U ||
               (value & 0xffff0000U) == 0xc0a80000U;
    }
    if (storage.ss_family == AF_INET6) {
        const auto *address = reinterpret_cast<const sockaddr_in6 *>(&storage);
        const auto *bytes = address->sin6_addr.s6_addr;
        // ULA and link-local only. IPv4-mapped addresses are refused.
        return (bytes[0] & 0xfeU) == 0xfcU ||
               (bytes[0] == 0xfeU && (bytes[1] & 0xc0U) == 0x80U);
    }
    return false;
}

struct NativeSelection {
    sockaddr_storage address{};
    socklen_t length{};
    std::uint32_t interfaceIndex{};
};

bool findInterfaceAddress(std::string_view name,
                          const sockaddr_storage &wanted,
                          NativeSelection &selected) noexcept {
#if defined(_WIN32)
    // AdapterName is the stable adapter identifier; friendly display names
    // must be resolved by R10 before this call.
    alignas(IP_ADAPTER_ADDRESSES) std::array<unsigned char, 16384> buffer{};
    ULONG bytes = static_cast<ULONG>(buffer.size());
    if (::GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST |
            GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()),
            &bytes) != NO_ERROR) return false;
    const auto *adapter = reinterpret_cast<const IP_ADAPTER_ADDRESSES *>(buffer.data());
    for (; adapter != nullptr; adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp ||
            adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
            name != adapter->AdapterName) continue;
        const ULONG index = wanted.ss_family == AF_INET6 ?
            adapter->Ipv6IfIndex : adapter->IfIndex;
        if (index == 0) continue;
        for (auto *entry = adapter->FirstUnicastAddress; entry; entry = entry->Next) {
            const auto *address = entry->Address.lpSockaddr;
            if (!address || address->sa_family != wanted.ss_family) continue;
            const std::size_t length = wanted.ss_family == AF_INET ?
                sizeof(sockaddr_in) : sizeof(sockaddr_in6);
            const auto *left = wanted.ss_family == AF_INET ?
                reinterpret_cast<const void *>(&reinterpret_cast<const sockaddr_in *>(address)->sin_addr) :
                reinterpret_cast<const void *>(&reinterpret_cast<const sockaddr_in6 *>(address)->sin6_addr);
            const auto *right = wanted.ss_family == AF_INET ?
                reinterpret_cast<const void *>(&reinterpret_cast<const sockaddr_in *>(&wanted)->sin_addr) :
                reinterpret_cast<const void *>(&reinterpret_cast<const sockaddr_in6 *>(&wanted)->sin6_addr);
            const auto size = wanted.ss_family == AF_INET ? sizeof(in_addr) : sizeof(in6_addr);
            if (std::memcmp(left, right, size) != 0) continue;
            std::memcpy(&selected.address, address, length);
            selected.length = static_cast<socklen_t>(length);
            selected.interfaceIndex = index;
            return true;
        }
    }
#else
    ifaddrs *addresses = nullptr;
    if (::getifaddrs(&addresses) != 0) return false;
    // The public API bounds the name; avoid allocation in a noexcept path.
    if (name.empty() || name.size() >= 128U) {
        ::freeifaddrs(addresses);
        return false;
    }
    std::array<char, 128> nativeName{};
    std::memcpy(nativeName.data(), name.data(), name.size());
    const unsigned int index = ::if_nametoindex(nativeName.data());
    for (auto *entry = addresses; entry; entry = entry->ifa_next) {
        if (!entry->ifa_addr || name != entry->ifa_name ||
            (entry->ifa_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING) ||
            (entry->ifa_flags & IFF_LOOPBACK) != 0 ||
            entry->ifa_addr->sa_family != wanted.ss_family) continue;
        const std::size_t length = wanted.ss_family == AF_INET ?
            sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        const auto *left = wanted.ss_family == AF_INET ?
            reinterpret_cast<const void *>(&reinterpret_cast<const sockaddr_in *>(entry->ifa_addr)->sin_addr) :
            reinterpret_cast<const void *>(&reinterpret_cast<const sockaddr_in6 *>(entry->ifa_addr)->sin6_addr);
        const auto *right = wanted.ss_family == AF_INET ?
            reinterpret_cast<const void *>(&reinterpret_cast<const sockaddr_in *>(&wanted)->sin_addr) :
            reinterpret_cast<const void *>(&reinterpret_cast<const sockaddr_in6 *>(&wanted)->sin6_addr);
        const auto size = wanted.ss_family == AF_INET ? sizeof(in_addr) : sizeof(in6_addr);
        if (index == 0 || std::memcmp(left, right, size) != 0) continue;
        std::memcpy(&selected.address, entry->ifa_addr, length);
        selected.length = static_cast<socklen_t>(length);
        selected.interfaceIndex = index;
        break;
    }
    ::freeifaddrs(addresses);
    return selected.interfaceIndex != 0;
#endif
    return false;
}

LanListenerError socketFailure() noexcept {
#if defined(_WIN32)
    const int error = ::WSAGetLastError();
    if (error == WSAEADDRINUSE || error == WSAEACCES)
        return error == WSAEADDRINUSE ? LanListenerError::PortOccupied : LanListenerError::PermissionDenied;
#else
    if (errno == EADDRINUSE) return LanListenerError::PortOccupied;
    if (errno == EACCES || errno == EPERM) return LanListenerError::PermissionDenied;
#endif
    return LanListenerError::ListenerNotReady;
}
} // namespace

OwnedLanListener::OwnedLanListener(OwnedLanListener &&other) noexcept {
    *this = std::move(other);
}
OwnedLanListener &OwnedLanListener::operator=(OwnedLanListener &&other) noexcept {
    if (this != &other) {
        close();
        socket_ = std::exchange(other.socket_, OwnedNativeTcpSocket::kInvalidSocket);
        endpoint_ = std::exchange(other.endpoint_, TcpPeerEndpoint{});
        std::memcpy(interfaceName_, other.interfaceName_, sizeof(interfaceName_));
        interfaceIndex_ = std::exchange(other.interfaceIndex_, 0);
        generation_ = std::exchange(other.generation_, 0U);
    }
    return *this;
}
OwnedLanListener::~OwnedLanListener() { close(); }
void OwnedLanListener::close() noexcept {
    if (valid()) {
        closeSocket(static_cast<NativeSocket>(socket_));
        socket_ = OwnedNativeTcpSocket::kInvalidSocket;
    }
    endpoint_ = {};
    interfaceIndex_ = 0;
    generation_ = 0U;
}
bool OwnedLanListener::interfaceStillMatches() const noexcept {
    if (!valid() || interfaceIndex_ == 0) return false;
    sockaddr_storage address{};
    if (endpoint_.family == TcpPeerAddressFamily::Ipv4) {
        auto &v4 = reinterpret_cast<sockaddr_in &>(address);
        v4.sin_family = AF_INET;
        std::memcpy(&v4.sin_addr, endpoint_.address.data(), sizeof(in_addr));
    } else if (endpoint_.family == TcpPeerAddressFamily::Ipv6) {
        auto &v6 = reinterpret_cast<sockaddr_in6 &>(address);
        v6.sin6_family = AF_INET6;
        std::memcpy(&v6.sin6_addr, endpoint_.address.data(), sizeof(in6_addr));
    } else return false;
    NativeSelection selection{};
    return findInterfaceAddress(interfaceName_, address, selection) &&
           selection.interfaceIndex == interfaceIndex_;
}

LanListenerResult openLanListener(LanListenerRequest request) noexcept {
    LanListenerResult result{};
    if (request.interfaceName.empty() || request.interfaceName.size() >= 128 ||
        request.numericAddress.empty() || request.numericAddress.size() > 64 ||
        request.port == 0 || request.interfaceName.find('\0') != std::string_view::npos ||
        request.numericAddress.find('\0') != std::string_view::npos) {
        result.error = LanListenerError::InvalidSelection;
        return result;
    }
    // A bounded, NUL-terminated numeric literal; no DNS or heap allocation.
    std::array<char, 65> numericAddress{};
    std::memcpy(numericAddress.data(), request.numericAddress.data(),
                request.numericAddress.size());
    sockaddr_storage wanted{};
    auto &v4 = reinterpret_cast<sockaddr_in &>(wanted);
    auto &v6 = reinterpret_cast<sockaddr_in6 &>(wanted);
    if (::inet_pton(AF_INET, numericAddress.data(), &v4.sin_addr) == 1)
        wanted.ss_family = AF_INET;
    else if (::inet_pton(AF_INET6, numericAddress.data(), &v6.sin6_addr) == 1)
        wanted.ss_family = AF_INET6;
    else {
        result.error = LanListenerError::InvalidSelection;
        return result;
    }
    if (!allowedAddress(wanted)) {
        result.error = LanListenerError::InvalidSelection;
        return result;
    }
    NativeSelection selection{};
    if (!findInterfaceAddress(request.interfaceName, wanted, selection)) {
        result.error = LanListenerError::InterfaceUnavailable;
        return result;
    }
    if (wanted.ss_family == AF_INET) {
        reinterpret_cast<sockaddr_in &>(selection.address).sin_port = htons(request.port);
    } else {
        auto &address = reinterpret_cast<sockaddr_in6 &>(selection.address);
        address.sin6_port = htons(request.port);
        // Link-local requires interface scope. ULA must not inherit a stale scope.
        address.sin6_scope_id = (address.sin6_addr.s6_addr[0] == 0xfeU &&
            (address.sin6_addr.s6_addr[1] & 0xc0U) == 0x80U) ?
            selection.interfaceIndex : 0;
    }
    const NativeSocket socket = ::socket(wanted.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (socket == invalidSocket) {
        result.error = socketFailure();
        return result;
    }
    const auto fail = [&](LanListenerError error) noexcept {
        closeSocket(socket);
        result.error = error;
        return std::move(result);
    };
    if (wanted.ss_family == AF_INET6) {
        int ipv6Only = 1;
        if (::setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY,
#if defined(_WIN32)
            reinterpret_cast<const char *>(&ipv6Only),
#else
            &ipv6Only,
#endif
            sizeof(ipv6Only)) != 0) return fail(socketFailure());
    }
#if defined(_WIN32)
    BOOL exclusive = TRUE;
    if (::setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char *>(&exclusive), sizeof(exclusive)) != 0)
        return fail(socketFailure());
    u_long nonblocking = 1;
    if (::ioctlsocket(socket, FIONBIO, &nonblocking) != 0)
        return fail(socketFailure());
    if (!::SetHandleInformation(reinterpret_cast<HANDLE>(socket), HANDLE_FLAG_INHERIT, 0))
        return fail(LanListenerError::ListenerNotReady);
#else
    // Allow a stopped server to reclaim its exact configured endpoint when a
    // process-owned accepted connection is still in TCP TIME_WAIT after an
    // active close. This is deliberately SO_REUSEADDR, never SO_REUSEPORT:
    // the existing exact-address live-listener collision must still fail.
    int reuseAddress = 1;
    if (::setsockopt(
            socket, SOL_SOCKET, SO_REUSEADDR,
            &reuseAddress, sizeof(reuseAddress)) != 0)
        return fail(socketFailure());

    int flags = ::fcntl(socket, F_GETFL, 0);
    if (flags < 0 || ::fcntl(socket, F_SETFL, flags | O_NONBLOCK) != 0 ||
        ::fcntl(socket, F_SETFD, FD_CLOEXEC) != 0)
        return fail(socketFailure());
#endif
    if (::bind(socket, reinterpret_cast<const sockaddr *>(&selection.address),
               selection.length) != 0) return fail(socketFailure());
    if (::listen(socket, SOMAXCONN) != 0) return fail(socketFailure());
    sockaddr_storage bound{};
    socklen_t boundBytes = sizeof(bound);
    if (::getsockname(socket, reinterpret_cast<sockaddr *>(&bound),
                      &boundBytes) != 0 || bound.ss_family != wanted.ss_family)
        return fail(LanListenerError::ListenerNotReady);
    TcpPeerEndpoint endpoint{};
    endpoint.family = wanted.ss_family == AF_INET ?
        TcpPeerAddressFamily::Ipv4 : TcpPeerAddressFamily::Ipv6;
    endpoint.port = request.port;
    if (wanted.ss_family == AF_INET) {
        const auto &address = reinterpret_cast<const sockaddr_in &>(bound);
        if (ntohs(address.sin_port) != request.port ||
            std::memcmp(&address.sin_addr, &v4.sin_addr, sizeof(in_addr)) != 0)
            return fail(LanListenerError::ListenerNotReady);
        std::memcpy(endpoint.address.data(), &address.sin_addr, sizeof(in_addr));
    } else {
        const auto &address = reinterpret_cast<const sockaddr_in6 &>(bound);
        if (ntohs(address.sin6_port) != request.port ||
            std::memcmp(&address.sin6_addr, &v6.sin6_addr, sizeof(in6_addr)) != 0)
            return fail(LanListenerError::ListenerNotReady);
        std::memcpy(endpoint.address.data(), &address.sin6_addr, sizeof(in6_addr));
        endpoint.ipv6ScopeId = address.sin6_scope_id;
    }
    result.listener.socket_ = static_cast<std::uintptr_t>(socket);
    result.listener.endpoint_ = endpoint;
    std::memcpy(result.listener.interfaceName_, request.interfaceName.data(),
                request.interfaceName.size());
    result.listener.interfaceName_[request.interfaceName.size()] = '\0';
    result.listener.interfaceIndex_ = selection.interfaceIndex;
    if (!result.listener.interfaceStillMatches()) {
        result.listener.close();
        result.error = LanListenerError::InterfaceUnavailable;
        return result;
    }
    result.listener.generation_ = allocateListenerGeneration();
    if (result.listener.generation_ == 0U) {
        result.listener.close();
        result.error = LanListenerError::ListenerNotReady;
        return result;
    }
    result.error = LanListenerError::None;
    return result;
}
} // namespace rdp_server::server::transport
