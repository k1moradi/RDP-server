// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "nonblocking_tcp_adapter.h"

#include <cstdint>
#include <string_view>

namespace rdp_server::server::transport
{
// R10 must obtain explicit, current GUI consent before calling this API.
// The selected interface and numeric local address must match a native,
// UP interface. Private address ranges are NOT an authentication boundary.
// Single-event-loop ownership: close before reconfiguring or stopping Share.
enum class LanListenerError : std::uint8_t {
    None, InvalidSelection, InterfaceUnavailable, PermissionDenied,
    PortOccupied, ListenerNotReady, TerminalDisconnect,
    CertificateMismatch
};

struct LanListenerResult;
struct LanListenerRequest {
    std::string_view interfaceName;
    std::string_view numericAddress; // numeric IPv4 or IPv6, no DNS resolution
    std::uint16_t port;              // zero is deliberately forbidden
};

class OwnedLanListener final {
public:
    OwnedLanListener() noexcept = default;
    OwnedLanListener(const OwnedLanListener &) = delete;
    OwnedLanListener &operator=(const OwnedLanListener &) = delete;
    OwnedLanListener(OwnedLanListener &&other) noexcept;
    OwnedLanListener &operator=(OwnedLanListener &&other) noexcept;
    ~OwnedLanListener();
    void close() noexcept;
    [[nodiscard]] bool valid() const noexcept { return socket_ != OwnedNativeTcpSocket::kInvalidSocket; }
    [[nodiscard]] std::uintptr_t nativeSocket() const noexcept { return socket_; }
    [[nodiscard]] TcpPeerEndpoint boundEndpoint() const noexcept { return endpoint_; }
    // Detect address removal/interface down/reassignment. Caller must retire
    // listener and all associated connections on false; no automatic rebind.
    [[nodiscard]] bool interfaceStillMatches() const noexcept;
private:
    friend struct LanListenerResult;
    friend LanListenerResult openLanListener(LanListenerRequest) noexcept;
    std::uintptr_t socket_{OwnedNativeTcpSocket::kInvalidSocket};
    TcpPeerEndpoint endpoint_{};
    char interfaceName_[128]{};
    std::uint32_t interfaceIndex_{};
};
struct LanListenerResult {
    LanListenerError error{LanListenerError::ListenerNotReady};
    OwnedLanListener listener{};
};
[[nodiscard]] LanListenerResult openLanListener(LanListenerRequest request) noexcept;
} // namespace rdp_server::server::transport
