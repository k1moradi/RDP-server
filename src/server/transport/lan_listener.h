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

// Fixed redacted text for R7/R10 status surfaces. Never include raw socket,
// peer, TLS, certificate path, interface-address or credential diagnostics.
[[nodiscard]] constexpr std::string_view lanListenerErrorMessage(
    LanListenerError error) noexcept
{
    switch (error) {
    case LanListenerError::None: return "No error";
    case LanListenerError::InvalidSelection: return "Invalid LAN listener selection";
    case LanListenerError::InterfaceUnavailable: return "Selected local interface unavailable";
    case LanListenerError::PermissionDenied: return "Permission denied while opening LAN listener";
    case LanListenerError::PortOccupied: return "Requested LAN port is occupied";
    case LanListenerError::ListenerNotReady: return "LAN listener is not ready";
    case LanListenerError::TerminalDisconnect: return "LAN transport disconnected";
    case LanListenerError::CertificateMismatch: return "TLS identity does not match the selected LAN endpoint";
    }
    return "LAN listener failed";
}

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
    // Exact interface identity R1 validated at bind time. R10 may render this
    // value, but it is descriptive metadata and never an admission capability.
    [[nodiscard]] std::string_view interfaceName() const noexcept
    {
        return valid() ? std::string_view{interfaceName_} : std::string_view{};
    }
    [[nodiscard]] std::uint32_t interfaceIndex() const noexcept
    {
        return valid() ? interfaceIndex_ : 0U;
    }
    // Process-local epoch for one successfully validated bind. This is
    // descriptive lifetime metadata, never R2 admission or peer authority.
    [[nodiscard]] std::uint64_t generation() const noexcept
    {
        return valid() ? generation_ : 0U;
    }
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
    std::uint64_t generation_{};
};
struct LanListenerResult {
    LanListenerError error{LanListenerError::ListenerNotReady};
    OwnedLanListener listener{};
};
[[nodiscard]] LanListenerResult openLanListener(LanListenerRequest request) noexcept;
} // namespace rdp_server::server::transport
