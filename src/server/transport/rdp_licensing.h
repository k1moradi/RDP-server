// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{

// MS-RDPBCGR 2.2.1.12.1.1 LICENSE_PREAMBLE uses a 16-bit total length.
// This first-party parser never allocates from peer-controlled lengths.
inline constexpr std::size_t kMaximumRdpLicensingPduBytes = 65535U;

enum class RdpLicensingMessageType : std::uint8_t
{
    ServerLicenseRequest = 0x01,
    ServerPlatformChallenge = 0x02,
    ServerNewLicense = 0x03,
    ServerUpgradeLicense = 0x04,
    ClientLicenseInfo = 0x12,
    ClientNewLicenseRequest = 0x13,
    ClientPlatformChallengeResponse = 0x15,
    ErrorAlert = 0xff,
};

enum class RdpLicensingParseError : std::uint8_t
{
    None,
    Truncated,
    Oversized,
    LengthMismatch,
    InvalidType,
    InvalidFlags,
};

struct RdpLicensingMessageView
{
    RdpLicensingMessageType type{RdpLicensingMessageType::ErrorAlert};
    std::uint8_t protocolVersion{};
    bool extendedErrorSupported{};
    // Borrowed from the caller's immutable completeMessage. The span remains
    // valid only while that input storage is alive and unchanged; the parser
    // and lifecycle never retain it beyond the current call.
    std::span<const std::uint8_t> body{};
};

struct RdpLicensingParseResult
{
    RdpLicensingMessageView value{};
    RdpLicensingParseError error{RdpLicensingParseError::Truncated};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpLicensingParseError::None;
    }
};

// Parse exactly one already-isolated licensing PDU. Upstream R3 still must
// prove R2 admission, session generation, assigned MCS user/global channel,
// complete segmentation/reassembly, licensing phase and client direction.
// A successful parse never authenticates, licenses or activates a session.
[[nodiscard]] RdpLicensingParseResult parseRdpLicensingMessage(
    std::span<const std::uint8_t> completeMessage) noexcept;

enum class RdpLicensingPhase : std::uint8_t
{
    NotStarted,
    AwaitClientLicenseResponse,
    AwaitServerDecision,
    Failed,
    Closed,
};

enum class RdpLicensingIntake : std::uint8_t
{
    ClientLicenseInfoAccepted,
    ClientNewLicenseRequestAccepted,
    MalformedMessage,
    UnexpectedMessage,
    Failed,
    Closed,
};

// Stateful licensing phase owned by the sole R3 session. This component has
// no socket, SSL, thread, event loop, identity or authorization capability.
// Serialized event-loop use only. The initial transition means that a future
// authorized owner has fully delivered its Server License Request; encoding or
// queueing such a packet is not delivery. No transition to licensed/completed
// exists in this increment: accepted client syntax stops at AwaitServerDecision.
class RdpLicensingLifecycle final
{
public:
    RdpLicensingLifecycle() noexcept = default;
    RdpLicensingLifecycle(const RdpLicensingLifecycle &) = delete;
    RdpLicensingLifecycle &operator=(const RdpLicensingLifecycle &) = delete;
    RdpLicensingLifecycle(RdpLicensingLifecycle &&) = delete;
    RdpLicensingLifecycle &operator=(RdpLicensingLifecycle &&) = delete;

    [[nodiscard]] RdpLicensingPhase phase() const noexcept { return phase_; }

    // Call only after the one outbound writer reports full plaintext progress
    // for the Server License Request belonging to this session generation.
    // Wrong-order calls are terminal to prevent a stale completion advancing a
    // different licensing exchange.
    [[nodiscard]] bool onServerLicenseRequestWritten() noexcept;

    // Accept exactly one complete client licensing message in the initial
    // response state. CLIENT_LICENSE_INFO and CLIENT_NEW_LICENSE_REQUEST are
    // structurally validated according to MS-RDPELE 2.2.2.3 and 2.2.2.2.
    // Cryptographic license validation/key derivation is deliberately not yet
    // performed, so success never means that licensing has completed.
    [[nodiscard]] RdpLicensingIntake onClientMessage(
        std::span<const std::uint8_t> completeMessage) noexcept;

    // Terminal for this object. Reconnect requires a fresh owning R3 session
    // and therefore a fresh RdpLicensingLifecycle instance.
    void close() noexcept { phase_ = RdpLicensingPhase::Closed; }

private:
    void fail() noexcept { phase_ = RdpLicensingPhase::Failed; }

    RdpLicensingPhase phase_{RdpLicensingPhase::NotStarted};
};

} // namespace rdp_server::server::transport
