// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
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

// Enhanced-Security SERVER_LICENSE_REQUEST omits the redundant licensing
// certificate, but still requires genuine random and provisioned identity.
// Bound the one owned connection-sequence write independently of peer limits.
inline constexpr std::size_t kMaximumRdpServerLicenseRequestBytes = 2048U;

enum class RdpServerLicenseRequestEncodeError : std::uint8_t
{
    None,
    InvalidRandom,
    InvalidProductInfo,
    InvalidScope,
    Oversized,
    OutputTooSmall,
};

struct RdpServerLicenseRequestFields
{
    // Borrowed only for encode/queue. The caller must establish CSPRNG
    // provenance; structural serialization cannot prove entropy quality.
    std::span<const std::uint8_t> serverRandom{};
    std::uint32_t productVersion{};
    // Complete null-terminated UTF-16LE strings, terminators included.
    std::span<const std::uint8_t> companyNameUtf16{};
    std::span<const std::uint8_t> productIdUtf16{};
    // Complete null-terminated ANSI issuer scope.
    std::span<const std::uint8_t> scopeAnsi{};
};

struct RdpServerLicenseRequestEncodeResult
{
    std::size_t bytesWritten{};
    RdpServerLicenseRequestEncodeError error{
        RdpServerLicenseRequestEncodeError::InvalidRandom};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == RdpServerLicenseRequestEncodeError::None;
    }
};

// MS-RDPELE 2.2.2.1 SERVER_LICENSE_REQUEST for Enhanced RDP Security.
// Allocation-free; output is untouched on failure. The key-exchange BLOB is
// KEY_EXCHANGE_ALG_RSA, the certificate BLOB is empty as permitted when TLS
// protects RDP traffic, and exactly one caller-provisioned scope is emitted.
// This function never invents random bytes, product/scope identity, licensing
// authority, certificate material, or authorization.
[[nodiscard]] RdpServerLicenseRequestEncodeResult
encodeEnhancedSecurityServerLicenseRequest(
    const RdpServerLicenseRequestFields &fields,
    std::span<std::uint8_t> output) noexcept;

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
    friend class RdpServerLicenseRequestWriteGate;

    // Only the receipt gate may advance this transition after every byte of
    // its stable owned SERVER_LICENSE_REQUEST has been accepted.
    [[nodiscard]] bool onServerLicenseRequestWritten() noexcept;
    void fail() noexcept { phase_ = RdpLicensingPhase::Failed; }

    RdpLicensingPhase phase_{RdpLicensingPhase::NotStarted};
};

struct RdpServerLicenseRequestWriteView
{
    std::span<const std::uint8_t> bytes{};
    std::uint64_t replySequence{};
    std::uint64_t writeSliceSequence{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return !bytes.empty() && replySequence != 0U &&
               writeSliceSequence != 0U;
    }
};

enum class RdpServerLicenseRequestWriteOutcome : std::uint8_t
{
    Pending,
    Delivered,
    Rejected,
};

// Single-owner write accounting for one SERVER_LICENSE_REQUEST. Serialized
// event-loop use only. Stable contiguous bytes and two monotonic receipts bind
// every submitted suffix. Zero-byte backpressure preserves the slice; positive
// partial progress rotates only the slice receipt; only full accepted-byte
// delivery advances licensing. Any stale/duplicate receipt, overwrite,
// over-report, abandonment, or lifecycle mismatch closes both objects.
// This proves delivery only, not R2 admission or configuration provenance.
class RdpServerLicenseRequestWriteGate final
{
public:
    explicit RdpServerLicenseRequestWriteGate(
        RdpLicensingLifecycle &lifecycle) noexcept
        : lifecycle_(&lifecycle)
    {
    }
    RdpServerLicenseRequestWriteGate(
        const RdpServerLicenseRequestWriteGate &) = delete;
    RdpServerLicenseRequestWriteGate &operator=(
        const RdpServerLicenseRequestWriteGate &) = delete;
    RdpServerLicenseRequestWriteGate(
        RdpServerLicenseRequestWriteGate &&) = delete;
    RdpServerLicenseRequestWriteGate &operator=(
        RdpServerLicenseRequestWriteGate &&) = delete;

    [[nodiscard]] bool queue(
        const RdpServerLicenseRequestFields &fields) noexcept;
    [[nodiscard]] RdpServerLicenseRequestWriteView
    pendingWrite() const noexcept;
    [[nodiscard]] RdpServerLicenseRequestWriteOutcome onBytesWritten(
        std::uint64_t replySequence,
        std::uint64_t writeSliceSequence,
        std::size_t acceptedBytes) noexcept;
    void close() noexcept;

private:
    [[nodiscard]] bool advanceReplySequence() noexcept;
    [[nodiscard]] bool advanceWriteSliceSequence() noexcept;

    std::array<std::uint8_t, kMaximumRdpServerLicenseRequestBytes> pending_{};
    RdpLicensingLifecycle *lifecycle_{};
    std::size_t pendingLength_{};
    std::size_t bytesWritten_{};
    std::uint64_t replySequence_{};
    std::uint64_t writeSliceSequence_{};
    bool delivered_{};
    bool closed_{};
};

} // namespace rdp_server::server::transport
