// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "mcs_connect_initial.h"
#include "security_negotiation.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{

// Candidate-only upper limit for the first *decrypted* MCS TPKT, before
// domain/channel allocation. Larger input fails closed before being buffered.
inline constexpr std::size_t kMaximumInitialMcsTpktBytes = 8192;

enum class PreauthStage : std::uint8_t
{
    AwaitConnectionRequest,
    AwaitTls,
    AwaitMcsConnectInitial,
    Closed,
};

// A transport diagnostic, NOT a session authorizer. No method here may
// approve a user, construct a domain, select a desktop or send MCS responses.
// The object stores neither sensitive identifiers nor borrowed packet views.
class PreauthSession final
{
public:
    [[nodiscard]] PreauthStage stage() const noexcept { return stage_; }

    [[nodiscard]] SecurityReply onConnectionRequest(
        const ConnectionParseResult &request) noexcept;

    [[nodiscard]] bool onTlsHandshake(bool completed) noexcept;

    // Successful decoding consumes one envelope but ALWAYS closes the
    // diagnostic; authentication and MCS Connect-Response do not exist yet.
    [[nodiscard]] bool onEncryptedMcsConnectInitial(
        std::span<const std::uint8_t> packet) noexcept;

    void close() noexcept { stage_ = PreauthStage::Closed; }

private:
    PreauthStage stage_{PreauthStage::AwaitConnectionRequest};
};


// Incremental intake for the first, plaintext X.224 Connection Request
// carried over a TCP byte stream (RFC 1006, MS-RDPBCGR 2.2.1.1).
// After a complete request the caller must transmit the returned X.224
// Confirm/Failure before initiating TLS or closing the transport.
// No TLS provider, credentials, listener or desktop admission exists here.
enum class ConnectionIntakeStatus : std::uint8_t
{
    NeedMore,
    ReplyThenTls,
    ReplyThenClose,
    Invalid,
    Closed,
};

struct ConnectionIntakeResult
{
    // Exact prefix consumed from the supplied span. Any trailing bytes
    // remain owned by the caller for the negotiated transport layer.
    std::size_t bytesConsumed{};
    ConnectionIntakeStatus status{ConnectionIntakeStatus::NeedMore};
    // Only meaningful for ReplyThenTls and ReplyThenClose.
    SecurityReply reply{};
};

// Single owner of the initial request buffer and existing preauth state.
// Not thread-safe: invoke every method on the connection's event loop.
// Holds at most kMaximumConnectionRequestBytes; never retains borrowed input.
// A completed or rejected request cannot be replayed on this object.
class PreauthConnectionStream final
{
public:
    [[nodiscard]] PreauthStage stage() const noexcept
    {
        return session_.stage();
    }

    [[nodiscard]] ConnectionIntakeResult consumeConnectionRequest(
        std::span<const std::uint8_t> receivedBytes) noexcept;

    // The caller must first send all ReplyThenTls bytes and execute
    // a real TLS provider handshake. This bool is a diagnostic signal,
    // NOT proof of credential authentication or OS session authorization.
    [[nodiscard]] bool onTlsHandshake(bool completed) noexcept
    {
        return session_.onTlsHandshake(completed);
    }

    // One already-decrypted complete MCS envelope. Remains diagnostic;
    // the existing preauth state machine closes after examining it.
    [[nodiscard]] bool onEncryptedMcsConnectInitial(
        std::span<const std::uint8_t> packet) noexcept
    {
        return session_.onEncryptedMcsConnectInitial(packet);
    }

    void close() noexcept;

private:
    void clearRequestBuffer() noexcept;

    PreauthSession session_{};
    std::array<std::uint8_t, kMaximumConnectionRequestBytes> requestBuffer_{};
    std::size_t bufferedBytes_{};
    std::size_t expectedBytes_{};
};

} // namespace rdp_server::server::transport
