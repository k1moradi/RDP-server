// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "mcs_connect_initial.h"
#include "security_negotiation.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <openssl/types.h>

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

// MS-RDPBCGR 2.2.1.3: decrypted TPKT/X.224 Data TPDU encapsulating
// an MCS Connect Initial with GCC Conference Create Request.
enum class McsIntakeStatus : std::uint8_t
{
    NeedMore,
    EnvelopeValidated,
    Invalid,
    Closed,
};

struct McsIntakeResult
{
    // Exact prefix consumed. Trailing plaintext is *not* admitted here.
    std::size_t bytesConsumed{};
    McsIntakeStatus status{McsIntakeStatus::NeedMore};
};

// Single owner of the initial plaintext and post-TLS diagnostic buffers.
// Not thread-safe: invoke every method on the connection's event loop.
// Reuses one fixed, bounded storage for both connection setup envelopes.
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

    // The transport must call this only AFTER all 19 X.224 reply bytes
    // have been transmitted. Partial sends and failures must report false;
    // a premature or repeated report terminates the diagnostic.
    [[nodiscard]] bool onConnectionReplySent(bool completed) noexcept;

    // The caller must first send all ReplyThenTls bytes and complete a
    // SERVER-side OpenSSL TLS handshake. An arbitrary bool no longer
    // suffices at the stream boundary. The SSL object remains borrowed,
    // must outlive this call, and MUST NOT grant identity/OS admission.
    // The caller owns socket/BIO I/O, encrypted data, and TLS cancellation.
    [[nodiscard]] bool onTlsHandshake(const SSL *serverTls) noexcept;

    // Feed bytes returned by a TLS provider *after* a successful TLS
    // transition. Decrypted fragments may split/coalesce TPKTs.
    // Validate the entire first MCS/GCC envelope and close the diagnostic.
    // No authentication, MCS response, channel or desktop is created.
    [[nodiscard]] McsIntakeResult consumeDecryptedMcsConnectInitial(
        std::span<const std::uint8_t> decryptedBytes) noexcept;

    // Read the first MCS/GCC envelope directly from the same completed
    // OpenSSL server connection passed to onTlsHandshake(). The caller
    // owns SSL and its nonblocking BIO; never invoke concurrently with
    // another SSL_read/SSL_write on the same object. A WANT_READ/WRITE
    // leaves the diagnostic waiting for transport progress. Each call
    // reads at most one bounded TPKT, never a coalesced following PDU.
    // bytesConsumed means decrypted APPLICATION bytes, NOT TLS wire bytes.
    // Successful envelope validation still closes WITHOUT OS admission.
    [[nodiscard]] McsIntakeResult consumeMcsConnectInitialFromTls(
        SSL *serverTls) noexcept;

    void close() noexcept;

private:
    void clearIntakeBuffer() noexcept;

    PreauthSession session_{};
    // The first X.224 CR uses <=260 bytes of this same MCS-sized buffer.
    std::array<std::uint8_t, kMaximumInitialMcsTpktBytes> intakeBuffer_{};
    std::size_t bufferedBytes_{};
    std::size_t expectedBytes_{};
    // True only after exactly one completed X.224 Confirm write.
    bool connectionReplySent_{};
    // Borrowed identity only: the caller must keep this SSL alive until
    // the diagnostic closes. No TLS or OS session ownership is duplicated.
    const SSL *activeServerTls_{};
};

} // namespace rdp_server::server::transport
