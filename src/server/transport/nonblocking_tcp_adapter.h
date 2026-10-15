// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "preauth_session.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{

// One native recv/send or borrowed OpenSSL BIO callback may transfer at
// most one bounded 18 KiB chunk (TLS 1.2 ciphertext maximum payload;
// TLS 1.3 is smaller). Larger caller buffers are processed incrementally
// by their own event loop. No int narrowing on Windows and no allocation.
inline constexpr std::size_t kMaximumTcpIoChunkBytes = 18U * 1024U;

// One result from a caller-owned NONBLOCKING TCP descriptor. A Progress
// result must have 1..buffer.size() bytes. Other outcomes must have zero.
// No invented timeouts, packet boundaries or automatic OS authorization.
enum class TcpIoOutcome : std::uint8_t
{
    Progress,
    WouldBlock,
    EndOfStream,
    Failure,
};

struct TcpIoResult
{
    TcpIoOutcome outcome{TcpIoOutcome::Failure};
    std::size_t bytes{};
};

// Borrowed OS transport; the caller owns socket setup, readiness polling,
// closure/cancellation and lifetime. Must be called on one event loop.
class TcpNonblockingIo
{
public:
    virtual ~TcpNonblockingIo() = default;
    [[nodiscard]] virtual TcpIoResult receive(
        std::span<std::uint8_t> destination) noexcept = 0;
    [[nodiscard]] virtual TcpIoResult send(
        std::span<const std::uint8_t> source) noexcept = 0;
};

// Thin cross-platform native recv/send adapter. Borrowed socket is already
// connected and set NONBLOCKING by its owner. On Windows, WSAStartup must
// have been performed. On macOS/BSD, owner must prevent SIGPIPE (e.g.
// SO_NOSIGPIPE); Linux uses MSG_NOSIGNAL when available.
// No listening/binding/activation, no socket ownership or duplication.
class NativeTcpIo final : public TcpNonblockingIo
{
public:
    explicit NativeTcpIo(std::uintptr_t nativeSocket) noexcept
        : socket_(nativeSocket) {}
    [[nodiscard]] TcpIoResult receive(
        std::span<std::uint8_t> destination) noexcept override;
    [[nodiscard]] TcpIoResult send(
        std::span<const std::uint8_t> source) noexcept override;
private:
    std::uintptr_t socket_{};
};

// Borrow an existing NONBLOCKING TCP transport for OpenSSL, using custom
// BIO callbacks rather than converting a Windows SOCKET to a POSIX int.
// SSL owns the BIO; the adapter/socket owner outlives every SSL operation.
// The SSL must have no BIO attached and its role must already be chosen.
// This is transport plumbing, NOT certificate/user authorization.
[[nodiscard]] bool attachNonblockingTcpBio(
    SSL *tls, TcpNonblockingIo &io) noexcept;

enum class TcpPreauthEvent : std::uint8_t
{
    NeedRead,
    NeedWrite,
    ReadyForTls,
    Closed,
    Invalid,
};

// One connection owner. An event loop calls onReadable/onWritable only when
// the borrowed socket is ready, until it returns ReadyForTls or Closed.
// Read sizes are the exact CR header/body remainder (<=260 bytes), so
// coalesced ClientHello bytes are left in the OS receive buffer for TLS.
// The successful X.224 Confirm must be completely sent before TLS starts.
// The failure response must be completely sent before terminal close.
// This adapter cannot authenticate, open an OS session or emit MCS replies.
class PreauthTcpAdapter final
{
public:
    explicit PreauthTcpAdapter(TcpNonblockingIo &io) noexcept : io_(io) {}

    [[nodiscard]] TcpPreauthEvent onReadable() noexcept;
    [[nodiscard]] TcpPreauthEvent onWritable() noexcept;
    // After ReadyForTls, the owner must attach the same configured SSL
    // to the connected nonblocking socket/BIO and drive the appropriate
    // readiness callback. No second state machine or listener is added.
    // Only after the complete X.224 Confirm: borrow the very same
    // connected TCP adapter for TLS network records. No socket ownership.
    [[nodiscard]] bool attachTlsTransport(SSL *serverTls) noexcept;

    // Direct parameterized handshake is retained for existing synthetic
    // BIO diagnostics. Once a network BIO has been attached, ONLY that
    // SSL/BIO pair can progress, including through this legacy API.
    [[nodiscard]] TlsHandshakeStatus onTlsIoReady(
        SSL *serverTls) noexcept;

    // Strict connected-TCP integration callbacks for the event loop.
    // SSL and its exact borrowed BIO are pinned by attachTlsTransport;
    // callers CANNOT substitute another TLS object at readiness time.
    // Requires all X.224 Confirm bytes to have been sent first.
    // The MCS callback consumes at most one encrypted, exact-length
    // packet via the SAME completed TLS and then closes this diagnostic.
    // These APIs NEVER allow authenticated MCS/channel/OS admission.
    [[nodiscard]] TlsHandshakeStatus onAttachedTlsIoReady() noexcept;
    [[nodiscard]] McsIntakeResult onAttachedMcsIoReady() noexcept;
    [[nodiscard]] PreauthConnectionStream &connection() noexcept
    {
        return connection_;
    }
    void close() noexcept
    {
        attachedServerTls_ = nullptr;
        attachedTcpBio_ = nullptr;
        connection_.close();
    }

private:
    [[nodiscard]] TcpPreauthEvent idleStatus() const noexcept;
    [[nodiscard]] bool matchesAttachedTlsTransport() const noexcept;

    TcpNonblockingIo &io_;
    PreauthConnectionStream connection_{};
    // Borrowed by this one connection owner, never another SSL/BIO owner.
    // Both must outlive this adapter and remain on its one event loop.
    SSL *attachedServerTls_{};
    BIO *attachedTcpBio_{};
};

} // namespace rdp_server::server::transport
