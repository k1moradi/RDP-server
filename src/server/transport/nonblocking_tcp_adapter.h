// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "preauth_session.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{

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
    [[nodiscard]] TlsHandshakeStatus onTlsIoReady(
        SSL *serverTls) noexcept
    {
        return connection_.advanceTlsHandshake(serverTls);
    }
    [[nodiscard]] PreauthConnectionStream &connection() noexcept
    {
        return connection_;
    }
    void close() noexcept { connection_.close(); }

private:
    [[nodiscard]] TcpPreauthEvent idleStatus() const noexcept;

    TcpNonblockingIo &io_;
    PreauthConnectionStream connection_{};
};

} // namespace rdp_server::server::transport
