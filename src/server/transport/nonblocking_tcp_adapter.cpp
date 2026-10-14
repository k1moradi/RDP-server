// SPDX-License-Identifier: GPL-3.0-or-later
#include "nonblocking_tcp_adapter.h"

#include <array>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#else
#include <cerrno>
#include <sys/socket.h>
#endif

namespace rdp_server::server::transport
{
namespace
{
[[nodiscard]] TcpIoResult nativeFailure() noexcept
{
#ifdef _WIN32
    const int code = WSAGetLastError();
    return {code == WSAEWOULDBLOCK || code == WSAEINTR
                ? TcpIoOutcome::WouldBlock : TcpIoOutcome::Failure, 0};
#else
    return {errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR
                ? TcpIoOutcome::WouldBlock : TcpIoOutcome::Failure, 0};
#endif
}
}

TcpIoResult NativeTcpIo::receive(std::span<std::uint8_t> destination) noexcept
{
    if (destination.empty())
    {
        return {TcpIoOutcome::Failure, 0};
    }
#ifdef _WIN32
    const int result = ::recv(static_cast<SOCKET>(socket_),
                              reinterpret_cast<char *>(destination.data()),
                              static_cast<int>(destination.size()), 0);
    if (result == SOCKET_ERROR) return nativeFailure();
#else
    const auto result = ::recv(static_cast<int>(socket_),
                               destination.data(), destination.size(), 0);
    if (result < 0) return nativeFailure();
#endif
    return result == 0 ? TcpIoResult{TcpIoOutcome::EndOfStream, 0}
                       : TcpIoResult{TcpIoOutcome::Progress,
                                     static_cast<std::size_t>(result)};
}

TcpIoResult NativeTcpIo::send(std::span<const std::uint8_t> source) noexcept
{
    if (source.empty())
    {
        return {TcpIoOutcome::Failure, 0};
    }
#ifdef _WIN32
    const int result = ::send(static_cast<SOCKET>(socket_),
                              reinterpret_cast<const char *>(source.data()),
                              static_cast<int>(source.size()), 0);
    if (result == SOCKET_ERROR) return nativeFailure();
#else
#ifdef MSG_NOSIGNAL
    constexpr int flags = MSG_NOSIGNAL;
#else
    constexpr int flags = 0;
#endif
    const auto result = ::send(static_cast<int>(socket_), source.data(),
                               source.size(), flags);
    if (result < 0) return nativeFailure();
#endif
    return result == 0 ? TcpIoResult{TcpIoOutcome::WouldBlock, 0}
                       : TcpIoResult{TcpIoOutcome::Progress,
                                     static_cast<std::size_t>(result)};
}

TcpPreauthEvent PreauthTcpAdapter::idleStatus() const noexcept
{
    if (!connection_.pendingConnectionReply().empty())
    {
        return TcpPreauthEvent::NeedWrite;
    }
    switch (connection_.stage())
    {
    case PreauthStage::AwaitConnectionRequest:
        return TcpPreauthEvent::NeedRead;
    case PreauthStage::AwaitTls:
        return TcpPreauthEvent::ReadyForTls;
    case PreauthStage::Closed:
        return TcpPreauthEvent::Closed;
    case PreauthStage::AwaitMcsConnectInitial:
        // The socket adapter is only for the pre-TLS plaintext boundary.
        return TcpPreauthEvent::ReadyForTls;
    }
    return TcpPreauthEvent::Invalid;
}

TcpPreauthEvent PreauthTcpAdapter::onReadable() noexcept
{
    if (connection_.stage() != PreauthStage::AwaitConnectionRequest)
    {
        return idleStatus();
    }
    // No unbounded receive loop. Request is limited to 260 bytes,
    // and each successful recv must make forward progress.
    std::array<std::uint8_t, kMaximumConnectionRequestBytes> buffer{};
    for (std::size_t tries = 0; tries < kMaximumConnectionRequestBytes; ++tries)
    {
        const auto needed = connection_.connectionRequestBytesNeeded();
        if (needed == 0 || needed > buffer.size())
        {
            connection_.close();
            return TcpPreauthEvent::Invalid;
        }
        const auto received = io_.receive(std::span(buffer).first(needed));
        if (received.outcome == TcpIoOutcome::WouldBlock &&
            received.bytes == 0)
        {
            return TcpPreauthEvent::NeedRead;
        }
        if (received.outcome != TcpIoOutcome::Progress ||
            received.bytes == 0 || received.bytes > needed)
        {
            connection_.close();
            return TcpPreauthEvent::Invalid;
        }
        const auto parsed = connection_.consumeConnectionRequest(
            std::span(buffer).first(received.bytes));
        if (parsed.bytesConsumed != received.bytes)
        {
            connection_.close();
            return TcpPreauthEvent::Invalid;
        }
        switch (parsed.status)
        {
        case ConnectionIntakeStatus::NeedMore:
            continue;
        case ConnectionIntakeStatus::ReplyThenTls:
        case ConnectionIntakeStatus::ReplyThenClose:
            return TcpPreauthEvent::NeedWrite;
        case ConnectionIntakeStatus::Invalid:
        case ConnectionIntakeStatus::Closed:
            connection_.close();
            return TcpPreauthEvent::Invalid;
        }
    }
    connection_.close();
    return TcpPreauthEvent::Invalid;
}

TcpPreauthEvent PreauthTcpAdapter::onWritable() noexcept
{
    const auto pending = connection_.pendingConnectionReply();
    if (pending.empty())
    {
        return idleStatus();
    }
    // Reply length is fixed at 19 bytes. Every successful write must
    // make progress on exactly the provided unsent suffix.
    for (std::size_t tries = 0; tries < 19; ++tries)
    {
        const auto suffix = connection_.pendingConnectionReply();
        if (suffix.empty())
        {
            return idleStatus();
        }
        const auto written = io_.send(suffix);
        if (written.outcome == TcpIoOutcome::WouldBlock &&
            written.bytes == 0)
        {
            return TcpPreauthEvent::NeedWrite;
        }
        if (written.outcome != TcpIoOutcome::Progress ||
            written.bytes == 0 || written.bytes > suffix.size())
        {
            connection_.close();
            return TcpPreauthEvent::Invalid;
        }
        const auto status = connection_.onConnectionReplyBytesWritten(
            written.bytes);
        switch (status)
        {
        case ConnectionReplyWriteStatus::NeedMore:
            continue;
        case ConnectionReplyWriteStatus::ReplySentStartTls:
            return TcpPreauthEvent::ReadyForTls;
        case ConnectionReplyWriteStatus::ReplySentClose:
            return TcpPreauthEvent::Closed;
        case ConnectionReplyWriteStatus::Invalid:
        case ConnectionReplyWriteStatus::Closed:
            connection_.close();
            return TcpPreauthEvent::Invalid;
        }
    }
    connection_.close();
    return TcpPreauthEvent::Invalid;
}

} // namespace rdp_server::server::transport
