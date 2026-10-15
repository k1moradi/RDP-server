// SPDX-License-Identifier: GPL-3.0-or-later
#include "nonblocking_tcp_adapter.h"

#include <algorithm>
#include <array>
#include <memory>

#include <openssl/bio.h>
#include <openssl/ssl.h>

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

// OpenSSL invokes these callbacks synchronously during SSL_do_handshake,
// SSL_read_ex and SSL_write_ex. The BIO borrows TcpNonblockingIo and does not
// own, duplicate, close or alter the native socket.
namespace
{
int tcpBioCreate(BIO *bio)
{
    BIO_set_init(bio, 0);
    BIO_set_data(bio, nullptr);
    BIO_set_shutdown(bio, 0);
    return 1;
}

int tcpBioDestroy(BIO *bio)
{
    if (bio == nullptr) return 0;
    BIO_set_init(bio, 0);
    BIO_set_data(bio, nullptr);
    return 1;
}

int tcpBioRead(BIO *bio, char *data, std::size_t size,
               std::size_t *readBytes)
{
    if (readBytes == nullptr) return 0;
    *readBytes = 0;
    BIO_clear_retry_flags(bio);
    if (data == nullptr || size == 0 || BIO_get_init(bio) != 1)
        return 0;
    auto *io = static_cast<TcpNonblockingIo *>(BIO_get_data(bio));
    if (io == nullptr) return 0;
    const auto requested = (std::min)(size, kMaximumTcpIoChunkBytes);
    const auto result = io->receive(
        {reinterpret_cast<std::uint8_t *>(data), requested});
    if (result.outcome == TcpIoOutcome::WouldBlock && result.bytes == 0)
    {
        BIO_set_retry_read(bio);
        return 0;
    }
    if (result.outcome != TcpIoOutcome::Progress ||
        result.bytes == 0 || result.bytes > requested)
        return 0;
    *readBytes = result.bytes;
    return 1;
}

int tcpBioWrite(BIO *bio, const char *data, std::size_t size,
                std::size_t *writtenBytes)
{
    if (writtenBytes == nullptr) return 0;
    *writtenBytes = 0;
    BIO_clear_retry_flags(bio);
    if (data == nullptr || size == 0 || BIO_get_init(bio) != 1)
        return 0;
    auto *io = static_cast<TcpNonblockingIo *>(BIO_get_data(bio));
    if (io == nullptr) return 0;
    const auto requested = (std::min)(size, kMaximumTcpIoChunkBytes);
    const auto result = io->send(
        {reinterpret_cast<const std::uint8_t *>(data), requested});
    if (result.outcome == TcpIoOutcome::WouldBlock && result.bytes == 0)
    {
        BIO_set_retry_write(bio);
        return 0;
    }
    if (result.outcome != TcpIoOutcome::Progress ||
        result.bytes == 0 || result.bytes > requested)
        return 0;
    *writtenBytes = result.bytes;
    return 1;
}

long tcpBioCtrl(BIO *, int command, long, void *)
{
    if (command == BIO_CTRL_FLUSH) return 1;
    // These socket BIOs have no internal plaintext buffering or state.
    return 0;
}

struct TcpBioMethod final
{
    std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)>
        method{BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
                            "rdp-server borrowed nonblocking TCP"),
               BIO_meth_free};

    TcpBioMethod()
    {
        if (!method) return;
        if (BIO_meth_set_create(method.get(), tcpBioCreate) != 1 ||
            BIO_meth_set_destroy(method.get(), tcpBioDestroy) != 1 ||
            BIO_meth_set_read_ex(method.get(), tcpBioRead) != 1 ||
            BIO_meth_set_write_ex(method.get(), tcpBioWrite) != 1 ||
            BIO_meth_set_ctrl(method.get(), tcpBioCtrl) != 1)
            method.reset();
    }
};

[[nodiscard]] const BIO_METHOD *tcpBioMethod() noexcept
{
    static const TcpBioMethod method{};
    return method.method.get();
}
}

bool attachNonblockingTcpBio(SSL *tls, TcpNonblockingIo &io) noexcept
{
    if (tls == nullptr || SSL_get_rbio(tls) != nullptr ||
        SSL_get_wbio(tls) != nullptr || SSL_is_init_finished(tls) == 1)
        return false;
    const auto *method = tcpBioMethod();
    if (method == nullptr) return false;
    BIO *bio = BIO_new(method);
    if (bio == nullptr) return false;
    BIO_set_data(bio, &io);
    BIO_set_init(bio, 1);
    // SSL assumes ownership of exactly one shared read/write BIO, but
    // the caller still owns the borrowed TcpNonblockingIo and socket.
    SSL_set_bio(tls, bio, bio);
    return true;
}

bool PreauthTcpAdapter::attachTlsTransport(SSL *serverTls) noexcept
{
    if (attachedServerTls_ != nullptr || serverTls == nullptr ||
        connection_.stage() != PreauthStage::AwaitTls ||
        !connection_.pendingConnectionReply().empty() ||
        SSL_is_server(serverTls) != 1 ||
        !attachNonblockingTcpBio(serverTls, io_))
    {
        close();
        return false;
    }
    // Only this BIO, borrowing the SAME TCP I/O as X.224, is eligible
    // for the subsequent connected TLS and MCS readiness callbacks.
    attachedServerTls_ = serverTls;
    attachedTcpBio_ = SSL_get_rbio(serverTls);
    if (!matchesAttachedTlsTransport())
    {
        close();
        return false;
    }
    return true;
}

bool PreauthTcpAdapter::matchesAttachedTlsTransport() const noexcept
{
    // Check identities before dereferencing a potentially replaced BIO:
    // SSL_set_bio may have freed the original BIO in the interim.
    return attachedServerTls_ != nullptr &&
           attachedTcpBio_ != nullptr &&
           SSL_get_rbio(attachedServerTls_) == attachedTcpBio_ &&
           SSL_get_wbio(attachedServerTls_) == attachedTcpBio_ &&
           BIO_get_init(attachedTcpBio_) == 1 &&
           BIO_get_data(attachedTcpBio_) == &io_;
}

TlsHandshakeStatus PreauthTcpAdapter::onAttachedTlsIoReady() noexcept
{
    if (connection_.stage() == PreauthStage::Closed)
        return TlsHandshakeStatus::Closed;
    if (connection_.stage() != PreauthStage::AwaitTls ||
        !matchesAttachedTlsTransport())
    {
        close();
        return TlsHandshakeStatus::Invalid;
    }
    const auto status = connection_.advanceTlsHandshake(attachedServerTls_);
    if (status == TlsHandshakeStatus::Invalid ||
        status == TlsHandshakeStatus::Closed)
        close();
    return status;
}

TlsHandshakeStatus PreauthTcpAdapter::onTlsIoReady(
    SSL *serverTls) noexcept
{
    // Existing memory-BIO tests use the underlying diagnostic directly.
    // Once attached to the native TCP adapter, identity substitution
    // must not bypass the stricter connected-socket ownership checks.
    if (attachedServerTls_ == nullptr)
        return connection_.advanceTlsHandshake(serverTls);
    if (serverTls != attachedServerTls_)
    {
        close();
        return TlsHandshakeStatus::Invalid;
    }
    return onAttachedTlsIoReady();
}

McsIntakeResult PreauthTcpAdapter::onAttachedMcsIoReady() noexcept
{
    if (connection_.stage() == PreauthStage::Closed)
        return {0, McsIntakeStatus::Closed};
    if (connection_.stage() != PreauthStage::AwaitMcsConnectInitial ||
        !matchesAttachedTlsTransport())
    {
        close();
        return {0, McsIntakeStatus::Invalid};
    }
    const auto result =
        connection_.consumeMcsConnectInitialFromTls(attachedServerTls_);
    if (result.status == McsIntakeStatus::Invalid ||
        result.status == McsIntakeStatus::Closed ||
        result.status == McsIntakeStatus::EnvelopeValidated)
        close();
    return result;
}

TcpIoResult NativeTcpIo::receive(std::span<std::uint8_t> destination) noexcept
{
    if (destination.empty())
    {
        return {TcpIoOutcome::Failure, 0};
    }
    const auto requested = (std::min)(
        destination.size(), kMaximumTcpIoChunkBytes);
#ifdef _WIN32
    const int result = ::recv(static_cast<SOCKET>(socket_),
                              reinterpret_cast<char *>(destination.data()),
                              static_cast<int>(requested), 0);
    if (result == SOCKET_ERROR) return nativeFailure();
#else
    const auto result = ::recv(static_cast<int>(socket_),
                               destination.data(), requested, 0);
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
    const auto requested = (std::min)(
        source.size(), kMaximumTcpIoChunkBytes);
#ifdef _WIN32
    const int result = ::send(static_cast<SOCKET>(socket_),
                              reinterpret_cast<const char *>(source.data()),
                              static_cast<int>(requested), 0);
    if (result == SOCKET_ERROR) return nativeFailure();
#else
#ifdef MSG_NOSIGNAL
    constexpr int flags = MSG_NOSIGNAL;
#else
    constexpr int flags = 0;
#endif
    const auto result = ::send(static_cast<int>(socket_), source.data(),
                               requested, flags);
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
