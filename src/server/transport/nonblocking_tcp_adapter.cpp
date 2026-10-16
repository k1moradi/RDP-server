// SPDX-License-Identifier: GPL-3.0-or-later
#include "nonblocking_tcp_adapter.h"

#include <algorithm>
#include <array>
#include <limits>
#include <memory>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
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

void OwnedNativeTcpSocket::close() noexcept
{
    if (!valid()) return;
    const auto socketToClose =
        std::exchange(socket_, kInvalidSocket);
#ifdef _WIN32
    ::closesocket(static_cast<SOCKET>(socketToClose));
#else
    ::close(static_cast<int>(socketToClose));
#endif
}

TcpAcceptResult acceptNonblockingTcpConnection(
    std::uintptr_t listenerSocket) noexcept
{
    if (listenerSocket == OwnedNativeTcpSocket::kInvalidSocket)
        return {};

#ifdef _WIN32
    const SOCKET acceptedSocket = ::accept(
        static_cast<SOCKET>(listenerSocket), nullptr, nullptr);
    if (acceptedSocket == INVALID_SOCKET)
    {
        return {nativeFailure().outcome == TcpIoOutcome::WouldBlock
                    ? TcpAcceptOutcome::WouldBlock
                    : TcpAcceptOutcome::Failure, {}};
    }

    // A returned SOCKET belongs to this function until all setup succeeds.
    // Do not expose a blocking or inheritable handle on partial failure.
    u_long nonblocking = 1;
    if (::ioctlsocket(acceptedSocket, FIONBIO, &nonblocking) != 0 ||
        ::SetHandleInformation(reinterpret_cast<HANDLE>(acceptedSocket),
                               HANDLE_FLAG_INHERIT, 0) == 0)
    {
        ::closesocket(acceptedSocket);
        return {};
    }
#else
    // Never truncate an untrusted uintptr_t into an unrelated POSIX fd.
    if (listenerSocket > static_cast<std::uintptr_t>(
            (std::numeric_limits<int>::max)()))
        return {};

#ifdef __linux__
    // Atomic descriptor flags avoid an inheritable or blocking window
    // during concurrent exec/fork or socket-readiness dispatch.
    const int acceptedSocket = ::accept4(
        static_cast<int>(listenerSocket), nullptr, nullptr,
        SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
    const int acceptedSocket = ::accept(
        static_cast<int>(listenerSocket), nullptr, nullptr);
#endif
    if (acceptedSocket < 0)
    {
        return {nativeFailure().outcome == TcpIoOutcome::WouldBlock
                    ? TcpAcceptOutcome::WouldBlock
                    : TcpAcceptOutcome::Failure, {}};
    }

#ifndef __linux__
    const int descriptorFlags = ::fcntl(acceptedSocket, F_GETFD, 0);
    const int socketFlags = ::fcntl(acceptedSocket, F_GETFL, 0);
    if (descriptorFlags < 0 || socketFlags < 0 ||
        ::fcntl(acceptedSocket, F_SETFD, descriptorFlags | FD_CLOEXEC) < 0 ||
        ::fcntl(acceptedSocket, F_SETFL, socketFlags | O_NONBLOCK) < 0)
    {
        ::close(acceptedSocket);
        return {};
    }
#endif

#ifdef SO_NOSIGPIPE
    const int noSigpipe = 1;
    if (::setsockopt(acceptedSocket, SOL_SOCKET, SO_NOSIGPIPE,
                     &noSigpipe, sizeof(noSigpipe)) != 0)
    {
        ::close(acceptedSocket);
        return {};
    }
#endif
#endif

    // This is ownership of a native connection only, NOT permission to
    // authenticate, dispatch MCS messages or open an OS desktop session.
    return {TcpAcceptOutcome::Accepted,
            OwnedNativeTcpSocket{static_cast<std::uintptr_t>(acceptedSocket)}};
}





TcpAcceptBatchResult acceptNonblockingTcpBatch(
    std::uintptr_t listenerSocket, std::size_t budget,
    TcpAcceptedSocketCallback onAccepted, void *context) noexcept
{
    using Outcome = TcpAcceptBatchOutcome;
    if (listenerSocket == OwnedNativeTcpSocket::kInvalidSocket ||
        budget == 0 || budget > kMaximumTcpAcceptBatch ||
        onAccepted == nullptr)
        return {Outcome::InvalidInput, 0};

    // The callback receives an owning RAII handle by value. If it
    // declines or forgets to adopt it, that handle closes automatically.
    // Reuse the ONLY native acceptor: its per-platform descriptor flags,
    // invalid listener checks and close-on-failure stay authoritative.
    std::size_t transferred = 0;
    for (; transferred < budget; )
    {
        auto result = acceptNonblockingTcpConnection(listenerSocket);
        if (result.outcome == TcpAcceptOutcome::WouldBlock)
            return {transferred == 0 ? Outcome::WouldBlock
                                     : Outcome::Drained, transferred};
        if (result.outcome != TcpAcceptOutcome::Accepted ||
            !result.connection.valid())
            return {Outcome::Failure, transferred};

        ++transferred;
        if (!onAccepted(std::move(result.connection), context))
            return {Outcome::CallbackStopped, transferred};
    }
    return {Outcome::BudgetReached, transferred};
}


TcpListenerPollResult pollNonblockingTcpAcceptBatch(
    std::uintptr_t listenerSocket, std::size_t budget,
    TcpAcceptedSocketCallback onAccepted, void *context,
    std::chrono::steady_clock::time_point deadline,
    std::chrono::milliseconds maxWait) noexcept
{
    using Outcome = TcpListenerPollOutcome;
    if (listenerSocket == OwnedNativeTcpSocket::kInvalidSocket ||
        budget == 0 || budget > kMaximumTcpAcceptBatch ||
        onAccepted == nullptr)
        return {Outcome::InvalidInput, {}};

#ifndef _WIN32
    // Never truncate a caller-provided unsigned socket identifier.
    if (listenerSocket > static_cast<std::uintptr_t>(
            (std::numeric_limits<int>::max)()))
        return {Outcome::InvalidInput, {}};
#endif

    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return {Outcome::Expired, {}};

    // Even an arbitrarily large requested wait cannot starve the
    // caller's other sockets. Each invocation contains at most one
    // native wait and one bounded accept batch, with no hidden retry.
    const auto requested = (std::max)(maxWait, std::chrono::milliseconds{0});
    const auto left =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);
    const auto bounded = (std::min)(
        (std::min)(requested, kMaximumTcpPollWait), left);
    const int timeoutMillis = static_cast<int>(bounded.count()); // 0..25

#ifdef _WIN32
    const SOCKET listener = static_cast<SOCKET>(listenerSocket);
    fd_set readable{};
    fd_set exceptional{};
    FD_ZERO(&readable);
    FD_ZERO(&exceptional);
    FD_SET(listener, &readable);
    FD_SET(listener, &exceptional);
    timeval timeout{};
    timeout.tv_usec = timeoutMillis * 1000L;
    // Winsock select supports a listening socket; no fd-number bound
    // or POSIX descriptor conversion is involved.
    const int count = ::select(0, &readable, nullptr, &exceptional,
                               &timeout);
    const bool interrupted = count < 0 &&
                             WSAGetLastError() == WSAEINTR;
#else
    pollfd ready{};
    ready.fd = static_cast<int>(listenerSocket);
    ready.events = POLLIN;
    const int count = ::poll(&ready, static_cast<nfds_t>(1),
                             timeoutMillis);
    const bool interrupted = count < 0 && errno == EINTR;
#endif
    if (count < 0 && !interrupted)
        return {Outcome::Failure, {}};

    // Return control after EINTR rather than restarting the timeout.
    if (count <= 0)
        return {std::chrono::steady_clock::now() >= deadline
                    ? Outcome::Expired : Outcome::NoEvent, {}};

#ifdef _WIN32
    if (FD_ISSET(listener, &exceptional))
        return {Outcome::Failure, {}};
    if (!FD_ISSET(listener, &readable))
        return {Outcome::NoEvent, {}};
#else
    if ((ready.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        return {Outcome::Failure, {}};
    if ((ready.revents & POLLIN) == 0)
        return {Outcome::NoEvent, {}};
#endif

    // Do not independently accept, poll or create a second owner:
    // the first-party bounded acceptor alone determines connection
    // ownership, per-platform flags and eventual handoff/stop.
    auto result = acceptNonblockingTcpBatch(
        listenerSocket, budget, onAccepted, context);
    return {result.outcome == TcpAcceptBatchOutcome::Failure
                ? Outcome::Failure : Outcome::BatchCompleted,
            result};
}

TcpConnectionPollResult OwnedPreauthTcpConnection::pollSocketOnce(
    std::chrono::steady_clock::time_point deadline,
    std::chrono::milliseconds maxWait) noexcept
{
    using Outcome = TcpConnectionPollOutcome;
    using Interest = TcpConnectionIoInterest;
    if (!active()) return {Outcome::Closed, Interest::Closed};

    // Deadlines apply even while an external TLS context is pending.
    const auto now = std::chrono::steady_clock::now();
    if (cancelIfExpired(now, deadline))
        return {Outcome::Expired, Interest::Closed};

    const auto wanted = ioInterest();
    if (wanted == Interest::Closed)
    {
        cancel();
        return {Outcome::Closed, Interest::Closed};
    }
    if (wanted == Interest::ConfigureTls)
        return {Outcome::NeedsTls, wanted};

    // No unbounded wait, retry loop, OS timer or descriptor duplication.
    const auto maximum = (std::max)(maxWait, std::chrono::milliseconds{0});
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    const auto wait = (std::min)(
        (std::min)(maximum, kMaximumTcpPollWait), remaining);
    const int timeoutMillis = static_cast<int>(wait.count()); // 0..25

#ifdef _WIN32
    WSAPOLLFD ready{};
    ready.fd = static_cast<SOCKET>(nativeSocket());
    ready.events = wanted == Interest::Read ? POLLIN : POLLOUT;
    const int count = ::WSAPoll(&ready, 1UL, timeoutMillis);
    const bool interrupted = count < 0 && WSAGetLastError() == WSAEINTR;
#else
    if (nativeSocket() > static_cast<std::uintptr_t>(
            (std::numeric_limits<int>::max)()))
    {
        cancel();
        return {Outcome::Failure, Interest::Closed};
    }
    pollfd ready{};
    ready.fd = static_cast<int>(nativeSocket());
    ready.events = wanted == Interest::Read ? POLLIN : POLLOUT;
    const int count = ::poll(&ready, static_cast<nfds_t>(1), timeoutMillis);
    const bool interrupted = count < 0 && errno == EINTR;
#endif

    if (count < 0 && !interrupted)
    {
        cancel();
        return {Outcome::Failure, Interest::Closed};
    }
    // EINTR is NOT silently retried. Return control to the caller after
    // at most one OS poll and give a fresh chance to check the deadline.
    if (count <= 0)
    {
        if (cancelIfExpired(std::chrono::steady_clock::now(), deadline))
            return {Outcome::Expired, Interest::Closed};
        return {Outcome::NoEvent, ioInterest()};
    }

    if ((ready.revents & (POLLERR | POLLNVAL)) != 0)
    {
        cancel();
        return {Outcome::Failure, Interest::Closed};
    }

    // A hangup wakes the relevant callback exactly once so the owner
    // sees EOF or send failure through its existing bounded adapter.
    const bool hungUp = (ready.revents & POLLHUP) != 0;
    const bool readable = (ready.revents & POLLIN) != 0 || hungUp;
    const bool writable = (ready.revents & POLLOUT) != 0 || hungUp;
    if (!readable && !writable)
        return {Outcome::NoEvent, ioInterest()};

    const auto next = onSocketReady(readable, writable);
    return {Outcome::Dispatched, next};
}

TcpConnectionIoInterest OwnedPreauthTcpConnection::ioInterest() const noexcept
{
    if (!active()) return TcpConnectionIoInterest::Closed;

    // Connection Request parsing advances to AwaitTls (or rejects) BEFORE
    // its X.224 Confirm/Failure has drained. Pending wire bytes take
    // precedence over the protocol stage: only writable readiness may
    // deliver them, and TLS configuration must not start early.
    if (!adapter_.connection().pendingConnectionReply().empty())
        return TcpConnectionIoInterest::Write;

    switch (stage())
    {
    case PreauthStage::AwaitConnectionRequest:
        return TcpConnectionIoInterest::Read;
    case PreauthStage::AwaitTls:
        if (!serverTls_) return TcpConnectionIoInterest::ConfigureTls;
        return SSL_want_write(serverTls_.get())
                   ? TcpConnectionIoInterest::Write
                   : TcpConnectionIoInterest::Read;
    case PreauthStage::AwaitMcsConnectInitial:
        if (!serverTls_) return TcpConnectionIoInterest::Closed;
        // SSL_read_ex can exceptionally WANT_WRITE during TLS record
        // processing; honor the actual provider direction, not a guess.
        return SSL_want_write(serverTls_.get())
                   ? TcpConnectionIoInterest::Write
                   : TcpConnectionIoInterest::Read;
    case PreauthStage::Closed:
        return TcpConnectionIoInterest::Closed;
    }
    return TcpConnectionIoInterest::Closed;
}

TcpConnectionIoInterest OwnedPreauthTcpConnection::onSocketReady(
    bool readable, bool writable) noexcept
{
    const auto requested = ioInterest();
    if (requested == TcpConnectionIoInterest::Closed ||
        requested == TcpConnectionIoInterest::ConfigureTls ||
        (requested == TcpConnectionIoInterest::Read && !readable) ||
        (requested == TcpConnectionIoInterest::Write && !writable))
        return requested;

    // A protocol transition can occur before its Confirm/Failure is
    // delivered. Drain pending reply bytes through the existing
    // adapter regardless of whether the stage is AwaitTls or Closed.
    if (!adapter_.connection().pendingConnectionReply().empty())
    {
        (void)onWritable();
        return ioInterest();
    }

    // Exactly ONE existing bounded callback per matching event.
    switch (stage())
    {
    case PreauthStage::AwaitConnectionRequest:
        (void)onReadable();
        break;
    case PreauthStage::AwaitTls:
        (void)onTlsIoReady();
        break;
    case PreauthStage::AwaitMcsConnectInitial:
        (void)onMcsIoReady();
        break;
    case PreauthStage::Closed:
        cancel();
        break;
    }
    return ioInterest();
}

bool OwnedPreauthTcpConnection::cancelIfExpired(
    std::chrono::steady_clock::time_point now,
    std::chrono::steady_clock::time_point deadline) noexcept
{
    if (!active() || now < deadline) return false;
    cancel();
    return true;
}

const SSL *OwnedPreauthTcpConnection::establishedTls() const noexcept
{
    return active() && serverTls_ &&
                   stage() == PreauthStage::AwaitMcsConnectInitial &&
                   SSL_is_init_finished(serverTls_.get()) == 1
               ? serverTls_.get()
               : nullptr;
}

OwnedPreauthTcpConnection::OwnedPreauthTcpConnection(
    OwnedNativeTcpSocket acceptedSocket) noexcept
    : socket_(std::move(acceptedSocket)),
      io_(socket_.nativeSocket()),
      adapter_(io_)
{
    if (!socket_.valid()) adapter_.close();
}

void OwnedPreauthTcpConnection::cancel() noexcept
{
    // The BIO borrows io_; free its SSL before closing the native socket.
    adapter_.close();
    serverTls_.reset();
    socket_.close();
}

TcpPreauthEvent OwnedPreauthTcpConnection::onReadable() noexcept
{
    if (!active()) return TcpPreauthEvent::Closed;
    const auto status = adapter_.onReadable();
    if (status == TcpPreauthEvent::Closed ||
        status == TcpPreauthEvent::Invalid)
        cancel();
    return status;
}

TcpPreauthEvent OwnedPreauthTcpConnection::onWritable() noexcept
{
    if (!active()) return TcpPreauthEvent::Closed;
    const auto status = adapter_.onWritable();
    if (status == TcpPreauthEvent::Closed ||
        status == TcpPreauthEvent::Invalid)
        cancel();
    return status;
}

bool OwnedPreauthTcpConnection::attachServerTls(ServerTls serverTls) noexcept
{
    if (!active() || serverTls_ || !serverTls ||
        !adapter_.attachTlsTransport(serverTls.get()))
    {
        cancel();
        return false;
    }
    serverTls_ = std::move(serverTls);
    return true;
}

TlsHandshakeStatus OwnedPreauthTcpConnection::onTlsIoReady() noexcept
{
    if (!active()) return TlsHandshakeStatus::Closed;
    if (!serverTls_)
    {
        cancel();
        return TlsHandshakeStatus::Invalid;
    }
    const auto result = adapter_.onAttachedTlsIoReady();
    if (result == TlsHandshakeStatus::Invalid ||
        result == TlsHandshakeStatus::Closed)
        cancel();
    return result;
}

McsIntakeResult OwnedPreauthTcpConnection::onMcsIoReady() noexcept
{
    if (!active()) return {0, McsIntakeStatus::Closed};
    if (!serverTls_)
    {
        cancel();
        return {0, McsIntakeStatus::Invalid};
    }
    const auto result = adapter_.onAttachedMcsIoReady();
    if (result.status != McsIntakeStatus::NeedMore)
        cancel();
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
