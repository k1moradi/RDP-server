// SPDX-License-Identifier: GPL-3.0-or-later
// Test-only transport diagnostic: one private IPv4 loopback connection,
// X.224 negotiation, TLS 1.2+, and one encrypted MCS Connect-Initial,
// then mandatory disconnect with no domain admission.
// This MUST NOT be installed or exposed as an RDP desktop server.
// No MCS Connect-Response, CredSSP/NLA, user session or clipboard is admitted.
#include "transport/preauth_session.h"
#include "transport/tpkt_x224.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <memory>
#include <netinet/in.h>
#include <poll.h>
#include <span>
#include <sys/socket.h>
#include <unistd.h>

namespace
{

class OwnedSocket final
{
public:
    explicit OwnedSocket(int descriptor = -1) noexcept : descriptor_(descriptor) {}
    OwnedSocket(const OwnedSocket &) = delete;
    OwnedSocket &operator=(const OwnedSocket &) = delete;
    ~OwnedSocket()
    {
        if (descriptor_ >= 0)
        {
            (void)::close(descriptor_);
        }
    }
    [[nodiscard]] int get() const noexcept { return descriptor_; }
private:
    int descriptor_;
};

using SslContext = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslConnection = std::unique_ptr<SSL, decltype(&SSL_free)>;
using Deadline = std::chrono::steady_clock::time_point;
constexpr auto kOverallTimeout = std::chrono::seconds(5);

[[nodiscard]] bool waitForSocket(int fd, short requested,
                                 Deadline deadline) noexcept
{
    while (true)
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
        {
            return false;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const auto timeout = static_cast<int>(
            std::clamp<std::int64_t>(remaining.count(), 1, 5000));
        pollfd request{fd, requested, 0};
        const int result = ::poll(&request, 1, timeout);
        if (result < 0 && errno == EINTR)
        {
            continue;
        }
        return result > 0 && (request.revents & requested) != 0;
    }
}

[[nodiscard]] bool readExact(int fd, std::span<std::uint8_t> bytes,
                             Deadline deadline) noexcept
{
    std::size_t total = 0;
    while (total < bytes.size())
    {
        if (!waitForSocket(fd, POLLIN, deadline))
        {
            return false;
        }
        const ssize_t result = ::recv(fd, bytes.data() + total,
                                      bytes.size() - total, MSG_DONTWAIT);
        if (result < 0 && (errno == EINTR || errno == EAGAIN ||
                           errno == EWOULDBLOCK))
        {
            continue;
        }
        if (result <= 0)
        {
            return false;
        }
        total += static_cast<std::size_t>(result);
    }
    return true;
}

[[nodiscard]] bool writeExact(int fd, std::span<const std::uint8_t> bytes,
                              Deadline deadline) noexcept
{
    std::size_t total = 0;
    while (total < bytes.size())
    {
        if (!waitForSocket(fd, POLLOUT, deadline))
        {
            return false;
        }
        const ssize_t result = ::send(fd, bytes.data() + total,
                                      bytes.size() - total,
                                      MSG_DONTWAIT | MSG_NOSIGNAL);
        if (result < 0 && (errno == EINTR || errno == EAGAIN ||
                           errno == EWOULDBLOCK))
        {
            continue;
        }
        if (result <= 0)
        {
            return false;
        }
        total += static_cast<std::size_t>(result);
    }
    return true;
}

[[nodiscard]] SslContext openTlsContext(const char *certificate,
                                        const char *privateKey) noexcept
{
    SslContext context(SSL_CTX_new(TLS_server_method()), &SSL_CTX_free);
    if (!context || SSL_CTX_set_min_proto_version(
                        context.get(), TLS1_2_VERSION) != 1)
    {
        return {nullptr, &SSL_CTX_free};
    }
    // Avoid TLS-level compression; the diagnostic does not negotiate any
    // RDP compression nor expose an application protocol after the handshake.
    SSL_CTX_set_options(context.get(), SSL_OP_NO_COMPRESSION);
    if (SSL_CTX_use_certificate_chain_file(
            context.get(), certificate) != 1 ||
        SSL_CTX_use_PrivateKey_file(context.get(), privateKey,
                                    SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context.get()) != 1)
    {
        return {nullptr, &SSL_CTX_free};
    }
    return context;
}

// SSL_read only consumes decrypted application bytes. Both the 4-byte
// header and the frame remainder share the original connection deadline.
[[nodiscard]] bool readTlsExact(SSL *tls, int fd,
                                std::span<std::uint8_t> output,
                                Deadline deadline) noexcept
{
    std::size_t received = 0;
    while (received < output.size())
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            return false;
        }
        const auto available = output.size() - received;
        const int result = SSL_read(tls, output.data() + received,
                                    static_cast<int>(available));
        if (result > 0)
        {
            received += static_cast<std::size_t>(result);
            continue;
        }
        const int error = SSL_get_error(tls, result);
        if (error == SSL_ERROR_WANT_READ)
        {
            if (!waitForSocket(fd, POLLIN, deadline))
            {
                return false;
            }
        }
        else if (error == SSL_ERROR_WANT_WRITE)
        {
            if (!waitForSocket(fd, POLLOUT, deadline))
            {
                return false;
            }
        }
        else
        {
            // Includes peer closure, incomplete TLS records, corrupted
            // ciphertext and OpenSSL protocol errors.
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool readEncryptedMcsConnectInitial(
    SSL *tls, int fd, Deadline deadline,
    rdp_server::server::transport::PreauthSession &session) noexcept
{
    using namespace rdp_server::server::transport;
    std::array<std::uint8_t, kMaximumInitialMcsTpktBytes> packet{};
    if (!readTlsExact(tls, fd, std::span(packet).first(4), deadline))
    {
        session.close();
        return false;
    }
    const auto requestedLength =
        (static_cast<std::size_t>(packet[2]) << 8U) | packet[3];
    if (packet[0] != 3 || packet[1] != 0 ||
        requestedLength < 8 ||
        requestedLength > packet.size())
    {
        session.close();
        return false;
    }
    if (!readTlsExact(tls, fd,
                      std::span(packet).subspan(4, requestedLength - 4),
                      deadline))
    {
        session.close();
        return false;
    }
    // Parse only. Never emit an MCS Connect-Response or authorize a
    // channel, even for Microsoft's byte-exact published example.
    return session.onEncryptedMcsConnectInitial(
        std::span(packet).first(requestedLength));
}

[[nodiscard]] bool completeTlsHandshake(
    SSL_CTX *context, int fd, Deadline deadline,
    rdp_server::server::transport::PreauthSession &session) noexcept
{
    SslConnection ssl(SSL_new(context), &SSL_free);
    if (!ssl || SSL_set_fd(ssl.get(), fd) != 1)
    {
        return false;
    }
    while (std::chrono::steady_clock::now() < deadline)
    {
        const int result = SSL_accept(ssl.get());
        if (result == 1)
        {
            if (!session.onTlsHandshake(true))
            {
                return false;
            }
            const bool valid =
                readEncryptedMcsConnectInitial(ssl.get(), fd,
                                               deadline, session);
            // A valid MCS envelope grants NO channel/session access.
            // One best-effort nonblocking close_notify, no response PDU.
            (void)SSL_shutdown(ssl.get());
            return valid;
        }
        const int status = SSL_get_error(ssl.get(), result);
        if (status == SSL_ERROR_WANT_READ)
        {
            if (!waitForSocket(fd, POLLIN, deadline))
            {
                return false;
            }
        }
        else if (status == SSL_ERROR_WANT_WRITE)
        {
            if (!waitForSocket(fd, POLLOUT, deadline))
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }
    return false;
}

[[nodiscard]] int handleConnection(int client, SSL_CTX *tlsContext,
                                   Deadline deadline)
{
    sockaddr_in peer{};
    socklen_t peerBytes = sizeof(peer);
    if (::getpeername(client, reinterpret_cast<sockaddr *>(&peer),
                      &peerBytes) != 0 ||
        peerBytes != sizeof(peer) || peer.sin_family != AF_INET ||
        peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
    {
        return 1;
    }
    if (::fcntl(client, F_SETFL, O_NONBLOCK) == -1)
    {
        return 1;
    }

    std::array<std::uint8_t,
        rdp_server::server::transport::kMaximumConnectionRequestBytes> packet{};
    if (!readExact(client, std::span(packet).first(4), deadline))
    {
        return 1;
    }
    const auto length =
        rdp_server::server::transport::connectionRequestLength(
            std::span(packet).first(4));
    if (!length ||
        !readExact(client, std::span(packet).subspan(4, *length - 4),
                   deadline))
    {
        return 1;
    }
    const auto request =
        rdp_server::server::transport::parseConnectionRequest(
            std::span(packet).first(*length));
    if (!request)
    {
        return 1;
    }
    rdp_server::server::transport::PreauthSession session;
    const auto reply = session.onConnectionRequest(request);
    if (!writeExact(client, reply.packet, deadline))
    {
        return 1;
    }
    if (reply.decision !=
        rdp_server::server::transport::SecurityDecision::Tls)
    {
        // Sending an RDP_NEG_FAILURE followed by EOF is a correct
        // diagnostic rejection, not a successfully accepted session.
        return 0;
    }
    return completeTlsHandshake(tlsContext, client, deadline, session)
               ? 0 : 1;
}

} // namespace

int main(int argc, char **argv)
{
    // Missing or invalid credentials MUST be rejected before opening any
    // listener. Tests generate their ephemeral self-signed key externally;
    // no private key is stored in the project or log output.
    if (argc != 3)
    {
        std::cerr << "usage: tls_session_gate <certificate.pem> <private_key.pem>\n";
        return 2;
    }
    // Ignore SIGPIPE so peer cancellation is a normal fail-closed error.
    (void)::signal(SIGPIPE, SIG_IGN);
    const SslContext tls = openTlsContext(argv[1], argv[2]);
    if (!tls)
    {
        std::cerr << "TLS certificate or key configuration invalid\n";
        return 2;
    }

    OwnedSocket listener(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (listener.get() < 0)
    {
        return 2;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(0); // Always ephemeral, never port 3389.
    if (::bind(listener.get(), reinterpret_cast<sockaddr *>(&address),
               sizeof(address)) != 0 ||
        ::listen(listener.get(), 1) != 0)
    {
        return 2;
    }
    socklen_t addressBytes = sizeof(address);
    if (::getsockname(listener.get(), reinterpret_cast<sockaddr *>(&address),
                      &addressBytes) != 0 ||
        addressBytes != sizeof(address) ||
        address.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
    {
        return 2;
    }
    std::cout << "LISTEN_LOOPBACK=" << ntohs(address.sin_port)
              << '\n' << std::flush;
    const auto deadline = std::chrono::steady_clock::now() + kOverallTimeout;
    if (!waitForSocket(listener.get(), POLLIN, deadline))
    {
        return 1;
    }
    OwnedSocket client(::accept4(listener.get(), nullptr, nullptr,
                                 SOCK_CLOEXEC | SOCK_NONBLOCK));
    if (client.get() < 0)
    {
        return 1;
    }
    return handleConnection(client.get(), tls.get(), deadline);
}
