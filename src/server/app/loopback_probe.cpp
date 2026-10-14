// SPDX-License-Identifier: GPL-3.0-or-later
// NON-PRODUCTION diagnostic: accepts exactly one LOCAL connection and parses
// its initial TPKT/X.224 CR, then closes it. There is intentionally NO
// negotiation success, authentication, desktop access or installed service.
// This executable must NEVER listen on a non-loopback address.
#include "transport/tpkt_x224.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <netinet/in.h>
#include <poll.h>
#include <span>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <algorithm>

namespace
{
class OwnedSocket final
{
public:
    explicit OwnedSocket(int descriptor = -1) noexcept
        : descriptor_(descriptor) {}
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

constexpr auto kConnectionDeadline = std::chrono::seconds(5);

// An overall monotonic timeout rather than a per-read timeout, so a slowly
// dribbling local peer cannot extend the lifetime indefinitely.
[[nodiscard]] bool waitReadable(
    int descriptor, std::chrono::steady_clock::time_point deadline) noexcept
{
    for (;;)
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
        {
            return false;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        pollfd requested{descriptor, POLLIN, 0};
        const int result = ::poll(&requested, 1,
                                  static_cast<int>(std::max<std::int64_t>(1, remaining.count())));
        if (result < 0 && errno == EINTR)
        {
            continue;
        }
        return result > 0 && (requested.revents & POLLIN) != 0;
    }
}

[[nodiscard]] bool receiveExact(
    int descriptor, std::span<std::uint8_t> output,
    std::chrono::steady_clock::time_point deadline) noexcept
{
    std::size_t received = 0;
    while (received < output.size())
    {
        if (!waitReadable(descriptor, deadline))
        {
            return false;
        }
        const ssize_t bytes = ::recv(descriptor, output.data() + received,
                                     output.size() - received, 0);
        if (bytes < 0 && errno == EINTR)
        {
            continue;
        }
        if (bytes <= 0)
        {
            return false;
        }
        received += static_cast<std::size_t>(bytes);
    }
    return true;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 1)
    {
        (void)argv;
        std::cerr << "loopback probe takes no arguments\n";
        return 2;
    }

    OwnedSocket listener(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (listener.get() < 0)
    {
        std::cerr << "could not create loopback socket\n";
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
        std::cerr << "could not bind private probe\n";
        return 2;
    }

    socklen_t addressBytes = sizeof(address);
    if (::getsockname(listener.get(), reinterpret_cast<sockaddr *>(&address),
                      &addressBytes) != 0 ||
        addressBytes != sizeof(address) ||
        address.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
    {
        std::cerr << "loopback-only socket identity failed\n";
        return 2;
    }

    // This line is machine-readable orchestration data, not diagnostic logging.
    std::cout << "LISTEN_LOOPBACK=" << ntohs(address.sin_port) << '\n' << std::flush;
    const auto deadline = std::chrono::steady_clock::now() + kConnectionDeadline;
    if (!waitReadable(listener.get(), deadline))
    {
        std::cerr << "probe accept deadline elapsed\n";
        return 2;
    }
    OwnedSocket client(::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC));
    if (client.get() < 0)
    {
        std::cerr << "probe accept failed\n";
        return 2;
    }

    // Additional defense against accidental address or socket reconfiguration.
    sockaddr_in peer{};
    socklen_t peerBytes = sizeof(peer);
    if (::getpeername(client.get(), reinterpret_cast<sockaddr *>(&peer),
                      &peerBytes) != 0 ||
        peerBytes != sizeof(peer) ||
        peer.sin_family != AF_INET ||
        peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
    {
        std::cerr << "probe rejected non-loopback peer\n";
        return 2;
    }

    std::array<std::uint8_t,
        rdp_server::server::transport::kMaximumConnectionRequestBytes> packet{};
    if (!receiveExact(client.get(), std::span(packet).first(4), deadline))
    {
        std::cerr << "incomplete TPKT header\n";
        return 1;
    }
    const auto length =
        rdp_server::server::transport::connectionRequestLength(
            std::span(packet).first(4));
    if (!length ||
        !receiveExact(client.get(), std::span(packet).subspan(4, *length - 4),
                      deadline))
    {
        std::cerr << "invalid or incomplete X.224 frame\n";
        return 1;
    }
    const auto result =
        rdp_server::server::transport::parseConnectionRequest(
            std::span(packet).first(*length));
    if (!result)
    {
        std::cerr << "invalid X.224 connection request\n";
        return 1;
    }
    // Success here means only syntax was parsed, NOT RDP client acceptance.
    // Closing before X.224 Confirmation is intentional while TLS, CredSSP and
    // session authorization are absent; never claim PROTOCOL_RDP support.
    return 0;
}
