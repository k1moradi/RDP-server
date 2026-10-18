// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string_view>

namespace rdp_server::server::runtime
{

// Pure preflight only. It cannot authorize a listener or an OS session.
// Bind still validates SO_ACCEPTCONN and the exact getsockname address/port.
[[nodiscard]] constexpr bool isEligibleLinuxLoopbackListenerEndpoint(
    std::string_view address, std::uint16_t port) noexcept
{
    return port != 0U &&
           (address == "127.0.0.1" || address == "::1");
}

// The only Linux listener descriptor owner; callers of the R10 GUI backend
// must reuse this instead of adopting another native socket owner. No hidden
// bind/listen in construction and no copy/move while the poller borrows it.
class LinuxListenerOwner final
{
public:
    explicit LinuxListenerOwner(int descriptor) noexcept
        : descriptor_(descriptor) {}
    LinuxListenerOwner(const LinuxListenerOwner&) = delete;
    LinuxListenerOwner& operator=(const LinuxListenerOwner&) = delete;
    LinuxListenerOwner(LinuxListenerOwner&&) = delete;
    LinuxListenerOwner& operator=(LinuxListenerOwner&&) = delete;
    ~LinuxListenerOwner() noexcept;

    [[nodiscard]] int descriptor() const noexcept { return descriptor_; }
    [[nodiscard]] int release() noexcept
    {
        const int value = descriptor_;
        descriptor_ = -1;
        return value;
    }

private:
    int descriptor_{-1};
};

[[nodiscard]] bool hasLinuxServeDescriptorBudget(unsigned acceptBudget) noexcept;

// Returns a caller-owned NONBLOCKING+CLOEXEC descriptor only after verifying
// literal loopback policy, stream/listen role and exact kernel bound endpoint.
// Does not authenticate a client or activate an OS desktop; never call before
// the existing R10 pre-listener security/credential provision succeeds.
[[nodiscard]] int openVerifiedLinuxLoopbackListener(
    std::string_view listenAddress, std::uint16_t listenPort) noexcept;

} // namespace rdp_server::server::runtime
