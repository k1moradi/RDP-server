// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

enum class LinuxPamPasswordVerificationStatus : std::uint8_t
{
    Authorized,
    Denied,
    InvalidInput,
    ProviderFailure,
};

// Linux-only OS credential verifier boundary. This object does not know about
// RDP, TLS, GSS principals, console sessions or admission leases. R2 must
// establish those independent facts before a future integration may treat an
// Authorized result as one ingredient of its private completion proof.
//
// All calls are externally serialized. Configuration is explicit and one-shot;
// no default PAM service is consulted. Password input is bounded UTF-16LE and
// is converted only into a verifier-owned, stack-resident UTF-8 buffer that is
// cleansed before verify() returns. PAM may make its own provider-owned copy
// while servicing its conversation callback; this class never retains one.
class LinuxPamPasswordVerifier final
{
public:
    LinuxPamPasswordVerifier() noexcept = default;
    LinuxPamPasswordVerifier(const LinuxPamPasswordVerifier &) = delete;
    LinuxPamPasswordVerifier &operator=(const LinuxPamPasswordVerifier &) = delete;
    LinuxPamPasswordVerifier(LinuxPamPasswordVerifier &&) = delete;
    LinuxPamPasswordVerifier &operator=(LinuxPamPasswordVerifier &&) = delete;

    [[nodiscard]] bool configure(std::string_view serviceName) noexcept;

    [[nodiscard]] LinuxPamPasswordVerificationStatus verify(
        std::string_view unixAccount,
        std::span<const std::uint8_t> passwordUtf16Le) const noexcept;

    [[nodiscard]] bool configured() const noexcept { return configured_; }
    [[nodiscard]] std::string_view serviceName() const noexcept
    {
        return configured_
            ? std::string_view(serviceName_.data(), serviceNameLength_)
            : std::string_view{};
    }

private:
    std::array<char, 65> serviceName_{};
    std::size_t serviceNameLength_{};
    bool attempted_{};
    bool configured_{};
};

} // namespace rdp_server::server::security
