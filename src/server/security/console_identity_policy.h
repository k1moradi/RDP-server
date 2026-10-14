// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace rdp_server::server::security
{

// Policy matching is NOT authenticated admission. A real system service must
// independently prove GSS identity, UNIX account ownership, login-session
// provenance and local-console authorization before issuing any capability.
inline constexpr std::size_t kMaximumConsoleIdentityRules = 16;
inline constexpr std::uint32_t kConsoleViewPermission = 0x1U;
inline constexpr std::uint32_t kConsoleInputPermission = 0x2U;
inline constexpr std::uint32_t kConsoleClipboardPermission = 0x4U;
inline constexpr std::uint32_t kConsoleAllowedPermissions =
    kConsoleViewPermission | kConsoleInputPermission |
    kConsoleClipboardPermission;

enum class ConsoleRuleError : std::uint8_t
{
    None,
    InvalidRule,
    Duplicate,
    Full,
};

enum class ConsolePolicyMatch : std::uint8_t
{
    Denied,
    CandidateOnly, // NEVER a session authorization or admission token.
};

struct ConsoleIdentityRuleInput
{
    std::string_view kerberosPrincipal{};
    std::string_view unixAccount{};
    std::string_view seat{};
    std::string_view display{};
    std::uint32_t localUid{};
    std::uint32_t permissions{};
};

struct ConsoleIdentityRequest
{
    std::string_view kerberosPrincipal{};
    std::string_view unixAccount{};
    std::string_view seat{};
    std::string_view display{};
    std::uint32_t localUid{};
    std::uint32_t observedConsoleOwnerUid{};
    std::uint32_t requestedPermissions{};
};

// Fixed-capacity, owning policy. No on-disk config is loaded implicitly,
// no wildcard rules, PAM, NSS, logind, display socket or filesystem access.
class ConsoleIdentityPolicy final
{
public:
    ConsoleIdentityPolicy() noexcept = default;
    ConsoleIdentityPolicy(const ConsoleIdentityPolicy &) = delete;
    ConsoleIdentityPolicy &operator=(const ConsoleIdentityPolicy &) = delete;

    [[nodiscard]] ConsoleRuleError add(
        const ConsoleIdentityRuleInput &rule) noexcept;

    // The caller supplies only a candidate observation; it is not evidence
    // the kernel, GSS provider, logind or X server verified these attributes.
    [[nodiscard]] ConsolePolicyMatch matchCandidate(
        const ConsoleIdentityRequest &request) const noexcept;

    [[nodiscard]] std::size_t size() const noexcept { return count_; }

private:
    struct Rule
    {
        std::array<char, 129> principal{};
        std::array<char, 33> account{};
        std::array<char, 17> seat{};
        std::array<char, 9> display{};
        std::uint32_t uid{};
        std::uint32_t permissions{};
    };
    std::array<Rule, kMaximumConsoleIdentityRules> rules_{};
    std::size_t count_{};
};

} // namespace rdp_server::server::security
