// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <atomic>
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
    GenerationExhausted,
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

    // GUI-facing OS-account access lifecycle. Replacement publishes exactly
    // one new policy generation; every acceptor/lease bound to an older
    // generation consequently fails its existing freshness checks. No
    // password, Kerberos ticket, NTLM-equivalent verifier or OS-login result
    // is stored here. Rule mutation remains externally serialized.
    [[nodiscard]] ConsoleRuleError replaceSingle(
        const ConsoleIdentityRuleInput &rule) noexcept;

    // Remove every configured identity and publish a fresh revocation
    // generation. False is the terminal generation-exhaustion case: rules
    // are still erased and generation becomes zero so positive use fails
    // closed. Revocation itself is never host-user consent or authentication.
    [[nodiscard]] bool revokeAll() noexcept;

    // The caller supplies only a candidate observation; it is not evidence
    // the kernel, GSS provider, logind or X server verified these attributes.
    [[nodiscard]] ConsolePolicyMatch matchCandidate(
        const ConsoleIdentityRequest &request) const noexcept;

    // Read-only identity-only query for the final CredSSP boundary. This
    // deliberately ignores seat/display/UID/native evidence and can return
    // CandidateOnly only. expectedGeneration is the nonzero epoch captured
    // when this service-owned policy is bound to the GSS owner. If one
    // principal names different local accounts across rules, deny ambiguity.
    [[nodiscard]] ConsolePolicyMatch matchPrincipalAccountCandidate(
        std::string_view kerberosPrincipal,
        std::string_view unixAccount,
        std::uint64_t expectedGeneration) const noexcept;

    [[nodiscard]] std::size_t size() const noexcept { return count_; }

    // Monotonic configuration epoch used to revoke native admission leases.
    // Rule mutation itself remains externally serialized; this atomic epoch
    // is a revocation fence, not concurrent access to the rules array.
    [[nodiscard]] std::uint64_t generation() const noexcept
    {
        return generation_.load(std::memory_order_acquire);
    }

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
    [[nodiscard]] bool nextGeneration(
        std::uint64_t &next) const noexcept;
    void clearRules() noexcept;

    std::array<Rule, kMaximumConsoleIdentityRules> rules_{};
    std::size_t count_{};
    std::atomic<std::uint64_t> generation_{};
};

} // namespace rdp_server::server::security
