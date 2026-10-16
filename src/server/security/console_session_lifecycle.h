// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace rdp_server::server::security
{

enum class ConsoleLifecycleState : std::uint8_t
{
    NotObserved,
    CandidateOnly, // NEVER a live/authorized desktop session.
    Revoked,       // Terminal for the lifetime of this monitor.
};

// Per-connection, noncopyable, fixed-capacity *candidate* lifecycle monitor.
// Does not hold or grant an authorization capability, GSS context, or X11
// handle. Source and policy are borrowed only for each synchronous call.
// Callers must serialize use; no concurrently executing methods, no worker
// thread, no background monitoring and no notification subscription.
// In a future live service, an actual supervisor must provide atomic
// admission/revocation and teardown; polling here is NOT sufficient.
class ConsoleSessionLifecycleMonitor final
{
public:
    ConsoleSessionLifecycleMonitor() noexcept = default;
    ConsoleSessionLifecycleMonitor(const ConsoleSessionLifecycleMonitor &) = delete;
    ConsoleSessionLifecycleMonitor &operator=(const ConsoleSessionLifecycleMonitor &) = delete;

    // An initial negative observation irrevocably revokes this monitor.
    // The caller's request strings are copied into fixed-capacity storage.
    [[nodiscard]] ConsoleLifecycleState observe(
        const ConsoleIdentityPolicy &policy,
        const ConsoleEvidenceRequest &request,
        ConsoleOsEvidenceSource &source) noexcept;

    // Must be invoked explicitly. Re-reads policy, NSS and console source.
    // Any changed session/UID, disappeared account, expired observation,
    // clock regression or denied policy causes terminal revocation.
    [[nodiscard]] ConsoleLifecycleState revalidate(
        const ConsoleIdentityPolicy &policy,
        ConsoleOsEvidenceSource &source) noexcept;

    void revoke() noexcept;

    [[nodiscard]] ConsoleLifecycleState state() const noexcept
    {
        return state_;
    }

private:
    [[nodiscard]] ConsoleEvidenceRequest requestView() const noexcept;

    std::array<char, 129> kerberosPrincipal_{};
    std::array<char, 33> unixAccount_{};
    std::array<char, 17> seat_{};
    std::array<char, 9> display_{};
    std::size_t kerberosPrincipalLength_{};
    std::size_t unixAccountLength_{};
    std::size_t seatLength_{};
    std::size_t displayLength_{};
    std::uint32_t requestedPermissions_{};
    ConsoleCandidateSessionFingerprint fingerprint_{};
    ConsoleLifecycleState state_{ConsoleLifecycleState::NotObserved};
};

} // namespace rdp_server::server::security
