// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/authentication_attempt_limiter.h"

#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

using rdp_server::server::security::AuthenticationAttemptLimiter;

void testVerifiedAccountTableExhaustion()
{
    using Limit = AuthenticationAttemptLimiter;
    const Limit::TimePoint start{};
    Limit limiter;

    // Exactly the bounded number of distinct provider-verified principals
    // may occupy the table. An unexpired slot is never evicted to admit
    // a new principal and thereby reset an existing failed-attempt budget.
    for (std::size_t i = 0; i < Limit::kMaximumTrackedAccounts; ++i)
    {
        const std::string principal =
            std::string("user") + std::to_string(i) + "@EXAMPLE.TEST";
        assert(limiter.reserveVerifiedAccountAttempt(principal, start));
    }
    constexpr std::string_view overflow{"overflow@EXAMPLE.TEST"};
    assert(!limiter.reserveVerifiedAccountAttempt(overflow, start));
    assert(!limiter.reserveVerifiedAccountAttempt(
        overflow, start + Limit::kAttemptWindow - std::chrono::seconds{1}));
    assert(!limiter.reserveVerifiedAccountAttempt(
        overflow, start - std::chrono::seconds{1}));

    // Existing exact identities retain their own budget while slots
    // are full. Neither reconnect nor saturation may refund attempts.
    for (std::size_t i = 1; i < Limit::kMaximumAccountAttempts; ++i)
    {
        assert(limiter.reserveVerifiedAccountAttempt(
            "user0@EXAMPLE.TEST", start));
    }
    assert(!limiter.reserveVerifiedAccountAttempt(
        "user0@EXAMPLE.TEST", start));

    // Invalid principal strings never free a live entry or consume slots.
    constexpr std::string_view withNul{"user\0@EXAMPLE.TEST", 17U};
    assert(!limiter.reserveVerifiedAccountAttempt(withNul, start));
    assert(!limiter.reserveVerifiedAccountAttempt(
        "bad principal@EXAMPLE.TEST", start));
    assert(!limiter.reserveVerifiedAccountAttempt(
        std::string(129U, 'x'), start));
    assert(!limiter.reserveVerifiedAccountAttempt(
        std::string(1U, static_cast<char>(0xff)), start));

    // A complete monotonic-window expiry permits reusing retired slots
    // with reset accounting; an earlier overflow is not permanent denial.
    assert(limiter.reserveVerifiedAccountAttempt(
        overflow, start + Limit::kAttemptWindow));
    assert(limiter.reserveVerifiedAccountAttempt(
        "user0@EXAMPLE.TEST", start + Limit::kAttemptWindow));

    // Exact byte identity remains case-sensitive and max-length is allowed.
    Limit exact;
    assert(exact.reserveVerifiedAccountAttempt(
        "Alice@EXAMPLE.TEST", start));
    assert(exact.reserveVerifiedAccountAttempt(
        "alice@EXAMPLE.TEST", start));
    assert(exact.reserveVerifiedAccountAttempt(
        std::string(Limit::kMaximumAccountBytes, 'A'), start));
    assert(!exact.reserveVerifiedAccountAttempt(
        std::string(Limit::kMaximumAccountBytes + 1U, 'A'), start));

    // Account table saturation never overrides the independent peer/global
    // reservation policy of the same service-owned limiter.
    constexpr std::array<std::uint8_t, 4> peer{127U, 0U, 0U, 1U};
    assert(limiter.reservePeerAuthenticationAttempt(peer, start));
}

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;

    if (std::string_view(argv[1]) == "verified-account-table-exhaustion")
    {
        testVerifiedAccountTableExhaustion();
        return 0;
    }
    if (std::string_view(argv[1]) !=
        "bounded-peer-global-and-account-attempts")
        return 2;

    using Limit = AuthenticationAttemptLimiter;
    const Limit::TimePoint start{};
    constexpr std::array<std::uint8_t, 4> ipv4{127U, 0U, 0U, 1U};
    constexpr std::array<std::uint8_t, 16> ipv6{
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};

    // Invalid and regressing requests never consume or reset a peer budget.
    Limit peers;
    assert(!peers.reservePeerAuthenticationAttempt({}, start));
    assert(!peers.reservePeerAuthenticationAttempt(
        std::span<const std::uint8_t>{ipv6}.first(5), start));
    for (std::size_t i = 0; i < Limit::kMaximumPeerAttempts; ++i)
        assert(peers.reservePeerAuthenticationAttempt(ipv4, start));
    assert(!peers.reservePeerAuthenticationAttempt(ipv4, start));
    assert(!peers.reservePeerAuthenticationAttempt(
        ipv4, start - std::chrono::seconds{1}));
    assert(peers.reservePeerAuthenticationAttempt(ipv6, start));
    assert(peers.reservePeerAuthenticationAttempt(
        ipv4, start + Limit::kAttemptWindow));
    for (std::size_t i = 1; i < Limit::kMaximumPeerAttempts; ++i)
        assert(peers.reservePeerAuthenticationAttempt(
            ipv4, start + Limit::kAttemptWindow));
    assert(!peers.reservePeerAuthenticationAttempt(
        ipv4, start + Limit::kAttemptWindow));

    // Distinct peer addresses share one global budget even when every peer
    // has remaining per-address quota.
    Limit global;
    for (std::size_t i = 0; i < Limit::kMaximumGlobalAttempts; ++i)
    {
        const std::array<std::uint8_t, 4> address{
            127U, 0U, 0U,
            static_cast<std::uint8_t>(i / Limit::kMaximumPeerAttempts + 1U)};
        assert(global.reservePeerAuthenticationAttempt(address, start));
    }
    constexpr std::array<std::uint8_t, 4> afterGlobal{
        127U, 0U, 0U, 32U};
    assert(!global.reservePeerAuthenticationAttempt(afterGlobal, start));
    assert(global.reservePeerAuthenticationAttempt(
        afterGlobal, start + Limit::kAttemptWindow));

    // Fixed occupancy denies a 65th live peer rather than evicting an
    // unexpired entry to evade per-peer tracking.
    Limit capacity;
    for (std::size_t i = 0; i < Limit::kMaximumTrackedPeers; ++i)
    {
        const std::array<std::uint8_t, 4> address{
            10U, 1U, 0U, static_cast<std::uint8_t>(i + 1U)};
        assert(capacity.reservePeerAuthenticationAttempt(address, start));
    }
    constexpr std::array<std::uint8_t, 4> overflow{10U, 1U, 0U, 65U};
    assert(!capacity.reservePeerAuthenticationAttempt(overflow, start));
    assert(capacity.reservePeerAuthenticationAttempt(
        overflow, start + Limit::kAttemptWindow));

    // Account counters are independent of the presenting peer. Account
    // inputs must come from a genuine provider identity, never GUI text.
    Limit accounts;
    for (std::size_t i = 0; i < Limit::kMaximumAccountAttempts; ++i)
        assert(accounts.reserveVerifiedAccountAttempt(
            "alice@EXAMPLE.TEST", start));
    assert(!accounts.reserveVerifiedAccountAttempt("alice@EXAMPLE.TEST", start));
    assert(!accounts.reserveVerifiedAccountAttempt(
        "alice@EXAMPLE.TEST", start - std::chrono::seconds{1}));
    assert(accounts.reserveVerifiedAccountAttempt("bob@EXAMPLE.TEST", start));
    assert(!accounts.reserveVerifiedAccountAttempt("", start));
    assert(!accounts.reserveVerifiedAccountAttempt("invalid user", start));
    assert(!accounts.reserveVerifiedAccountAttempt(
        std::string(Limit::kMaximumAccountBytes + 1U, 'x'), start));
    assert(accounts.reserveVerifiedAccountAttempt(
        "alice@EXAMPLE.TEST", start + Limit::kAttemptWindow));

    return 0;
}
