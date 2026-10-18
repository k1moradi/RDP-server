// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

// Service-lifetime, fixed-capacity protection against repeated NLA attempts.
// The serialized listener owns this object: methods are NOT thread-safe and
// callers must not share it between concurrent event-loop threads. It has no
// socket, credential, GSS, OS admission, log or allocation side effects.
//
// Call reservePeerAuthenticationAttempt BEFORE opening an R1 TLS/GSS owner.
// After genuine provider authentication of a user principal (not a claimed
// username), reserveVerifiedAccountAttempt before checking delegated secrets.
// The account gate is separate: it must never be fed unverified client text.
// No positive result is an authentication, native lease or Share capability.
class AuthenticationAttemptLimiter final
{
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    static constexpr std::size_t kMaximumTrackedPeers = 64U;
    static constexpr std::size_t kMaximumTrackedAccounts = 64U;
    static constexpr std::size_t kMaximumAccountBytes = 128U;
    static constexpr std::uint16_t kMaximumPeerAttempts = 8U;
    static constexpr std::uint16_t kMaximumAccountAttempts = 8U;
    static constexpr std::uint16_t kMaximumGlobalAttempts = 128U;
    static constexpr auto kAttemptWindow = std::chrono::seconds{60};

    AuthenticationAttemptLimiter() noexcept = default;
    AuthenticationAttemptLimiter(const AuthenticationAttemptLimiter &) = delete;
    AuthenticationAttemptLimiter &operator=(const AuthenticationAttemptLimiter &) = delete;

    // Accept only exact, already-validated IPv4 (4 bytes) or IPv6 (16 bytes).
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) is the same peer as native IPv4:
    // keeping the two encodings separate would double the per-peer budget
    // on dual-stack listeners. Unmapped IPv6 still keeps all 16 bytes.
    // A new address is rejected if all tracked slots are still live. Charged
    // attempts cannot be refunded by disconnect/retry, so a failed TLS/NTLM
    // exchange cannot escape its bound by reconnecting immediately.
    [[nodiscard]] bool reservePeerAuthenticationAttempt(
        std::span<const std::uint8_t> address, TimePoint now) noexcept
    {
        if ((address.size() != 4U && address.size() != 16U) ||
            !globalAttemptAvailable(now))
            return false;

        // Canonicalize only the RFC 4291 IPv4-mapped IPv6 prefix, never
        // arbitrary 16-byte IPv6 addresses. No allocation, shared cache or
        // socket-family assumptions enter this R2 security boundary.
        auto peer = address;
        if (address.size() == 16U &&
            std::all_of(address.begin(), address.begin() + 10,
                        [](std::uint8_t octet) noexcept {
                            return octet == 0U;
                        }) &&
            address[10] == 0xffU && address[11] == 0xffU)
        {
            peer = address.subspan(12U, 4U);
        }

        auto *slot = findOrReuseSlot(
            peers_, now, [peer](const PeerSlot &entry) noexcept {
                return entry.addressLength == peer.size() &&
                    std::equal(peer.begin(), peer.end(),
                               entry.address.begin());
            });
        if (slot == nullptr || slot->window.attempts >= kMaximumPeerAttempts)
            return false;

        if (slot->addressLength == 0U)
        {
            std::copy(peer.begin(), peer.end(), slot->address.begin());
            slot->addressLength = static_cast<std::uint8_t>(peer.size());
        }

        ++slot->window.attempts;
        if (!global_.active || now - global_.start >= kAttemptWindow)
            global_ = {true, now, 1U};
        else
            ++global_.attempts;
        return true;
    }

    // Only for a provider-verified principal; do not expose this as a GUI
    // password check. The account is a bounded, non-secret identity string
    // kept only in service RAM; nothing is persisted, hashed or logged here.
    [[nodiscard]] bool reserveVerifiedAccountAttempt(
        std::string_view verifiedPrincipal, TimePoint now) noexcept
    {
        if (verifiedPrincipal.empty() ||
            verifiedPrincipal.size() > kMaximumAccountBytes ||
            !std::all_of(verifiedPrincipal.begin(), verifiedPrincipal.end(),
                         [](unsigned char character) noexcept {
                             return character >= 0x21U && character <= 0x7eU;
                         }))
            return false;

        auto *slot = findOrReuseSlot(
            accounts_, now, [verifiedPrincipal](const AccountSlot &entry) noexcept {
                return entry.accountLength == verifiedPrincipal.size() &&
                    std::string_view(entry.account.data(),
                                     entry.accountLength) == verifiedPrincipal;
            });
        if (slot == nullptr ||
            slot->window.attempts >= kMaximumAccountAttempts)
            return false;

        if (slot->accountLength == 0U)
        {
            std::copy(verifiedPrincipal.begin(), verifiedPrincipal.end(),
                      slot->account.begin());
            slot->accountLength =
                static_cast<std::uint8_t>(verifiedPrincipal.size());
        }

        ++slot->window.attempts;
        return true;
    }

private:
    struct Window
    {
        bool active{};
        TimePoint start{};
        std::uint16_t attempts{};
    };

    struct PeerSlot
    {
        Window window{};
        std::array<std::uint8_t, 16U> address{};
        std::uint8_t addressLength{};
    };

    struct AccountSlot
    {
        Window window{};
        std::array<char, kMaximumAccountBytes> account{};
        std::uint8_t accountLength{};
    };

    [[nodiscard]] bool globalAttemptAvailable(TimePoint now) const noexcept
    {
        if (!global_.active)
            return true;
        if (now < global_.start)
            return false; // Never let regressing test/provider clocks reset limits.
        return now - global_.start >= kAttemptWindow ||
               global_.attempts < kMaximumGlobalAttempts;
    }

    template <typename Slot, std::size_t Capacity, typename Matches>
    [[nodiscard]] static Slot *findOrReuseSlot(
        std::array<Slot, Capacity> &slots, TimePoint now,
        Matches matches) noexcept
    {
        Slot *reusable = nullptr;
        for (auto &slot : slots)
        {
            if (!slot.window.active)
            {
                if (reusable == nullptr)
                    reusable = &slot;
                continue;
            }
            if (now < slot.window.start)
                return nullptr; // Invalid monotonic ordering: fail closed.
            if (now - slot.window.start >= kAttemptWindow)
            {
                if (reusable == nullptr)
                    reusable = &slot;
                continue;
            }
            if (matches(slot))
                return &slot;
        }

        if (reusable == nullptr)
            return nullptr;
        *reusable = Slot{}; // Erase retired identity/address before reuse.
        reusable->window = {true, now, 0U};
        return reusable;
    }

    Window global_{};
    std::array<PeerSlot, kMaximumTrackedPeers> peers_{};
    std::array<AccountSlot, kMaximumTrackedAccounts> accounts_{};
};

} // namespace rdp_server::server::security
