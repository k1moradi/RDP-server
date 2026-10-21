// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace rdp_server::server::security
{

enum class MacNativeSessionEvidenceStatus : std::uint8_t
{
    Unavailable,
    Observed,
};

inline constexpr std::size_t kMaximumMacNativeConsoleUserBytes = 255;

// Read-only candidate evidence for the caller's local graphical console
// session. This does NOT authenticate an RDP user and cannot mint admission.
struct MacNativeSessionEvidence final
{
    std::array<char, kMaximumMacNativeConsoleUserBytes + 1> consoleUser{};
    std::size_t consoleUserBytes{};
    std::uint32_t consoleUserId{};
    std::uint32_t auditUserId{};
    std::uint64_t auditSessionId{};
    std::uint32_t securitySessionId{};
    std::uint32_t securitySessionAttributes{};

    [[nodiscard]] std::string_view consoleUserName() const noexcept
    {
        return consoleUserBytes != 0 &&
                       consoleUserBytes <= kMaximumMacNativeConsoleUserBytes
                   ? std::string_view(consoleUser.data(), consoleUserBytes)
                   : std::string_view{};
    }

    [[nodiscard]] bool matchesAuthenticatedUserId(
        std::uint32_t authenticatedUserId) const noexcept;
    [[nodiscard]] bool sameNativeSession(
        const MacNativeSessionEvidence &other) const noexcept;
};

class MacNativeSessionEvidenceSource
{
public:
    virtual ~MacNativeSessionEvidenceSource() = default;
    MacNativeSessionEvidenceSource() = default;
    MacNativeSessionEvidenceSource(
        const MacNativeSessionEvidenceSource &) = delete;
    MacNativeSessionEvidenceSource &operator=(
        const MacNativeSessionEvidenceSource &) = delete;

    [[nodiscard]] virtual MacNativeSessionEvidenceStatus readCurrent(
        MacNativeSessionEvidence &evidence) const noexcept = 0;
};

class MacNativeSessionEvidenceReader final
    : public MacNativeSessionEvidenceSource
{
public:
    [[nodiscard]] MacNativeSessionEvidenceStatus readCurrent(
        MacNativeSessionEvidence &evidence) const noexcept override;
};

} // namespace rdp_server::server::security
