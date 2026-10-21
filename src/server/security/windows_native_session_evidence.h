// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::security
{

inline constexpr std::size_t kMaximumWindowsNativeSidBytes = 68;

enum class WindowsNativeSessionEvidenceStatus : std::uint8_t
{
    Unavailable,
    Observed,
};

// Read-only candidate evidence from the running Windows process and its
// physical interactive WTS logon session. This is NOT authentication and NOT
// an admission capability. A genuine R2 SSPI/CredSSP provider must privately
// bind its authenticated user SID to userSid before a lease can be issued.
struct WindowsNativeSessionEvidence final
{
    std::array<std::byte, kMaximumWindowsNativeSidBytes> userSid{};
    std::size_t userSidBytes{};
    std::uint32_t sessionId{};
    std::uint32_t authenticationIdLow{};
    std::int32_t authenticationIdHigh{};
    std::int64_t logonTime100Nanoseconds{};
    std::uint32_t logonType{};

    [[nodiscard]] bool matchesAuthenticatedSid(
        std::span<const std::byte> authenticatedSid) const noexcept;
    [[nodiscard]] bool sameNativeSession(
        const WindowsNativeSessionEvidence &other) const noexcept;
};

// Read-only evidence source. Injection exists for deterministic R2 authorization
// tests only; a production native grant is composed with the concrete reader.
class WindowsNativeSessionEvidenceSource
{
public:
    virtual ~WindowsNativeSessionEvidenceSource() = default;
    WindowsNativeSessionEvidenceSource() = default;
    WindowsNativeSessionEvidenceSource(
        const WindowsNativeSessionEvidenceSource &) = delete;
    WindowsNativeSessionEvidenceSource &operator=(
        const WindowsNativeSessionEvidenceSource &) = delete;

    [[nodiscard]] virtual WindowsNativeSessionEvidenceStatus readCurrent(
        WindowsNativeSessionEvidence &evidence) const noexcept = 0;
};

// Least-privilege personal-desktop adapter. The process itself must run in the
// user's physical interactive WTS session. Service Session 0 is unavailable;
// a future LocalSystem/WTSQueryUserToken design requires separate review.
class WindowsNativeSessionEvidenceReader final
    : public WindowsNativeSessionEvidenceSource
{
public:
    [[nodiscard]] WindowsNativeSessionEvidenceStatus readCurrent(
        WindowsNativeSessionEvidence &evidence) const noexcept override;
};

} // namespace rdp_server::server::security
