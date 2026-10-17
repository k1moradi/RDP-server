// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace rdp_server::server::security
{

enum class MacNativeSessionEvidenceStatus : std::uint8_t
{
    Unavailable,
    Observed,
};

// Read-only candidate evidence for the caller's local graphical console
// session. This does NOT authenticate an RDP user and cannot mint admission.
struct MacNativeSessionEvidence final
{
    std::uint32_t consoleUserId{};
    std::uint32_t auditUserId{};
    std::uint64_t auditSessionId{};
    std::uint32_t securitySessionId{};
    std::uint32_t securitySessionAttributes{};

    [[nodiscard]] bool matchesAuthenticatedUserId(
        std::uint32_t authenticatedUserId) const noexcept;
    [[nodiscard]] bool sameNativeSession(
        const MacNativeSessionEvidence &other) const noexcept;
};

class MacNativeSessionEvidenceReader final
{
public:
    [[nodiscard]] MacNativeSessionEvidenceStatus readCurrent(
        MacNativeSessionEvidence &evidence) const noexcept;
};

} // namespace rdp_server::server::security
