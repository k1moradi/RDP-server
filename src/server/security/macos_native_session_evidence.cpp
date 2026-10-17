// SPDX-License-Identifier: GPL-3.0-or-later
#include "macos_native_session_evidence.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/AuthSession.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <bsm/audit.h>
#include <unistd.h>

#include <limits>

namespace rdp_server::server::security
{

bool MacNativeSessionEvidence::matchesAuthenticatedUserId(
    std::uint32_t authenticatedUserId) const noexcept
{
    return authenticatedUserId != 0 &&
           consoleUserId == authenticatedUserId &&
           auditUserId == authenticatedUserId &&
           auditSessionId != 0 &&
           securitySessionId != 0;
}

bool MacNativeSessionEvidence::sameNativeSession(
    const MacNativeSessionEvidence &other) const noexcept
{
    return consoleUserId != 0 &&
           consoleUserId == other.consoleUserId &&
           auditUserId == other.auditUserId &&
           auditSessionId == other.auditSessionId &&
           securitySessionId == other.securitySessionId &&
           securitySessionAttributes == other.securitySessionAttributes;
}

MacNativeSessionEvidenceStatus
MacNativeSessionEvidenceReader::readCurrent(
    MacNativeSessionEvidence &evidence) const noexcept
{
    evidence = {};

    uid_t consoleUserId = static_cast<uid_t>(-1);
    gid_t consoleGroupId = static_cast<gid_t>(-1);
    CFStringRef consoleUser = ::SCDynamicStoreCopyConsoleUser(
        nullptr, &consoleUserId, &consoleGroupId);
    if (consoleUser == nullptr)
    {
        return MacNativeSessionEvidenceStatus::Unavailable;
    }
    ::CFRelease(consoleUser);

    const uid_t effectiveUserId = ::geteuid();
    if (consoleUserId == 0 ||
        consoleUserId == static_cast<uid_t>(-1) ||
        effectiveUserId != consoleUserId ||
        static_cast<std::uint64_t>(consoleUserId) >
            std::numeric_limits<std::uint32_t>::max())
    {
        return MacNativeSessionEvidenceStatus::Unavailable;
    }

    auditinfo_addr_t auditInfo{};
    if (::getaudit_addr(
            &auditInfo, static_cast<int>(sizeof(auditInfo))) != 0 ||
        auditInfo.ai_auid == static_cast<au_id_t>(-1) ||
        auditInfo.ai_asid <= 0 ||
        static_cast<std::uint64_t>(auditInfo.ai_auid) !=
            static_cast<std::uint64_t>(consoleUserId))
    {
        return MacNativeSessionEvidenceStatus::Unavailable;
    }

    SecuritySessionId securitySessionId = noSecuritySession;
    SessionAttributeBits attributes = 0;
    if (::SessionGetInfo(
            callerSecuritySession, &securitySessionId, &attributes) !=
            errSecSuccess ||
        securitySessionId == noSecuritySession ||
        (attributes & sessionHasGraphicAccess) == 0 ||
        (attributes & sessionIsRemote) != 0 ||
        (attributes & sessionIsRoot) != 0)
    {
        return MacNativeSessionEvidenceStatus::Unavailable;
    }

    evidence.consoleUserId =
        static_cast<std::uint32_t>(consoleUserId);
    evidence.auditUserId =
        static_cast<std::uint32_t>(auditInfo.ai_auid);
    evidence.auditSessionId =
        static_cast<std::uint64_t>(auditInfo.ai_asid);
    evidence.securitySessionId =
        static_cast<std::uint32_t>(securitySessionId);
    evidence.securitySessionAttributes =
        static_cast<std::uint32_t>(attributes);
    return MacNativeSessionEvidenceStatus::Observed;
}

} // namespace rdp_server::server::security
