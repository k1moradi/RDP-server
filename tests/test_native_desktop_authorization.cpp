// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/native_desktop_authorization.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>

namespace
{

using namespace rdp_server::server::security;

static_assert(!std::is_copy_constructible_v<
              WindowsNativeDesktopAuthorizationView>);
static_assert(!std::is_move_constructible_v<
              WindowsNativeDesktopAuthorizationView>);
static_assert(!std::is_copy_constructible_v<
              MacNativeDesktopAuthorizationView>);
static_assert(!std::is_move_constructible_v<
              MacNativeDesktopAuthorizationView>);
static_assert(!std::is_copy_constructible_v<
              WindowsNativeDesktopAuthorization>);
static_assert(!std::is_copy_constructible_v<
              MacNativeDesktopAuthorization>);

class FakeOwnerEvidenceSource final : public ConsoleOsEvidenceSource
{
public:
    ConsoleSessionObservation session{
        ConsoleEvidenceReadStatus::Observed,
        "owner-session",
        "seat0",
        ":0",
        1000U,
        7U,
        1000U,
        true,
        true,
        1000U,
        ConsoleDesktopLockState::Unlocked,
        false};
    std::optional<std::uint64_t> now{1000U};

    [[nodiscard]] ConsoleAccountObservation readUnixAccount(
        std::string_view /* account */) noexcept override
    {
        return {};
    }

    [[nodiscard]] ConsoleSessionObservation readActiveConsole() noexcept override
    {
        return session;
    }

    [[nodiscard]] std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override
    {
        return now;
    }
};

class OwnerFixture final
{
public:
    OwnerFixture() : authority(evidence)
    {
        grant(kConsoleViewPermission | kConsoleInputPermission);
    }

    void grant(std::uint32_t permissions)
    {
        evidence.session.observedAtMonotonicMilliseconds = *evidence.now;
        const OwnerSharingIntent intent{
            permissions,
            60'000U};
        assert(authority.requestConsent(intent) ==
               OwnerConsentRequestResult::Granted);
    }

    FakeOwnerEvidenceSource evidence{};
    CurrentOwnerSharingAuthority authority;
};

[[nodiscard]] WindowsNativeSessionEvidence makeWindowsEvidence() noexcept
{
    WindowsNativeSessionEvidence evidence{};
    evidence.userSid[0] = std::byte{0x01};
    evidence.userSid[1] = std::byte{0x05};
    evidence.userSid[2] = std::byte{0x15};
    evidence.userSid[3] = std::byte{0x2A};
    evidence.userSidBytes = 4;
    evidence.sessionId = 42U;
    evidence.authenticationIdLow = 101U;
    evidence.authenticationIdHigh = 202;
    evidence.logonTime100Nanoseconds = 303;
    evidence.logonType = 2U;
    return evidence;
}

class FakeWindowsEvidenceSource final
    : public WindowsNativeSessionEvidenceSource
{
public:
    WindowsNativeSessionEvidenceStatus status{
        WindowsNativeSessionEvidenceStatus::Observed};
    WindowsNativeSessionEvidence evidence{makeWindowsEvidence()};

    [[nodiscard]] WindowsNativeSessionEvidenceStatus readCurrent(
        WindowsNativeSessionEvidence &output) const noexcept override
    {
        output = status == WindowsNativeSessionEvidenceStatus::Observed
                     ? evidence
                     : WindowsNativeSessionEvidence{};
        return status;
    }
};

class FakeWindowsAuthenticatedIdentity final
    : public WindowsAuthenticatedIdentityProof
{
public:
    FakeWindowsAuthenticatedIdentity()
    {
        const auto evidence = makeWindowsEvidence();
        std::copy_n(
            evidence.userSid.begin(), evidence.userSidBytes, sid.begin());
        sidBytes = evidence.userSidBytes;
    }

    [[nodiscard]] std::uint64_t authenticationGeneration()
        const noexcept override
    {
        return generation;
    }

    [[nodiscard]] bool matchesAuthenticatedSid(
        std::span<const std::byte> candidate) const noexcept override
    {
        return candidate.size() == sidBytes &&
               std::equal(candidate.begin(), candidate.end(), sid.begin());
    }

    std::array<std::byte, kMaximumWindowsNativeSidBytes> sid{};
    std::size_t sidBytes{};
    std::uint64_t generation{11U};
};

[[nodiscard]] MacNativeSessionEvidence makeMacEvidence() noexcept
{
    MacNativeSessionEvidence evidence{};
    constexpr std::string_view consoleUser{"owner"};
    std::copy(consoleUser.begin(), consoleUser.end(),
              evidence.consoleUser.begin());
    evidence.consoleUserBytes = consoleUser.size();
    evidence.consoleUserId = 501U;
    evidence.auditUserId = 501U;
    evidence.auditSessionId = 77U;
    evidence.securitySessionId = 88U;
    evidence.securitySessionAttributes = 0x10U;
    return evidence;
}

class FakeMacEvidenceSource final : public MacNativeSessionEvidenceSource
{
public:
    MacNativeSessionEvidenceStatus status{
        MacNativeSessionEvidenceStatus::Observed};
    MacNativeSessionEvidence evidence{makeMacEvidence()};

    [[nodiscard]] MacNativeSessionEvidenceStatus readCurrent(
        MacNativeSessionEvidence &output) const noexcept override
    {
        output = status == MacNativeSessionEvidenceStatus::Observed
                     ? evidence
                     : MacNativeSessionEvidence{};
        return status;
    }
};

class FakeMacAuthenticatedIdentity final : public MacAuthenticatedIdentityProof
{
public:
    [[nodiscard]] std::uint64_t authenticationGeneration()
        const noexcept override
    {
        return generation;
    }

    [[nodiscard]] bool matchesAuthenticatedUserId(
        std::uint32_t candidate) const noexcept override
    {
        return candidate == userId;
    }

    std::uint32_t userId{501U};
    std::uint64_t generation{12U};
};

struct WindowsPositiveVisit final
{
    bool called{};
    std::uint64_t expectedAuthorizationGeneration{};
};

[[nodiscard]] bool inspectWindowsAuthorization(
    const WindowsNativeDesktopAuthorizationView &authorization,
    void *context) noexcept
{
    auto &visit = *static_cast<WindowsPositiveVisit *>(context);
    visit.called = true;
    assert(authorization.authenticationKind() ==
           NativeDesktopAuthenticationKind::ExistingOsAccount);
    assert(authorization.authenticatedSid().size() == 4);
    assert(authorization.wtsSessionId() == 42U);
    assert(authorization.authenticationIdLow() == 101U);
    assert(authorization.authenticationIdHigh() == 202);
    assert(authorization.logonTime100Nanoseconds() == 303);
    assert(authorization.permissionMask() ==
           (kConsoleViewPermission | kConsoleInputPermission));
    assert(authorization.authenticationGeneration() == 11U);
    assert(authorization.authorizationGeneration() ==
           visit.expectedAuthorizationGeneration);
    assert(authorization.ownerAuthorizationEpoch().grantGeneration != 0);
    assert(authorization.ownerAuthorizationEpoch().revocationGeneration != 0);
    return true;
}

struct MacPositiveVisit final
{
    bool called{};
    std::uint64_t expectedAuthorizationGeneration{};
};

[[nodiscard]] bool inspectMacAuthorization(
    const MacNativeDesktopAuthorizationView &authorization,
    void *context) noexcept
{
    auto &visit = *static_cast<MacPositiveVisit *>(context);
    visit.called = true;
    assert(authorization.authenticationKind() ==
           NativeDesktopAuthenticationKind::ExistingOsAccount);
    assert(authorization.authenticatedUserId() == 501U);
    assert(authorization.consoleUser() == "owner");
    assert(authorization.auditUserId() == 501U);
    assert(authorization.auditSessionId() == 77U);
    assert(authorization.securitySessionId() == 88U);
    assert(authorization.securitySessionAttributes() == 0x10U);
    assert(authorization.permissionMask() ==
           (kConsoleViewPermission | kConsoleInputPermission));
    assert(authorization.authenticationGeneration() == 12U);
    assert(authorization.authorizationGeneration() ==
           visit.expectedAuthorizationGeneration);
    assert(authorization.ownerAuthorizationEpoch().grantGeneration != 0);
    assert(authorization.ownerAuthorizationEpoch().revocationGeneration != 0);
    return true;
}

[[nodiscard]] bool acceptWindowsAuthorization(
    const WindowsNativeDesktopAuthorizationView & /* authorization */,
    void * /* context */) noexcept
{
    return true;
}

[[nodiscard]] bool acceptMacAuthorization(
    const MacNativeDesktopAuthorizationView & /* authorization */,
    void * /* context */) noexcept
{
    return true;
}

struct WindowsMutationVisit final
{
    FakeWindowsEvidenceSource *source{};
};

[[nodiscard]] bool mutateWindowsSessionDuringVisit(
    const WindowsNativeDesktopAuthorizationView & /* authorization */,
    void *context) noexcept
{
    auto &visit = *static_cast<WindowsMutationVisit *>(context);
    ++visit.source->evidence.sessionId;
    return true;
}

struct MacMutationVisit final
{
    FakeMacEvidenceSource *source{};
};

[[nodiscard]] bool mutateMacSessionDuringVisit(
    const MacNativeDesktopAuthorizationView & /* authorization */,
    void *context) noexcept
{
    auto &visit = *static_cast<MacMutationVisit *>(context);
    ++visit.source->evidence.auditSessionId;
    return true;
}

void testWindowsPositiveConstruction()
{
    OwnerFixture owner;
    FakeWindowsEvidenceSource nativeEvidence;
    FakeWindowsAuthenticatedIdentity authenticatedIdentity;
    WindowsNativeDesktopAuthorization authorization{
        authenticatedIdentity, nativeEvidence, owner.authority};

    assert(authorization.bindAuthenticatedIdentity(
               kConsoleViewPermission | kConsoleInputPermission) ==
           NativeDesktopAuthorizationBindResult::Bound);
    const std::uint64_t generation = authorization.authorizationGeneration();
    assert(generation != 0);

    WindowsPositiveVisit visit{false, generation};
    assert(authorization.visit(
        generation, kConsoleViewPermission,
        inspectWindowsAuthorization, &visit));
    assert(visit.called);
    assert(authorization.authorizationGeneration() == generation);
}

void testWindowsStaleDenials()
{
    OwnerFixture owner;
    FakeWindowsEvidenceSource nativeEvidence;
    FakeWindowsAuthenticatedIdentity authenticatedIdentity;
    WindowsNativeDesktopAuthorization authorization{
        authenticatedIdentity, nativeEvidence, owner.authority};
    constexpr std::uint32_t fullPermissions =
        kConsoleViewPermission | kConsoleInputPermission;

    assert(authorization.bindAuthenticatedIdentity(kConsoleInputPermission) ==
           NativeDesktopAuthorizationBindResult::InvalidPermissions);
    assert(authorization.bindAuthenticatedIdentity(
               fullPermissions | kConsoleClipboardPermission) ==
           NativeDesktopAuthorizationBindResult::InvalidPermissions);

    nativeEvidence.status = WindowsNativeSessionEvidenceStatus::Unavailable;
    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::NativeSessionUnavailable);
    nativeEvidence.status = WindowsNativeSessionEvidenceStatus::Observed;

    authenticatedIdentity.sid[0] ^= std::byte{0x01};
    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::AuthenticatedIdentityMismatch);
    authenticatedIdentity.sid[0] ^= std::byte{0x01};

    authenticatedIdentity.generation = 0;
    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::
               AuthenticatedIdentityUnavailable);
    authenticatedIdentity.generation = 11U;

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    std::uint64_t generation = authorization.authorizationGeneration();
    assert(!authorization.visit(
        generation + 1U, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));
    assert(authorization.authorizationGeneration() == generation);

    assert(authorization.bindAuthenticatedIdentity(kConsoleViewPermission) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    assert(!authorization.visit(
        generation, kConsoleInputPermission,
        acceptWindowsAuthorization, nullptr));
    assert(authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    nativeEvidence.evidence.userSid[0] ^= std::byte{0x01};
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));
    nativeEvidence.evidence = makeWindowsEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    ++nativeEvidence.evidence.sessionId;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));
    nativeEvidence.evidence = makeWindowsEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    ++nativeEvidence.evidence.authenticationIdLow;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));
    nativeEvidence.evidence = makeWindowsEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    ++nativeEvidence.evidence.authenticationIdHigh;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));
    nativeEvidence.evidence = makeWindowsEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    ++nativeEvidence.evidence.logonTime100Nanoseconds;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));
    nativeEvidence.evidence = makeWindowsEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    nativeEvidence.evidence.logonType = 11U;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));
    nativeEvidence.evidence = makeWindowsEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    ++authenticatedIdentity.generation;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));
    authenticatedIdentity.generation = 11U;

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    owner.grant(fullPermissions);
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    owner.authority.revoke(OwnerConsentRevocationReason::Stop);
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));
    owner.grant(fullPermissions);

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    WindowsMutationVisit mutation{&nativeEvidence};
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        mutateWindowsSessionDuringVisit, &mutation));
    nativeEvidence.evidence = makeWindowsEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    nativeEvidence.status = WindowsNativeSessionEvidenceStatus::Unavailable;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptWindowsAuthorization, nullptr));
    assert(authorization.authorizationGeneration() == 0);
}

void testMacPositiveConstruction()
{
    OwnerFixture owner;
    FakeMacEvidenceSource nativeEvidence;
    FakeMacAuthenticatedIdentity authenticatedIdentity;
    MacNativeDesktopAuthorization authorization{
        authenticatedIdentity, nativeEvidence, owner.authority};

    assert(authorization.bindAuthenticatedIdentity(
               kConsoleViewPermission | kConsoleInputPermission) ==
           NativeDesktopAuthorizationBindResult::Bound);
    const std::uint64_t generation = authorization.authorizationGeneration();
    assert(generation != 0);

    MacPositiveVisit visit{false, generation};
    assert(authorization.visit(
        generation, kConsoleViewPermission,
        inspectMacAuthorization, &visit));
    assert(visit.called);
    assert(authorization.authorizationGeneration() == generation);
}

void testMacStaleDenials()
{
    OwnerFixture owner;
    FakeMacEvidenceSource nativeEvidence;
    FakeMacAuthenticatedIdentity authenticatedIdentity;
    MacNativeDesktopAuthorization authorization{
        authenticatedIdentity, nativeEvidence, owner.authority};
    constexpr std::uint32_t fullPermissions =
        kConsoleViewPermission | kConsoleInputPermission;

    assert(authorization.bindAuthenticatedIdentity(kConsoleInputPermission) ==
           NativeDesktopAuthorizationBindResult::InvalidPermissions);
    assert(authorization.bindAuthenticatedIdentity(
               fullPermissions | kConsoleClipboardPermission) ==
           NativeDesktopAuthorizationBindResult::InvalidPermissions);

    nativeEvidence.status = MacNativeSessionEvidenceStatus::Unavailable;
    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::NativeSessionUnavailable);
    nativeEvidence.status = MacNativeSessionEvidenceStatus::Observed;

    authenticatedIdentity.userId = 502U;
    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::AuthenticatedIdentityMismatch);
    authenticatedIdentity.userId = 501U;

    authenticatedIdentity.generation = 0;
    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::
               AuthenticatedIdentityUnavailable);
    authenticatedIdentity.generation = 12U;

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    std::uint64_t generation = authorization.authorizationGeneration();
    assert(!authorization.visit(
        generation + 1U, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));
    assert(authorization.authorizationGeneration() == generation);

    assert(authorization.bindAuthenticatedIdentity(kConsoleViewPermission) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    assert(!authorization.visit(
        generation, kConsoleInputPermission,
        acceptMacAuthorization, nullptr));
    assert(authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    nativeEvidence.evidence.consoleUser[0] = 'x';
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));
    nativeEvidence.evidence = makeMacEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    ++nativeEvidence.evidence.consoleUserId;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));
    nativeEvidence.evidence = makeMacEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    ++nativeEvidence.evidence.auditUserId;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));
    nativeEvidence.evidence = makeMacEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    ++nativeEvidence.evidence.auditSessionId;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));
    nativeEvidence.evidence = makeMacEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    ++nativeEvidence.evidence.securitySessionId;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));
    nativeEvidence.evidence = makeMacEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    nativeEvidence.evidence.securitySessionAttributes ^= 0x01U;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));
    nativeEvidence.evidence = makeMacEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    ++authenticatedIdentity.generation;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));
    authenticatedIdentity.generation = 12U;

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    owner.grant(fullPermissions);
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    owner.authority.revoke(OwnerConsentRevocationReason::Stop);
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));
    owner.grant(fullPermissions);

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    MacMutationVisit mutation{&nativeEvidence};
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        mutateMacSessionDuringVisit, &mutation));
    nativeEvidence.evidence = makeMacEvidence();

    assert(authorization.bindAuthenticatedIdentity(fullPermissions) ==
           NativeDesktopAuthorizationBindResult::Bound);
    generation = authorization.authorizationGeneration();
    nativeEvidence.status = MacNativeSessionEvidenceStatus::Unavailable;
    assert(!authorization.visit(
        generation, kConsoleViewPermission,
        acceptMacAuthorization, nullptr));
    assert(authorization.authorizationGeneration() == 0);
}

} // namespace

int main(int argumentCount, char **arguments)
{
    assert(argumentCount == 2);
    const std::string_view testCase{arguments[1]};

    if (testCase == "windows-positive-construction")
    {
        testWindowsPositiveConstruction();
        return 0;
    }
    if (testCase == "windows-stale-denials")
    {
        testWindowsStaleDenials();
        return 0;
    }
    if (testCase == "macos-positive-construction")
    {
        testMacPositiveConstruction();
        return 0;
    }
    if (testCase == "macos-stale-denials")
    {
        testMacStaleDenials();
        return 0;
    }

    assert(false && "unknown native desktop authorization test case");
    return 1;
}
