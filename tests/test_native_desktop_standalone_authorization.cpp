// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/native_desktop_authorization.h"
#include "server/security/standalone_ntlmv2.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>

namespace
{

using namespace rdp_server::server::security;

static_assert(!std::is_copy_constructible_v<
              NativeDesktopAuthenticatedSessionProof>);
static_assert(!std::is_move_constructible_v<
              NativeDesktopAuthenticatedSessionProof>);

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
        session.observedAtMonotonicMilliseconds = now.value_or(0U);
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
        grant();
    }

    void grant()
    {
        evidence.session.observedAtMonotonicMilliseconds =
            evidence.now.value_or(0U);
        assert(authority.requestConsent(
                   {kConsoleViewPermission | kConsoleInputPermission,
                    60'000U}) ==
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
    evidence.userSidBytes = 4U;
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

// Synthetic proof of the generic R2 contract. It intentionally implements no
// SID/UID matcher. The real StandalonePasswordAuthenticatedPrincipalProof is
// separately pinned to exact owner-bound CredSSP/R1/TLS provenance.
class FakeStandaloneAuthenticatedSessionProof final
    : public NativeDesktopAuthenticatedSessionProof
{
public:
    explicit FakeStandaloneAuthenticatedSessionProof(
        const StandalonePasswordCredentialOwner &credentialOwner) noexcept
        : credentialOwner_(&credentialOwner)
    {
    }

    [[nodiscard]] NativeDesktopAuthenticationKind authenticationKind()
        const noexcept override
    {
        return NativeDesktopAuthenticationKind::StandalonePassword;
    }

    [[nodiscard]] std::uint64_t authenticationGeneration()
        const noexcept override
    {
        return revalidatesAuthenticatedSession() ? proofGeneration : 0U;
    }

    [[nodiscard]] bool revalidatesAuthenticatedSession()
        const noexcept override
    {
        if (!credentialsVerified || !connectionCurrent ||
            !tlsConnectionCurrent || credentialOwner_ == nullptr ||
            credentialGeneration == 0U)
        {
            return false;
        }

        const auto observation = credentialOwner_->observation();
        return observation.configured &&
               observation.generation == credentialGeneration;
    }

    void bindCredentialGeneration(std::uint64_t generation) noexcept
    {
        credentialGeneration = generation;
    }

    bool credentialsVerified{true};
    bool connectionCurrent{true};
    bool tlsConnectionCurrent{true};
    std::uint64_t proofGeneration{41U};
    std::uint64_t credentialGeneration{};

private:
    const StandalonePasswordCredentialOwner *credentialOwner_{};
};

class StandaloneWindowsFixture final
{
public:
    StandaloneWindowsFixture()
        : proof(credential),
          authorization(proof, nativeEvidence, owner.authority)
    {
        std::array<char16_t, 8> password{
            u'P', u'a', u's', u's', u'w', u'o', u'r', u'd'};
        assert(credential.configure(u"Session", password));
        const auto observation = credential.observation();
        assert(observation.configured && observation.generation != 0U);
        proof.bindCredentialGeneration(observation.generation);
    }

    OwnerFixture owner{};
    StandalonePasswordCredentialOwner credential{};
    FakeWindowsEvidenceSource nativeEvidence{};
    FakeStandaloneAuthenticatedSessionProof proof;
    WindowsNativeDesktopAuthorization authorization;
};

[[nodiscard]] bool inspectStandaloneWindows(
    const WindowsNativeDesktopAuthorizationView &authorization,
    void *context) noexcept
{
    auto &called = *static_cast<bool *>(context);
    called = true;
    assert(authorization.authenticationKind() ==
           NativeDesktopAuthenticationKind::StandalonePassword);
    assert(authorization.authenticatedSid().empty());
    assert(authorization.nativeSessionUserSid().size() == 4U);
    assert(authorization.wtsSessionId() == 42U);
    assert(authorization.authenticationGeneration() == 41U);
    return true;
}

[[nodiscard]] bool inspectStandaloneMac(
    const MacNativeDesktopAuthorizationView &authorization,
    void *context) noexcept
{
    auto &called = *static_cast<bool *>(context);
    called = true;
    assert(authorization.authenticationKind() ==
           NativeDesktopAuthenticationKind::StandalonePassword);
    assert(authorization.authenticatedUserId() == 0U);
    assert(authorization.nativeConsoleUserId() == 501U);
    assert(authorization.consoleUser() == "owner");
    assert(authorization.authenticationGeneration() == 41U);
    return true;
}

[[nodiscard]] bool acceptWindows(
    const WindowsNativeDesktopAuthorizationView & /* authorization */,
    void * /* context */) noexcept
{
    return true;
}

void testCurrentOwnerWithoutOsIdentity()
{
    StandaloneWindowsFixture windows;
    assert(windows.authorization.bindAuthenticatedSession(
               kConsoleViewPermission | kConsoleInputPermission) ==
           NativeDesktopAuthorizationBindResult::Bound);
    const std::uint64_t windowsGeneration =
        windows.authorization.authorizationGeneration();
    bool windowsVisited = false;
    assert(windows.authorization.visit(
        windowsGeneration, kConsoleViewPermission,
        &inspectStandaloneWindows, &windowsVisited));
    assert(windowsVisited);

    OwnerFixture macOwner;
    StandalonePasswordCredentialOwner macCredential;
    std::array<char16_t, 8> macPassword{
        u'P', u'a', u's', u's', u'w', u'o', u'r', u'd'};
    assert(macCredential.configure(u"Session", macPassword));
    const auto credentialObservation = macCredential.observation();
    FakeStandaloneAuthenticatedSessionProof macProof{macCredential};
    macProof.bindCredentialGeneration(credentialObservation.generation);
    FakeMacEvidenceSource macEvidence;
    MacNativeDesktopAuthorization macAuthorization{
        macProof, macEvidence, macOwner.authority};
    assert(macAuthorization.bindAuthenticatedSession(
               kConsoleViewPermission | kConsoleInputPermission) ==
           NativeDesktopAuthorizationBindResult::Bound);
    const std::uint64_t macGeneration =
        macAuthorization.authorizationGeneration();
    bool macVisited = false;
    assert(macAuthorization.visit(
        macGeneration, kConsoleViewPermission,
        &inspectStandaloneMac, &macVisited));
    assert(macVisited);
}

void testProvenanceAndRevocationDenials()
{
    {
        StandaloneWindowsFixture fixture;
        assert(fixture.authorization.bindAuthenticatedSession(
                   kConsoleViewPermission) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const auto generation = fixture.authorization.authorizationGeneration();
        fixture.proof.tlsConnectionCurrent = false;
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptWindows, nullptr));
    }

    {
        StandaloneWindowsFixture fixture;
        assert(fixture.authorization.bindAuthenticatedSession(
                   kConsoleViewPermission) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const auto generation = fixture.authorization.authorizationGeneration();
        fixture.proof.connectionCurrent = false;
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptWindows, nullptr));
    }

    {
        StandaloneWindowsFixture fixture;
        assert(fixture.authorization.bindAuthenticatedSession(
                   kConsoleViewPermission) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const auto generation = fixture.authorization.authorizationGeneration();
        ++fixture.proof.credentialGeneration;
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptWindows, nullptr));
    }

    {
        StandaloneWindowsFixture fixture;
        assert(fixture.authorization.bindAuthenticatedSession(
                   kConsoleViewPermission) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const auto generation = fixture.authorization.authorizationGeneration();
        std::array<char16_t, 11> replacement{
            u'N', u'e', u'w', u'P', u'a', u's',
            u's', u'w', u'o', u'r', u'd'};
        assert(fixture.credential.configure(u"Session", replacement));
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptWindows, nullptr));
    }

    {
        StandaloneWindowsFixture fixture;
        assert(fixture.authorization.bindAuthenticatedSession(
                   kConsoleViewPermission) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const auto generation = fixture.authorization.authorizationGeneration();
        fixture.owner.authority.revoke(OwnerConsentRevocationReason::Stop);
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptWindows, nullptr));
    }

    {
        StandaloneWindowsFixture fixture;
        assert(fixture.authorization.bindAuthenticatedSession(
                   kConsoleViewPermission) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const auto generation = fixture.authorization.authorizationGeneration();
        fixture.owner.evidence.session.lockState =
            ConsoleDesktopLockState::Locked;
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptWindows, nullptr));
    }

    {
        StandaloneWindowsFixture fixture;
        assert(fixture.authorization.bindAuthenticatedSession(
                   kConsoleViewPermission) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const auto generation = fixture.authorization.authorizationGeneration();
        ++fixture.nativeEvidence.evidence.sessionId;
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptWindows, nullptr));
    }

    {
        StandaloneWindowsFixture fixture;
        assert(fixture.authorization.bindAuthenticatedSession(
                   kConsoleViewPermission) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const auto generation = fixture.authorization.authorizationGeneration();
        fixture.proof.credentialsVerified = false;
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptWindows, nullptr));
    }
}

} // namespace

int main(int argumentCount, char **arguments)
{
    assert(argumentCount == 2);
    const std::string_view testCase{arguments[1]};

    if (testCase == "standalone-current-owner-without-os-identity")
    {
        testCurrentOwnerWithoutOsIdentity();
        return 0;
    }
    if (testCase == "standalone-provenance-and-revocation-denials")
    {
        testProvenanceAndRevocationDenials();
        return 0;
    }
    return 2;
}
