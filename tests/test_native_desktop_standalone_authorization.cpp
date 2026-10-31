// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/mac_console_admission.h"
#include "server/security/native_desktop_authorization.h"
#include "server/security/standalone_ntlmv2.h"
#include "server/transport/nonblocking_tcp_adapter.h"

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
static_assert(!std::is_copy_constructible_v<MacConsoleAdmissionBroker>);
static_assert(!std::is_move_constructible_v<MacConsoleAdmissionBroker>);

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

    [[nodiscard]] bool revalidatesOwnedR1Connection(
        const rdp_server::server::transport::OwnedPreauthTcpConnection
            &connection) const noexcept override
    {
        return exactConnectionCurrent && acceptedConnection == &connection &&
               revalidatesAuthenticatedSession();
    }

    [[nodiscard]] std::uint64_t configuredCredentialGeneration()
        const noexcept override
    {
        return revalidatesAuthenticatedSession()
            ? credentialGeneration
            : 0U;
    }

    const rdp_server::server::transport::OwnedPreauthTcpConnection
        *acceptedConnection{};
    bool exactConnectionCurrent{true};
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


// Offline-only macOS R2 visitor regression. Synthetic evidence cannot mint an
// R3 native admission lease; these checks enforce the reusable R2 grant lifetime.
class StandaloneMacFixture final
{
public:
    StandaloneMacFixture()
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

    [[nodiscard]] std::uint64_t bind(std::uint32_t permissions =
                                      kConsoleViewPermission |
                                          kConsoleInputPermission) noexcept
    {
        assert(authorization.bindAuthenticatedSession(permissions) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const auto generation = authorization.authorizationGeneration();
        assert(generation != 0U);
        return generation;
    }

    OwnerFixture owner{};
    StandalonePasswordCredentialOwner credential{};
    FakeMacEvidenceSource nativeEvidence{};
    FakeStandaloneAuthenticatedSessionProof proof;
    MacNativeDesktopAuthorization authorization;
};

[[nodiscard]] bool acceptStandaloneMac(
    const MacNativeDesktopAuthorizationView & /* authorization */,
    void * /* context */) noexcept
{
    return true;
}

struct MacRevocationDuringVisit final
{
    OwnerFixture *owner{};
    bool invoked{};
};

[[nodiscard]] bool revokeMacOwnerDuringVisit(
    const MacNativeDesktopAuthorizationView & /* authorization */,
    void *context) noexcept
{
    auto &mutation = *static_cast<MacRevocationDuringVisit *>(context);
    mutation.invoked = true;
    mutation.owner->authority.revoke(OwnerConsentRevocationReason::Stop);
    return true;
}

struct MacGrantReplacementDuringVisit final
{
    StandaloneMacFixture *fixture{};
    std::uint64_t originalGeneration{};
    std::uint64_t replacementGeneration{};
    bool viewStayedOnOriginalEvidence{};
};

[[nodiscard]] bool replaceMacGrantDuringVisit(
    const MacNativeDesktopAuthorizationView &authorization,
    void *context) noexcept
{
    auto &replacement = *static_cast<MacGrantReplacementDuringVisit *>(context);
    const auto previousAuditSessionId = authorization.auditSessionId();

    replacement.fixture->authorization.revoke();
    ++replacement.fixture->nativeEvidence.evidence.auditSessionId;
    assert(replacement.fixture->authorization.bindAuthenticatedSession(
               kConsoleViewPermission | kConsoleInputPermission) ==
           NativeDesktopAuthorizationBindResult::Bound);
    replacement.replacementGeneration =
        replacement.fixture->authorization.authorizationGeneration();
    replacement.viewStayedOnOriginalEvidence =
        authorization.auditSessionId() == previousAuditSessionId &&
        authorization.authorizationGeneration() == replacement.originalGeneration &&
        replacement.replacementGeneration != replacement.originalGeneration;
    return true;
}

void testMacStandaloneReentrantGenerationDenials()
{
    {
        StandaloneMacFixture fixture;
        fixture.proof.credentialsVerified = false;
        assert(fixture.authorization.bindAuthenticatedSession(
                   kConsoleViewPermission) ==
               NativeDesktopAuthorizationBindResult::
                   AuthenticatedIdentityUnavailable);
        assert(fixture.authorization.authorizationGeneration() == 0U);
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind(kConsoleViewPermission);
        assert(!fixture.authorization.visit(
            generation, kConsoleInputPermission, &acceptStandaloneMac, nullptr));
        assert(fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        fixture.owner.grant(); // Same permission, different consent epoch.
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        ++fixture.proof.proofGeneration;
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        std::array<char16_t, 3> password{u'N', u'e', u'w'};
        assert(fixture.credential.configure(u"Session", password));
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        fixture.proof.connectionCurrent = false; // Accepted R1 owner replaced.
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        fixture.proof.tlsConnectionCurrent = false; // TLS owner retired.
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
    for (const auto reason : {
             OwnerConsentRevocationReason::Stop,
             OwnerConsentRevocationReason::Logout,
             OwnerConsentRevocationReason::SessionReplacement})
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        fixture.owner.authority.revoke(reason);
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        fixture.owner.evidence.session.lockState = ConsoleDesktopLockState::Locked;
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        fixture.nativeEvidence.status = MacNativeSessionEvidenceStatus::Unavailable;
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        ++fixture.nativeEvidence.evidence.auditSessionId;
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        MacRevocationDuringVisit mutation{&fixture.owner};
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &revokeMacOwnerDuringVisit,
            &mutation));
        assert(mutation.invoked);
        assert(fixture.authorization.authorizationGeneration() == 0U);
    }
    {
        StandaloneMacFixture fixture;
        const auto generation = fixture.bind();
        MacGrantReplacementDuringVisit replacement{&fixture, generation};
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &replaceMacGrantDuringVisit,
            &replacement));
        assert(replacement.viewStayedOnOriginalEvidence);
        assert(replacement.replacementGeneration != 0U);
        assert(fixture.authorization.authorizationGeneration() ==
               replacement.replacementGeneration);
        assert(fixture.authorization.visit(
            replacement.replacementGeneration, kConsoleViewPermission,
            &acceptStandaloneMac, nullptr));
        assert(!fixture.authorization.visit(
            generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
    }
}

struct MacNestedAuthorizationAttempt final
{
    MacNativeDesktopAuthorization *authorization{};
    std::uint64_t originalGeneration{};
    bool outerCalled{};
    bool nestedCalled{};
    bool nestedAccepted{};
};

[[nodiscard]] bool markNestedMacAuthorization(
    const MacNativeDesktopAuthorizationView & /* authorization */,
    void *context) noexcept
{
    auto &attempt = *static_cast<MacNestedAuthorizationAttempt *>(context);
    attempt.nestedCalled = true;
    return true;
}

[[nodiscard]] bool attemptNestedMacAuthorization(
    const MacNativeDesktopAuthorizationView &authorization,
    void *context) noexcept
{
    auto &attempt = *static_cast<MacNestedAuthorizationAttempt *>(context);
    attempt.outerCalled = true;
    assert(authorization.authorizationGeneration() ==
           attempt.originalGeneration);
    attempt.nestedAccepted = attempt.authorization->visit(
        attempt.originalGeneration, kConsoleViewPermission,
        &markNestedMacAuthorization, &attempt);
    return true;
}

void testMacStandaloneNestedVisitorDenials()
{
    // Both calls use the real R2 owner; only the outer borrowed view is
    // authorized. This is not a synthetic native OS or R3 admission lease.
    StandaloneMacFixture fixture;
    const auto generation = fixture.bind();
    MacNestedAuthorizationAttempt attempt{&fixture.authorization, generation};
    assert(fixture.authorization.visit(
        generation, kConsoleViewPermission,
        &attemptNestedMacAuthorization, &attempt));
    assert(attempt.outerCalled);
    assert(!attempt.nestedCalled);
    assert(!attempt.nestedAccepted);
    assert(fixture.authorization.authorizationGeneration() == generation);
    assert(fixture.authorization.visit(
        generation, kConsoleViewPermission, &acceptStandaloneMac, nullptr));
}


class MacConsoleBrokerFixture final
{
public:
    MacConsoleBrokerFixture()
        : proof(credential),
          connection(rdp_server::server::transport::OwnedNativeTcpSocket{}),
          replacementConnection(
              rdp_server::server::transport::OwnedNativeTcpSocket{}),
          broker(proof, connection, nativeEvidence, owner.authority)
    {
        std::array<char16_t, 8> password{
            u'P', u'a', u's', u's', u'w', u'o', u'r', u'd'};
        assert(credential.configure(u"Session", password));
        const auto observation = credential.observation();
        assert(observation.configured && observation.generation != 0U);
        proof.bindCredentialGeneration(observation.generation);
        proof.acceptedConnection = &connection;
    }

    void prepare(std::uint32_t permissions =
                     kConsoleViewPermission | kConsoleInputPermission)
    {
        assert(broker.prepareAdmission(permissions) ==
               MacConsoleAdmissionPrepareResult::Prepared);
        assert(broker.state() == MacConsoleAdmissionState::Prepared);
        assert(broker.admissionGeneration() != 0U);
    }

    OwnerFixture owner{};
    StandalonePasswordCredentialOwner credential{};
    FakeMacEvidenceSource nativeEvidence{};
    FakeStandaloneAuthenticatedSessionProof proof;
    rdp_server::server::transport::OwnedPreauthTcpConnection connection;
    rdp_server::server::transport::OwnedPreauthTcpConnection
        replacementConnection;
    MacConsoleAdmissionBroker broker;
};

[[nodiscard]] bool markMacConsoleBrokerVisitor(
    const MacNativeDesktopAuthorizationView & /* authorization */,
    void *context) noexcept
{
    auto &called = *static_cast<bool *>(context);
    called = true;
    return true;
}

void testMacConsoleAdmissionMissingStaleProofDenials()
{
    {
        MacConsoleBrokerFixture fixture;
        fixture.proof.credentialsVerified = false;
        assert(fixture.broker.prepareAdmission(kConsoleViewPermission) ==
               MacConsoleAdmissionPrepareResult::AuthenticationUnavailable);
        assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
    }
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        std::array<char16_t, 3> password{u'N', u'e', u'w'};
        assert(fixture.credential.configure(u"Session", password));
        assert(!fixture.broker.revalidate(kConsoleViewPermission));
        assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
    }
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        fixture.proof.exactConnectionCurrent = false;
        assert(!fixture.broker.revalidate(kConsoleViewPermission));
        assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
    }
}

void testMacConsoleAdmissionWrongConnectionDenial()
{
    MacConsoleBrokerFixture fixture;
    fixture.proof.acceptedConnection = &fixture.replacementConnection;
    assert(fixture.proof.revalidatesAuthenticatedSession());
    assert(fixture.broker.prepareAdmission(kConsoleViewPermission) ==
           MacConsoleAdmissionPrepareResult::ConnectionMismatch);
    assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
}

void testMacConsoleAdmissionPermissionScopeDenials()
{
    {
        MacConsoleBrokerFixture fixture;
        assert(fixture.broker.prepareAdmission(kConsoleInputPermission) ==
               MacConsoleAdmissionPrepareResult::InvalidPermissions);
        assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
    }
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        bool called = false;
        assert(!fixture.broker.visitNativeAuthorization(
            kConsoleInputPermission, &markMacConsoleBrokerVisitor, &called));
        assert(!called);
        assert(fixture.broker.state() == MacConsoleAdmissionState::Prepared);
        assert(fixture.broker.revalidate(kConsoleViewPermission));
    }
}

void testMacConsoleAdmissionConsentEpochReplacementDenial()
{
    MacConsoleBrokerFixture fixture;
    fixture.prepare();
    fixture.owner.grant();
    assert(!fixture.broker.revalidate(kConsoleViewPermission));
    assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
}

struct MacConsoleNestedVisit final
{
    MacConsoleAdmissionBroker *broker{};
    bool outerCalled{};
    bool nestedCalled{};
    bool nestedAccepted{};
};

[[nodiscard]] bool markNestedMacConsoleVisit(
    const MacNativeDesktopAuthorizationView & /* authorization */,
    void *context) noexcept
{
    auto &visit = *static_cast<MacConsoleNestedVisit *>(context);
    visit.nestedCalled = true;
    return true;
}

[[nodiscard]] bool attemptNestedMacConsoleVisit(
    const MacNativeDesktopAuthorizationView & /* authorization */,
    void *context) noexcept
{
    auto &visit = *static_cast<MacConsoleNestedVisit *>(context);
    visit.outerCalled = true;
    visit.nestedAccepted = visit.broker->visitNativeAuthorization(
        kConsoleViewPermission, &markNestedMacConsoleVisit, &visit);
    return true;
}

void testMacConsoleAdmissionNestedVisitorReentryDenial()
{
    MacConsoleBrokerFixture fixture;
    fixture.prepare();
    MacConsoleNestedVisit visit{&fixture.broker};
    assert(fixture.broker.visitNativeAuthorization(
        kConsoleViewPermission, &attemptNestedMacConsoleVisit, &visit));
    assert(visit.outerCalled);
    assert(!visit.nestedCalled);
    assert(!visit.nestedAccepted);
    assert(fixture.broker.state() == MacConsoleAdmissionState::Prepared);
    assert(fixture.broker.revalidate(kConsoleViewPermission));
}

void testMacConsoleAdmissionSessionReplacementDenial()
{
    MacConsoleBrokerFixture fixture;
    fixture.prepare();
    ++fixture.nativeEvidence.evidence.auditSessionId;
    assert(!fixture.broker.revalidate(kConsoleViewPermission));
    assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
}

struct MacConsoleCallbackRevocation final
{
    OwnerFixture *owner{};
    bool called{};
};

[[nodiscard]] bool revokeMacConsoleOwnerDuringCallback(
    const MacNativeDesktopAuthorizationView & /* authorization */,
    void *context) noexcept
{
    auto &revocation = *static_cast<MacConsoleCallbackRevocation *>(context);
    revocation.called = true;
    revocation.owner->authority.revoke(OwnerConsentRevocationReason::Stop);
    return true;
}

void testMacConsoleAdmissionPostCallbackAuthorityLossDenial()
{
    MacConsoleBrokerFixture fixture;
    fixture.prepare();
    MacConsoleCallbackRevocation revocation{&fixture.owner};
    assert(!fixture.broker.visitNativeAuthorization(
        kConsoleViewPermission, &revokeMacConsoleOwnerDuringCallback,
        &revocation));
    assert(revocation.called);
    assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
}

void testMacConsoleAdmissionExplicitTerminalRevocation()
{
    MacConsoleBrokerFixture fixture;
    fixture.prepare();
    fixture.broker.revoke(
        MacConsoleAdmissionRevocationReason::ListenerReplacement);
    fixture.broker.revoke(MacConsoleAdmissionRevocationReason::OwnerStop);
    assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
    assert(fixture.broker.admissionGeneration() == 0U);
    assert(fixture.broker.revocationReason() ==
           MacConsoleAdmissionRevocationReason::ListenerReplacement);
    assert(!fixture.broker.revalidate(kConsoleViewPermission));
}

// R1/R2 boundary: an independently prepared macOS authorization lifetime
// cannot transition an inactive/unverified R1 connection into MCS. The fake
// proof tests only the broker's ordering; it cannot create native admission.
void testMacConsolePreparedTransportDormancy()
{
    using rdp_server::server::transport::PreauthStage;

    MacConsoleBrokerFixture fixture;
    const PreauthStage initialStage = fixture.connection.stage();
    assert(initialStage != PreauthStage::AwaitMcsConnectInitial);
    assert(!fixture.connection.active());
    assert(fixture.connection.establishedTls() == nullptr);

    fixture.prepare(kConsoleViewPermission);
    bool visited = false;
    assert(fixture.broker.visitNativeAuthorization(
        kConsoleViewPermission, &markMacConsoleBrokerVisitor, &visited));
    assert(visited);
    assert(fixture.broker.revalidate(kConsoleViewPermission));
    assert(fixture.connection.stage() == initialStage);
    assert(fixture.connection.establishedTls() == nullptr);
    assert(fixture.connection.transportGeneration() == 0U);

    fixture.broker.revoke(
        MacConsoleAdmissionRevocationReason::ListenerReplacement);
    assert(!fixture.broker.revalidate(kConsoleViewPermission));
    assert(fixture.connection.stage() == initialStage);
    fixture.connection.cancel();
    assert(fixture.connection.stage() == PreauthStage::Closed);
    assert(!fixture.connection.active());
}


void testMacConsoleProtectedIssuerRequiresExactLiveR1()
{
    using namespace rdp_server::server::transport;
    MacConsoleBrokerFixture fixture;
    fixture.prepare(kConsoleViewPermission);
    McsSessionLifecycle session;
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(!fixture.broker.authorizeR1CredSspAdmission(session));
    assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(fixture.connection.stage() == PreauthStage::Closed);
    assert(fixture.broker.admissionGeneration() == 0U);
    assert(!fixture.broker.authorizeR1CredSspAdmission(session));
    assert(fixture.broker.authorizeR3McsConnectInitial(session, {}) ==
           McsSessionIntake::AdmissionDenied);
}

void testMacConsoleProtectedIssuerConsentAndConnectionDenials()
{
    using namespace rdp_server::server::transport;
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        fixture.owner.grant(); // same permissions, changed consent epoch
        McsSessionLifecycle session;
        assert(!fixture.broker.authorizeR1CredSspAdmission(session));
        assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
        assert(session.phase() == McsSessionPhase::Closed);
    }
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        fixture.proof.acceptedConnection = &fixture.replacementConnection;
        McsSessionLifecycle session;
        assert(!fixture.broker.authorizeR1CredSspAdmission(session));
        assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
        assert(session.phase() == McsSessionPhase::Closed);
    }
}

// R1 must be promoted under native authority before R10 reads even a
// complete first-MCS TPKT. Synthetic fixtures can test the denial/ordering
// contract but cannot impersonate a real TLS socket or native macOS lease.
void testMacConsoleProtectedFirstMcsOrderingDenials()
{
    using namespace rdp_server::server::transport;
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        McsSessionLifecycle session;
        assert(fixture.broker.authorizeR3McsConnectInitial(session, {}) ==
               McsSessionIntake::AdmissionDenied);
        assert(session.phase() == McsSessionPhase::Closed);
        assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
        assert(fixture.connection.establishedTls() == nullptr);
    }
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        McsSessionLifecycle session;
        assert(!fixture.broker.authorizeR1CredSspAdmission(session));
        assert(session.phase() == McsSessionPhase::Closed);
        assert(fixture.connection.stage() == PreauthStage::Closed);
        assert(!fixture.broker.authorizeR1CredSspAdmission(session));
        assert(fixture.broker.authorizeR3McsConnectInitial(session, {}) ==
               McsSessionIntake::AdmissionDenied);
    }
}

// The borrowed Prepared-only fixture is deliberately unable to cross R1
// TLS completion. The entire Attach/Join/ClientInfo API must retire R3 when
// invoked without the earlier independently admitted native transport.
void testMacConsoleProtectedAttachJoinClientInfoDenials()
{
    using namespace rdp_server::server::transport;
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        McsSessionLifecycle session;
        assert(fixture.broker.authorizeR3AttachUser(session, {}) ==
               McsSessionIntake::AdmissionDenied);
        assert(session.phase() == McsSessionPhase::Closed);
        assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
    }
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        McsSessionLifecycle session;
        assert(!fixture.broker.authorizeR3AttachUserConfirmWrite(session));
        assert(fixture.broker.completeR3AttachUserConfirmWrite(
                   session, 1U, 1U, 0U) ==
               McsConnectResponseWriteOutcome::Rejected);
        assert(session.phase() == McsSessionPhase::Closed);
    }
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        McsSessionLifecycle session;
        assert(fixture.broker.authorizeR3ChannelJoin(session, {}) ==
               McsJoinStartOutcome::Rejected);
        assert(!fixture.broker.authorizeR3ChannelJoinConfirmWrite(session));
        assert(fixture.broker.completeR3ChannelJoinConfirmWrite(
                   session, 1U, 1U, 0U) == McsJoinWriteOutcome::Rejected);
        assert(!fixture.broker.authorizeR3ClientInfoPacket(session, {}));
        assert(session.phase() == McsSessionPhase::Closed);
        assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
    }
    {
        MacConsoleBrokerFixture fixture;
        fixture.prepare(kConsoleViewPermission);
        McsSessionLifecycle session;
        assert(!fixture.broker.authorizeR3ClientInfoPacket(session, {}));
        assert(session.phase() == McsSessionPhase::Closed);
        assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
    }
}

void testMacConsoleProtectedIssuerPrematureReceipts()
{
    using namespace rdp_server::server::transport;
    MacConsoleBrokerFixture fixture;
    fixture.prepare(kConsoleViewPermission);
    McsSessionLifecycle session;
    assert(!fixture.broker.authorizeR3ConnectResponseWrite(session));
    assert(session.phase() == McsSessionPhase::Closed);
    assert(fixture.broker.completeR3ConnectResponseWrite(
               session, 1U, 1U, 0U) ==
           McsConnectResponseWriteOutcome::Rejected);
    assert(fixture.broker.authorizeR3ErectDomain(session, {}) ==
           McsSessionIntake::AdmissionDenied);
    assert(!fixture.broker.authorizeR3ProtectedTransition(
        session, kConsoleViewPermission));
    assert(fixture.broker.state() == MacConsoleAdmissionState::Revoked);
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
    if (testCase == "macos-standalone-reentrant-generation-denials")
    {
        testMacStandaloneReentrantGenerationDenials();
        return 0;
    }
    if (testCase == "macos-standalone-nested-visitor-denials")
    {
        testMacStandaloneNestedVisitorDenials();
        return 0;
    }

    if (testCase == "macos-console-admission-missing-stale-proof-denials")
    {
        testMacConsoleAdmissionMissingStaleProofDenials();
        return 0;
    }
    if (testCase == "macos-console-admission-wrong-connection-denial")
    {
        testMacConsoleAdmissionWrongConnectionDenial();
        return 0;
    }
    if (testCase == "macos-console-admission-permission-scope-denials")
    {
        testMacConsoleAdmissionPermissionScopeDenials();
        return 0;
    }
    if (testCase == "macos-console-admission-consent-epoch-replacement-denial")
    {
        testMacConsoleAdmissionConsentEpochReplacementDenial();
        return 0;
    }
    if (testCase == "macos-console-admission-nested-visitor-reentry-denial")
    {
        testMacConsoleAdmissionNestedVisitorReentryDenial();
        return 0;
    }
    if (testCase == "macos-console-admission-session-replacement-denial")
    {
        testMacConsoleAdmissionSessionReplacementDenial();
        return 0;
    }
    if (testCase == "macos-console-admission-post-callback-authority-loss-denial")
    {
        testMacConsoleAdmissionPostCallbackAuthorityLossDenial();
        return 0;
    }
    if (testCase == "macos-console-admission-explicit-terminal-revocation")
    {
        testMacConsoleAdmissionExplicitTerminalRevocation();
        return 0;
    }
    if (testCase == "macos-console-protected-issuer-live-r1-denials")
    {
        testMacConsoleProtectedIssuerRequiresExactLiveR1();
        return 0;
    }
    if (testCase == "macos-console-protected-issuer-consent-connection-denials")
    {
        testMacConsoleProtectedIssuerConsentAndConnectionDenials();
        return 0;
    }
    if (testCase == "macos-console-protected-first-mcs-order-denials")
    {
        testMacConsoleProtectedFirstMcsOrderingDenials();
        return 0;
    }
    if (testCase == "macos-console-protected-attach-join-clientinfo-denials")
    {
        testMacConsoleProtectedAttachJoinClientInfoDenials();
        return 0;
    }
    if (testCase == "macos-console-protected-issuer-premature-receipts")
    {
        testMacConsoleProtectedIssuerPrematureReceipts();
        return 0;
    }
    if (testCase == "macos-console-prepared-transport-dormancy")
    {
        testMacConsolePreparedTransportDormancy();
        return 0;
    }
    return 2;
}
