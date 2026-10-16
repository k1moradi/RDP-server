// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/gssapi_spnego_acceptor.h"
#include "security/gssapi_console_gate.h"
#include "security/linux_console_admission.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>

using namespace rdp_server::server::security;
using rdp_server::server::transport::McsSessionIntake;
using rdp_server::server::transport::McsSessionLifecycle;
using rdp_server::server::transport::McsSessionPhase;
using rdp_server::server::transport::RdpLicensingPhase;

namespace
{

constexpr std::array<std::uint8_t, 21> kInitialTsRequest{
    0x30, 0x13, 0xa0, 0x03, 0x02, 0x01, 0x06,
    0xa1, 0x0c, 0x30, 0x0a, 0x30, 0x08,
    0xa0, 0x06, 0x04, 0x04, 0x60, 0x82, 0x01, 0x00};

void testConfigurationRejections()
{
    GssapiSpnegoAcceptor missingKeytab;
    assert(missingKeytab.stage() == SpnegoStage::Unconfigured);
    // No environment/default keytab is allowed; this path is deliberately
    // nonexistent. Exercise the real MIT GSS acquire-cred-from provider.
    assert(!missingKeytab.configure(
        "TERMSRV/rdp.example.test@EXAMPLE.TEST",
        "FILE:/__rdp_server_gssapi_ci_nonexistent__/missing.keytab"));
    assert(missingKeytab.stage() == SpnegoStage::Failed);
    assert(missingKeytab.verifiedPrincipal().empty());
    const auto diagnostics = missingKeytab.configurationDiagnostics();
    assert(diagnostics.stage == GssConfigurationFailure::ImportService ||
           diagnostics.stage == GssConfigurationFailure::AcquireCredentials);
    // A failed provider instance cannot be reconfigured or resurrected.
    assert(!missingKeytab.configure(
        "TERMSRV/rdp.example.test@EXAMPLE.TEST",
        "FILE:/__rdp_server_gssapi_ci_nonexistent__/missing.keytab"));

    GssapiSpnegoAcceptor noService;
    assert(!noService.configure(
        "host/rdp.example.test@EXAMPLE.TEST",
        "FILE:/__rdp_server_gssapi_ci_nonexistent__/missing.keytab"));
    assert(noService.stage() == SpnegoStage::Failed);
    assert(noService.configurationDiagnostics().stage ==
           GssConfigurationFailure::InvalidOptions);

    GssapiSpnegoAcceptor relativeKeytab;
    assert(!relativeKeytab.configure(
        "TERMSRV/rdp.example.test@EXAMPLE.TEST",
        "FILE:relative.keytab"));
    assert(relativeKeytab.stage() == SpnegoStage::Failed);

    // Initial SPNEGO tag and OID validation is syntax only; the provider
    // still must authenticate an actual GSS token after configuration.
    constexpr std::array<std::uint8_t, 11> spnegoToken{
        0x60, 0x09, 0x06, 0x06, 0x2b, 0x06,
        0x01, 0x05, 0x05, 0x02, 0xa0};
    assert(isInitialSpnegoToken(spnegoToken));
    auto wrongOid = spnegoToken;
    wrongOid[7] ^= 0x01U;
    assert(!isInitialSpnegoToken(wrongOid));
    assert(!isInitialSpnegoToken({}));

    // The protected binding request recognizer is NOT a trust check and
    // cannot grant user or console authorization.
    std::array<std::uint8_t, 48> protectedBinding{
        0x30, 0x2e, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa3, 0x03, 0x04, 0x01, 0x55,
        0xa5, 0x22, 0x04, 0x20};
    for (std::size_t offset = 16; offset < protectedBinding.size(); ++offset)
    {
        protectedBinding[offset] = 0x42;
    }
    assert(isCredSspPublicKeyAuthRequest(protectedBinding));
    protectedBinding[6] = 4; // v4 cannot use v5/v6 public-key nonce binding.
    assert(!isCredSspPublicKeyAuthRequest(protectedBinding));
    protectedBinding[6] = 6;
    protectedBinding[15] = 31; // malformed nonce size.
    assert(!isCredSspPublicKeyAuthRequest(protectedBinding));
}

void testFramedGssHandoffFailClosed()
{
    // No configured credentials and no GSS security context. Even a valid
    // DER TSRequest cannot authenticate a user or trigger a reply.
    GssapiSpnegoAcceptor unconfigured;
    TsRequestFrameReader reader;
    const auto framed = reader.consume(kInitialTsRequest);
    assert(framed.status == TsRequestFrameStatus::Complete);
    assert(framed.bytesConsumed == kInitialTsRequest.size());
    const auto result = unconfigured.acceptFramedNegoRequest(reader);
    assert(result.status == SpnegoStatus::Rejected);
    assert(result.outputToken.empty());
    assert(unconfigured.stage() == SpnegoStage::Failed);
    assert(unconfigured.verifiedPrincipal().empty());
    assert(reader.status() == TsRequestFrameStatus::Closed);
    assert(reader.completeDer().empty());
    assert(reader.bytesNeeded() == 0);

    GssapiSpnegoAcceptor premature;
    TsRequestFrameReader incomplete;
    assert(incomplete.consume(
        std::span(kInitialTsRequest).first(4)).status ==
        TsRequestFrameStatus::NeedMore);
    assert(premature.acceptFramedNegoRequest(incomplete).status ==
           SpnegoStatus::Rejected);
    assert(incomplete.status() == TsRequestFrameStatus::Closed);
    assert(premature.stage() == SpnegoStage::Failed);

    GssapiSpnegoAcceptor unsupportedVersion;
    TsRequestFrameReader oldVersion;
    auto downgraded = kInitialTsRequest;
    downgraded[6] = 4;
    assert(oldVersion.consume(downgraded).status ==
           TsRequestFrameStatus::Complete);
    assert(unsupportedVersion.acceptFramedNegoRequest(oldVersion).status ==
           SpnegoStatus::Rejected);
    assert(unsupportedVersion.stage() == SpnegoStage::Failed);
    assert(oldVersion.completeDer().empty());
    assert(oldVersion.status() == TsRequestFrameStatus::Closed);

    GssapiSpnegoAcceptor malformed;
    TsRequestFrameReader rejectedFrame;
    const std::array<std::uint8_t, 2> wrongTag{0x31, 0x00};
    assert(rejectedFrame.consume(wrongTag).status ==
           TsRequestFrameStatus::Invalid);
    assert(malformed.acceptFramedNegoRequest(rejectedFrame).status ==
           SpnegoStatus::Rejected);
    assert(malformed.stage() == SpnegoStage::Failed);
}

// This intentionally controllable source can produce a policy-matching
// candidate from synthetic inputs. It CANNOT authenticate Kerberos or the
// OS. The GSS-to-OS gate must refuse even reading this source when no
// independently TLS-bound provider name exists.
class CountingConsoleEvidenceSource final : public ConsoleOsEvidenceSource
{
public:
    int accountReads{};
    int sessionReads{};
    int clockReads{};

    [[nodiscard]] ConsoleAccountObservation readUnixAccount(
        std::string_view account) noexcept override
    {
        ++accountReads;
        return {ConsoleEvidenceReadStatus::Observed, account, 1001};
    }

    [[nodiscard]] ConsoleSessionObservation readActiveConsole() noexcept override
    {
        ++sessionReads;
        return {ConsoleEvidenceReadStatus::Observed,
                "c2", "seat0", ":0", 1001, 4, 1000, true, true};
    }

    [[nodiscard]] std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override
    {
        ++clockReads;
        return 1001;
    }

    void reset() noexcept
    {
        accountReads = 0;
        sessionReads = 0;
        clockReads = 0;
    }

    [[nodiscard]] bool untouched() const noexcept
    {
        return accountReads == 0 && sessionReads == 0 && clockReads == 0;
    }
};

using NativeAdmissionIssue = decltype(&LinuxConsoleAdmissionBroker::issue);
using R3McsAdmission =
    decltype(&LinuxConsoleAdmissionBroker::authorizeR3McsConnectInitial);
using R3NativeChange =
    decltype(&LinuxConsoleAdmissionBroker::onNativeSessionChangeReady);
using R3ProtectedTransition =
    decltype(&LinuxConsoleAdmissionBroker::authorizeR3ProtectedTransition);
using R3ConnectResponseWrite =
    decltype(&LinuxConsoleAdmissionBroker::authorizeR3ConnectResponseWrite);
using R3ConnectResponseCompletion =
    decltype(&LinuxConsoleAdmissionBroker::completeR3ConnectResponseWrite);

static_assert(!std::is_default_constructible_v<LinuxConsoleAdmissionLease>);
static_assert(!std::is_copy_constructible_v<LinuxConsoleAdmissionLease>);
static_assert(!std::is_copy_assignable_v<LinuxConsoleAdmissionLease>);
static_assert(std::is_move_constructible_v<LinuxConsoleAdmissionLease>);
static_assert(!std::is_invocable_v<
              NativeAdmissionIssue,
              LinuxConsoleAdmissionBroker &,
              GssapiSpnegoAcceptor &,
              const SSL *,
              const ConsoleEvidenceRequest &,
              CountingConsoleEvidenceSource &>);
static_assert(std::is_invocable_r_v<
              McsSessionIntake,
              R3McsAdmission,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease &,
              GssapiSpnegoAcceptor &,
              const SSL *,
              McsSessionLifecycle &,
              std::span<const std::uint8_t>>);
static_assert(!std::is_invocable_v<
              R3McsAdmission,
              LinuxConsoleAdmissionBroker &,
              bool,
              GssapiSpnegoAcceptor &,
              const SSL *,
              McsSessionLifecycle &,
              std::span<const std::uint8_t>>);
static_assert(std::is_invocable_r_v<
              bool,
              R3NativeChange,
              LinuxConsoleAdmissionBroker &,
              GssapiSpnegoAcceptor &,
              McsSessionLifecycle &>);
static_assert(std::is_invocable_r_v<
              bool,
              R3ProtectedTransition,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease &,
              GssapiSpnegoAcceptor &,
              const SSL *,
              McsSessionLifecycle &,
              std::uint32_t>);
static_assert(!std::is_invocable_v<
              R3ProtectedTransition,
              LinuxConsoleAdmissionBroker &,
              bool,
              GssapiSpnegoAcceptor &,
              const SSL *,
              McsSessionLifecycle &,
              std::uint32_t>);
static_assert(std::is_invocable_v<
              R3ConnectResponseWrite,
              LinuxConsoleAdmissionBroker &,
              const LinuxConsoleAdmissionLease &,
              GssapiSpnegoAcceptor &,
              const rdp_server::server::transport::OwnedPreauthTcpConnection &,
              McsSessionLifecycle &>);
static_assert(!std::is_invocable_v<
              R3ConnectResponseWrite,
              LinuxConsoleAdmissionBroker &,
              bool,
              GssapiSpnegoAcceptor &,
              const rdp_server::server::transport::SecurityNegotiationProvenance &,
              McsSessionLifecycle &>);
static_assert(std::is_invocable_r_v<
              rdp_server::server::transport::McsConnectResponseWriteOutcome,
              R3ConnectResponseCompletion,
              LinuxConsoleAdmissionBroker &,
              GssapiSpnegoAcceptor &,
              McsSessionLifecycle &,
              std::uint64_t, std::uint64_t, std::size_t>);

void testNativeAdmissionCapabilityDenials()
{
    ConsoleIdentityPolicy policy;
    assert(policy.generation() == 0);
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    assert(policy.generation() == 1);

    const ConsoleEvidenceRequest request{
        "alice@EXAMPLE.TEST", "alice", "seat0", ":0",
        kConsoleViewPermission};

    // No provider-derived GSS/TLS identity: fail before any positive native
    // admission can exist, then remain terminal on replay.
    GssapiSpnegoAcceptor unverified;
    LinuxConsoleAdmissionBroker broker(policy);
    assert(broker.state() == LinuxConsoleAdmissionState::Ready);
    const auto denied = broker.issue(unverified, nullptr, request);
    assert(!denied.has_value());
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(broker.nativeChangeFd() == -1);
    assert(broker.nativeChangeEvents() == -1);
    assert(unverified.stage() == SpnegoStage::Failed);

    const auto replay = broker.issue(unverified, nullptr, request);
    assert(!replay.has_value());
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);

    // Only successful policy mutation advances the lease-revocation epoch.
    const std::uint64_t generation = policy.generation();
    assert(policy.add({"alice@EXAMPLE.TEST", "other", "seat0", ":0",
                       1002, kConsoleViewPermission}) ==
           ConsoleRuleError::Duplicate);
    assert(policy.generation() == generation);
    assert(policy.add({"bob@EXAMPLE.TEST", "bob", "seat0", ":0",
                       1002, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    assert(policy.generation() == generation + 1);
}

void testR3McsAdmissionContract()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);

    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    assert(session.licensingPhase() == RdpLicensingPhase::NotStarted);

    // No fake positive lease is constructed by this test. Exercise the
    // production cancellation barrier that R1 must use on disconnect:
    // R3 protocol state closes before R2/GSS is revoked.
    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage() == SpnegoStage::Failed);

    // Repeated readiness/disconnect callbacks cannot revive either owner.
    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
}

void testR3ProtectedTransitionGenerationFence()
{
    // Public scalar generation values are revocation-only. Before a genuine
    // private R2 handoff no pair, including nonzero guesses, can make the sole
    // R3 owner retain state or advance toward Connect Response.
    McsSessionLifecycle guessed;
    assert(guessed.phase() == McsSessionPhase::AwaitVerifiedR2Admission);
    guessed.revokeUnlessAdmissionBindingMatches(1, 1);
    assert(guessed.phase() == McsSessionPhase::Closed);
    assert(guessed.licensingPhase() == RdpLicensingPhase::Closed);
    assert(guessed.pendingJoinConfirmation().empty());

    McsSessionLifecycle zero;
    zero.revokeUnlessAdmissionBindingMatches(0, 0);
    assert(zero.phase() == McsSessionPhase::Closed);
    assert(zero.licensingPhase() == RdpLicensingPhase::Closed);

    // Repeated or changed scalar input cannot revive a terminal owner.
    zero.revokeUnlessAdmissionBindingMatches(UINT64_MAX, UINT64_MAX);
    assert(zero.phase() == McsSessionPhase::Closed);
    assert(zero.pendingJoinConfirmation().empty());
    assert(!zero.channelJoinConfirmed(1003U));
}


void testR3ConnectResponseWriteContract()
{
    using Outcome =
        rdp_server::server::transport::McsConnectResponseWriteOutcome;
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST","alice","seat0",":0",
                       1001,kConsoleViewPermission})==
           ConsoleRuleError::None);
    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    assert(broker.completeR3ConnectResponseWrite(
        acceptor,session,1U,1U,0U)==Outcome::Rejected);
    assert(session.phase()==McsSessionPhase::Closed);
    assert(session.licensingPhase()==RdpLicensingPhase::Closed);
    assert(broker.state()==LinuxConsoleAdmissionState::Revoked);
    assert(acceptor.stage()==SpnegoStage::Failed);
    assert(broker.completeR3ConnectResponseWrite(
        acceptor,session,1U,1U,1U)==Outcome::Rejected);
    assert(session.phase()==McsSessionPhase::Closed);
}

void testR3NativeChangeRevocation()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);

    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;

    // A readiness callback without a successfully issued concrete native
    // lease/watch is never ignored or promoted into authorization.
    assert(!broker.onNativeSessionChangeReady(acceptor, session));
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(broker.nativeChangeFd() == -1);
    assert(broker.nativeChangeEvents() == -1);
    assert(acceptor.stage() == SpnegoStage::Failed);

    // Late/repeated event-loop delivery cannot revive any owner.
    assert(!broker.onNativeSessionChangeReady(acceptor, session));
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
}


void testR3McsDisconnectRevocationFence()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);

    constexpr std::array<std::uint8_t, 12> lateJoin{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x06, 0x03, 0xeb};
    constexpr std::array<std::uint8_t, 9> lateDisconnect{
        0x03, 0x00, 0x00, 0x09, 0x02, 0xf0, 0x80, 0x21, 0x80};

    const auto parsedJoin =
        rdp_server::server::transport::parseMcsChannelRequest(lateJoin);
    assert(parsedJoin);
    assert(parsedJoin.request.kind ==
           rdp_server::server::transport::McsChannelRequestKind::ChannelJoin);
    const auto parsedDisconnect =
        rdp_server::server::transport::parseMcsChannelRequest(lateDisconnect);
    assert(parsedDisconnect);
    assert(parsedDisconnect.request.kind ==
           rdp_server::server::transport::McsChannelRequestKind::
               DisconnectProviderUltimatum);

    GssapiSpnegoAcceptor acceptor;
    LinuxConsoleAdmissionBroker broker(policy);
    McsSessionLifecycle session;
    assert(session.phase() == McsSessionPhase::AwaitVerifiedR2Admission);

    // Model R1 disconnect using the real R2->R3 cancellation barrier. Once
    // R3 closes, syntactically valid queued/late MCS work cannot revive it or
    // produce a join confirmation, even if a readiness callback arrives late.
    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
    assert(broker.nativeChangeFd() == -1);
    assert(broker.nativeChangeEvents() == -1);
    assert(acceptor.stage() == SpnegoStage::Failed);

    assert(session.onDomainPdu(lateJoin) == McsSessionIntake::Closed);
    assert(session.onDomainPdu(lateDisconnect) == McsSessionIntake::Closed);
    assert(session.pendingJoinConfirmation().empty());
    assert(!session.channelJoinConfirmed(1003U));
    assert(session.phase() == McsSessionPhase::Closed);
    assert(session.licensingPhase() == RdpLicensingPhase::Closed);

    // Duplicate teardown after late work remains terminal and idempotent.
    broker.revokeR3Session(acceptor, session);
    assert(session.phase() == McsSessionPhase::Closed);
    assert(broker.state() == LinuxConsoleAdmissionState::Revoked);
}

void testConsoleGssProvenanceBeforeOsRead()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    const ConsoleEvidenceRequest request{
        "alice@EXAMPLE.TEST", "alice", "seat0", ":0",
        kConsoleViewPermission};
    CountingConsoleEvidenceSource fakeSource;
    // A fake source can report policy-consistent values, proving why
    // CandidateOnly must NEVER be treated as admission authority.
    assert(ConsoleOsEvidenceInspector{}.inspect(
        policy, request, fakeSource) == ConsoleEvidenceMatch::CandidateOnly);
    assert(fakeSource.accountReads == 1 &&
           fakeSource.sessionReads == 1 && fakeSource.clockReads == 1);
    fakeSource.reset();

    // A plausible caller identity with no GSS/TLS proof cannot even
    // trigger a read-only OS sample, let alone grant access.
    GssapiSpnegoAcceptor noKerberos;
    ConsoleAdmissionGate gate(policy);
    assert(gate.state() == ConsoleAdmissionState::NotRequested);
    assert(noKerberos.verifiedPrincipal().empty());
    gate.requestWithOsEvidence(noKerberos, request, fakeSource);
    assert(gate.state() == ConsoleAdmissionState::Denied);
    assert(noKerberos.stage() == SpnegoStage::Failed);
    assert(noKerberos.verifiedPrincipal().empty());
    assert(fakeSource.untouched());

    // The terminal gate and rejected provider may not be replayed, even
    // with different caller identity and a source that would match.
    const ConsoleEvidenceRequest forged{
        "bob@EXAMPLE.TEST", "alice", "seat0", ":0",
        kConsoleViewPermission};
    gate.requestWithOsEvidence(noKerberos, forged, fakeSource);
    assert(gate.state() == ConsoleAdmissionState::Denied);
    assert(fakeSource.untouched());

    // Even a genuinely attempted but failed explicit-keytab provider
    // must never sample OS data or return a candidate.
    GssapiSpnegoAcceptor missingProvider;
    assert(!missingProvider.configure(
        "TERMSRV/rdp.example.test@EXAMPLE.TEST",
        "FILE:/__rdp_server_gssapi_ci_nonexistent__/missing.keytab"));
    ConsoleAdmissionGate failedGate(policy);
    failedGate.requestWithOsEvidence(missingProvider, request, fakeSource);
    assert(failedGate.state() == ConsoleAdmissionState::Denied);
    assert(missingProvider.stage() == SpnegoStage::Failed);
    assert(fakeSource.untouched());

    // The historical caller-constructed policy snapshot is permanently
    // deny-only, even when its rule fields are otherwise consistent.
    GssapiSpnegoAcceptor snapshotProvider;
    ConsoleAdmissionGate snapshotGate(policy);
    snapshotGate.request(
        snapshotProvider, {"alice@EXAMPLE.TEST", "alice", "seat0",
                           ":0", 1001, 1001, kConsoleViewPermission});
    assert(snapshotGate.state() == ConsoleAdmissionState::Denied);
    assert(snapshotProvider.stage() == SpnegoStage::Failed);
    assert(fakeSource.untouched());
}

} // namespace

int main(int argc, char **argv)
{
    const auto invoke = [](std::string_view name) -> int
    {
        if (name == "gssapi-configuration-rejections")
        {
            testConfigurationRejections();
            return 0;
        }
        if (name == "gssapi-framed-handoff")
        {
            testFramedGssHandoffFailClosed();
            return 0;
        }
        if (name == "gssapi-console-provenance-before-os-read")
        {
            testConsoleGssProvenanceBeforeOsRead();
            return 0;
        }
        if (name == "gssapi-native-os-admission-capability-denials")
        {
            testNativeAdmissionCapabilityDenials();
            return 0;
        }
        if (name == "gssapi-r3-mcs-admission-contract")
        {
            testR3McsAdmissionContract();
            return 0;
        }
        if (name == "gssapi-r3-protected-transition-generation-fence")
        {
            testR3ProtectedTransitionGenerationFence();
            return 0;
        }
        if (name == "gssapi-r3-connect-response-write-contract")
        {
            testR3ConnectResponseWriteContract();
            return 0;
        }
        if (name == "gssapi-r3-native-change-revocation")
        {
            testR3NativeChangeRevocation();
            return 0;
        }
        if (name == "gssapi-r3-mcs-disconnect-revocation-fence")
        {
            testR3McsDisconnectRevocationFence();
            return 0;
        }
        return 2;
    };
    if (argc == 2)
    {
        return invoke(argv[1]);
    }
    if (argc != 1)
    {
        return 2;
    }
    testConfigurationRejections();
    testFramedGssHandoffFailClosed();
    testConsoleGssProvenanceBeforeOsRead();
    testNativeAdmissionCapabilityDenials();
    testR3McsAdmissionContract();
    testR3ProtectedTransitionGenerationFence();
    testR3ConnectResponseWriteContract();
    testR3NativeChangeRevocation();
    testR3McsDisconnectRevocationFence();
    return 0;
}
