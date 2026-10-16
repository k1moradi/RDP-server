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
    return 0;
}
