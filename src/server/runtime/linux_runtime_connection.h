// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "linux_runtime_security.h"
#include "runtime_licensing_authority.h"
#include "runtime_licensing_context.h"
#include "server/security/credssp_tsrequest.h"
#include "runtime_tls_context.h"
#include "server/security/linux_console_admission.h"
#include "server/transport/mcs_channel_connection.h"
#include "server/transport/nonblocking_tcp_adapter.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rdp_server::server::runtime
{

enum class LinuxCredSspStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    BindingVerified,
    CredentialsVerified,
    UnsupportedFinalCredentials,
    Invalid,
    Closed,
};

struct LinuxCredSspStepResult
{
    std::size_t plaintextBytesRead{};
    std::size_t plaintextBytesWritten{};
    LinuxCredSspStepStatus status{LinuxCredSspStepStatus::Closed};
};

enum class LinuxPreAdmissionStepStatus : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    TlsEstablished,
    BindingVerified,
    CredentialsVerified,
    UnsupportedFinalCredentials,
    Invalid,
    Closed,
};

struct LinuxPreAdmissionStepResult
{
    std::size_t plaintextBytesRead{};
    std::size_t plaintextBytesWritten{};
    LinuxPreAdmissionStepStatus status{LinuxPreAdmissionStepStatus::Closed};
};

// Exact identity for one borrowed R2 logind watcher registration. R10 never
// duplicates or closes descriptor; R2 admission/session generations prevent
// stale reconnect reuse even if the kernel later reuses the fd number.
struct LinuxRuntimeNativeChangeRegistration
{
    int descriptor{-1};
    int events{-1};
    std::uint64_t admissionGeneration{};
    std::uint64_t sessionGeneration{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return descriptor >= 0 && events > 0 &&
               admissionGeneration != 0U && sessionGeneration != 0U;
    }
};

// One nonmoving Linux connection aggregate for the eventual R10 event loop.
// It does NOT bind/listen and it does not invent protocol/authentication state:
// R1 remains the sole socket/BIO/SSL owner, R2 remains the sole native
// admission authority, and R3 remains the sole MCS session owner.
//
// The service-lifetime LinuxRuntimeSecurityConfiguration and
// RuntimeServerTlsContext must outlive this object. All methods are confined
// to one event-loop thread. revoke() is the single terminal ownership barrier:
// close R3 first, revoke R2/GSS and its lease, then release R1 TLS/socket.
class LinuxRuntimeConnection final
{
public:
    LinuxRuntimeConnection(
        LinuxRuntimeSecurityConfiguration &securityConfiguration,
        rdp_server::server::transport::OwnedNativeTcpSocket acceptedSocket)
        noexcept;
    ~LinuxRuntimeConnection();

    LinuxRuntimeConnection(const LinuxRuntimeConnection &) = delete;
    LinuxRuntimeConnection &operator=(const LinuxRuntimeConnection &) = delete;
    LinuxRuntimeConnection(LinuxRuntimeConnection &&) = delete;
    LinuxRuntimeConnection &operator=(LinuxRuntimeConnection &&) = delete;

    // True while this aggregate can make bounded protocol progress. A
    // provider-generated terminal CredSSP failure may remain writable after
    // GSS has failed but before aggregate teardown. This is never admission.
    [[nodiscard]] bool ready() const noexcept;

    [[nodiscard]] rdp_server::server::transport::TcpConnectionIoInterest
    ioInterest() const noexcept;

    // One bounded pre-admission scheduler step derived from the existing R1
    // phase/interest plus R2 CredSSP writer readiness. Wrong-direction
    // readiness returns the required direction with zero I/O. For a read,
    // R1-owned buffered TLS plaintext may permit one bounded application step
    // even when the native socket reports no new readability. The method may
    // attach one fresh R10 server TLS object only after the X.224 reply is
    // completely delivered. It never invokes R1's legacy MCS reader: positive
    // MCS remains reachable only through R2 admission.
    [[nodiscard]] LinuxPreAdmissionStepResult advancePreAdmission(
        bool readable, bool writable,
        const RuntimeServerTlsContext &tlsContext) noexcept;

    // Phase-specific compatibility delegates. A production pre-admission
    // scheduler should prefer advancePreAdmission(), because these methods do
    // not dispatch CredSSP after HYBRID TLS. They never authenticate/authorize.
    [[nodiscard]] rdp_server::server::transport::TcpPreauthEvent
    onReadable() noexcept;
    [[nodiscard]] rdp_server::server::transport::TcpPreauthEvent
    onWritable() noexcept;

    // Create a fresh SSL from the service-owned R10 context and transfer it
    // exactly once into R1. The SSL_CTX remains service-owned by tlsContext.
    [[nodiscard]] bool attachServerTls(
        const RuntimeServerTlsContext &tlsContext) noexcept;
    [[nodiscard]] rdp_server::server::transport::TlsHandshakeStatus
    onTlsIoReady() noexcept;

    // Delegate one bounded event-loop step to R2's owner-driven CredSSP/GSS
    // progression. R1 remains the sole SSL_read_ex/SSL_write_ex owner; R10
    // maps readiness and owns lifetimes only. BindingVerified is transport/GSS
    // evidence. CredentialsVerified means exact delegated account + PAM passed,
    // but native desktop admission is still required. UnsupportedFinalCredentials
    // is terminal and means final authInfo was not authorized.
    [[nodiscard]] LinuxCredSspStepResult onCredSspIoReady() noexcept;

    // Positive R2 issuance consumes the private final-credential candidate,
    // samples fresh concrete NSS/logind owner evidence, installs its change
    // watch, and only then completes R1/R2 admission. The lease never escapes
    // this aggregate.
    [[nodiscard]] bool issueAdmission(
        const rdp_server::server::security::ConsoleEvidenceRequest &request)
        noexcept;

    // R2 is the only positive entry into R3. Failure is terminal and invokes
    // the same ordered aggregate teardown.
    [[nodiscard]] rdp_server::server::transport::McsSessionIntake
    authorizeMcsConnectInitial(
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Borrow the R2-owned logind monitor fd and libsystemd poll mask only
    // after genuine admission with a live lease. Both are -1 otherwise.
    // Neither value owns/duplicates a descriptor or grants authorization.
    // Confined to the aggregate's event-loop thread: unregister the fd from
    // epoll/poll before revoke(), connection destruction or any callback that
    // can revoke the lease. Never close the borrowed fd. No registration may
    // outlive the owner or be reused on reconnect; discard queued events and
    // check the current borrow before dispatching readiness.
    [[nodiscard]] int nativeChangeFd() const noexcept;
    [[nodiscard]] int nativeChangeEvents() const noexcept;

    // Dispatch the concrete logind revocation source owned by R2. False means
    // either a spurious readiness notification or terminal revocation.
    [[nodiscard]] bool onNativeSessionChangeReady() noexcept;

    // Register only the current R2 borrow. The serialized caller must remove
    // this exact record from its poller before acknowledging unregistration.
    [[nodiscard]] std::optional<LinuxRuntimeNativeChangeRegistration>
    registerNativeChange() noexcept;
    [[nodiscard]] bool unregisterNativeChange(
        const LinuxRuntimeNativeChangeRegistration &registration) noexcept;
    // Dispatch is valid only after the exact record has been unregistered.
    // The aggregate drops registration identity before calling R2 because the
    // callback may synchronously revoke this whole connection.
    [[nodiscard]] bool dispatchNativeChangeReady(
        const LinuxRuntimeNativeChangeRegistration &registration) noexcept;

    // Consume the live R3 existing-CAL snapshot on this exact connection.
    // RuntimeLicensingContext product identity is checked before provider begin.
    [[nodiscard]] RuntimeLicensingExistingCalOperation
    beginExistingCalValidation(
        const RuntimeLicensingContext &licensingContext,
        RuntimeLicensingAuthority &authority) noexcept;
    [[nodiscard]] RuntimeLicensingExistingCalOperation
    pollExistingCalValidation() noexcept;
    [[nodiscard]] std::optional<RuntimeLicensingExistingCalDecision>
    authorizeExistingCalValidationDecision() noexcept;
    [[nodiscard]] bool retireExistingCalValidationDecision() noexcept;
    [[nodiscard]] RuntimeLicensingExistingCalOperation
    cancelExistingCalValidation() noexcept;

    // Terminal and idempotent. No object can retain a positive R2/R3
    // capability after the R1 TLS/socket is released.
    void revoke() noexcept;

    [[nodiscard]] rdp_server::server::security::SpnegoStage
    gssStage() const noexcept
    {
        return acceptor_.stage();
    }
    [[nodiscard]] rdp_server::server::security::LinuxConsoleAdmissionState
    admissionState() const noexcept;
    [[nodiscard]] rdp_server::server::transport::McsSessionPhase
    mcsPhase() const noexcept
    {
        return session_.phase();
    }
    [[nodiscard]] bool hasAdmissionLease() const noexcept
    {
        return lease_.has_value() && !lease_->isRevoked();
    }

private:
    [[nodiscard]] bool credSspReplyPending() const noexcept;
    [[nodiscard]] bool reauthorizeExistingCalValidation() noexcept;
    [[nodiscard]] bool nativeChangeRegistrationMatches(
        const LinuxRuntimeNativeChangeRegistration &registration) const
        noexcept;

    LinuxRuntimeSecurityConfiguration &securityConfiguration_;

    // Declaration order is deliberate. Explicit revoke() performs the
    // security ordering; reverse member destruction is also safe if a future
    // exception-free constructor path returns early: R3/lease/broker/GSS die
    // before R1's connection owner.
    rdp_server::server::transport::OwnedPreauthTcpConnection connection_;
    rdp_server::server::security::GssapiSpnegoAcceptor acceptor_{};
    std::optional<rdp_server::server::security::LinuxConsoleAdmissionBroker>
        broker_{};
    std::optional<rdp_server::server::security::LinuxConsoleAdmissionLease>
        lease_{};
    rdp_server::server::transport::McsSessionLifecycle session_{};
    std::optional<RuntimeExistingCalValidationBinding>
        existingCalValidation_{};
    std::optional<LinuxRuntimeNativeChangeRegistration>
        nativeChangeRegistration_{};
    bool nativeChangeRegistrationUnregistered_{};
    // Retired explicitly before the exact borrowed R1 TLS owner is canceled.
    rdp_server::server::security::TsRequestFrameReader credSspFrameReader_{};
    rdp_server::server::security::TsRequestTlsReplyWriter credSspReplyWriter_{};
    bool provisioned_{};
};

} // namespace rdp_server::server::runtime
