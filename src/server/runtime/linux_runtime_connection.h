// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "linux_runtime_security.h"
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

    // R1 preauth/readiness delegation. These never authenticate or authorize.
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
    // evidence, not native desktop admission. UnsupportedFinalCredentials is
    // terminal and means R2 consumed but did not authorize final authInfo.
    [[nodiscard]] LinuxCredSspStepResult onCredSspIoReady() noexcept;

    // Positive R2 issuance additionally requires R2's private final-credential
    // authorization completion proof. The current deny-only credential policy
    // cannot satisfy it, even after BindingVerified. The lease never escapes
    // this aggregate.
    [[nodiscard]] bool issueAdmission(
        const rdp_server::server::security::ConsoleEvidenceRequest &request)
        noexcept;

    // R2 is the only positive entry into R3. Failure is terminal and invokes
    // the same ordered aggregate teardown.
    [[nodiscard]] rdp_server::server::transport::McsSessionIntake
    authorizeMcsConnectInitial(
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Dispatch the concrete logind revocation source owned by R2. False means
    // either a spurious readiness notification or terminal revocation.
    [[nodiscard]] bool onNativeSessionChangeReady() noexcept;

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
    // Retired explicitly before the exact borrowed R1 TLS owner is canceled.
    rdp_server::server::security::TsRequestFrameReader credSspFrameReader_{};
    rdp_server::server::security::TsRequestTlsReplyWriter credSspReplyWriter_{};
    bool provisioned_{};
};

} // namespace rdp_server::server::runtime
