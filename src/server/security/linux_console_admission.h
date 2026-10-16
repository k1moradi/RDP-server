// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "console_os_evidence.h"
#include "gssapi_spnego_acceptor.h"
#include "linux_logind_console_evidence.h"
#include "linux_logind_session_change_watch.h"
#include "transport/mcs_channel_connection.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

namespace rdp_server::server::security
{

class LinuxConsoleAdmissionControl;

enum class LinuxConsoleAdmissionState : std::uint8_t
{
    Ready,
    Active,
    Revoked,
};

// Move-only R2 capability. Ordinary callers cannot construct one: only the
// concrete LinuxConsoleAdmissionBroker can mint it after genuine GSS/TLS and
// native NSS/logind/session-watch checks. Metadata is bounded and contains no
// password, ticket, keytab or delegated credential plaintext.
//
// The service-owned ConsoleIdentityPolicy must outlive this lease. Dropping
// the lease revokes its shared control epoch. A lease is intentionally not
// self-sufficient for protected R3 transitions: use broker.authorizes(),
// which revalidates live GSS/TLS, policy, logind/NSS and change-watch state.
class LinuxConsoleAdmissionLease final
{
public:
    LinuxConsoleAdmissionLease() = delete;
    ~LinuxConsoleAdmissionLease();

    LinuxConsoleAdmissionLease(const LinuxConsoleAdmissionLease &) = delete;
    LinuxConsoleAdmissionLease &operator=(const LinuxConsoleAdmissionLease &) = delete;
    LinuxConsoleAdmissionLease(LinuxConsoleAdmissionLease &&other) noexcept;
    LinuxConsoleAdmissionLease &operator=(LinuxConsoleAdmissionLease &&other) noexcept;

    // Local revocation/expiry/policy-epoch status only. A false result from
    // isRevoked() does NOT replace broker.authorizes() for protected use.
    [[nodiscard]] bool isRevoked() const noexcept;

    [[nodiscard]] std::string_view kerberosPrincipal() const noexcept;
    [[nodiscard]] std::string_view unixAccount() const noexcept;
    [[nodiscard]] std::string_view sessionId() const noexcept;
    [[nodiscard]] std::uint32_t localUid() const noexcept;
    [[nodiscard]] std::uint64_t sessionGeneration() const noexcept;
    [[nodiscard]] std::uint32_t permissionMask() const noexcept;
    [[nodiscard]] std::uint64_t admissionGeneration() const noexcept;

private:
    friend class LinuxConsoleAdmissionBroker;

    LinuxConsoleAdmissionLease(
        std::shared_ptr<LinuxConsoleAdmissionControl> control,
        std::uint64_t admissionGeneration,
        std::string_view kerberosPrincipal,
        std::string_view unixAccount,
        const ConsoleCandidateSessionFingerprint &fingerprint,
        std::uint32_t permissions) noexcept;

    void revokeControl() noexcept;
    void clearMetadata() noexcept;

    std::shared_ptr<LinuxConsoleAdmissionControl> control_{};
    std::array<char, 129> kerberosPrincipal_{};
    std::array<char, 33> unixAccount_{};
    std::array<char, 65> sessionId_{};
    std::size_t kerberosPrincipalLength_{};
    std::size_t unixAccountLength_{};
    std::size_t sessionIdLength_{};
    std::uint32_t localUid_{};
    std::uint64_t sessionGeneration_{};
    std::uint32_t permissions_{};
    std::uint64_t admissionGeneration_{};
};

// Linux-first production authorization broker. There is deliberately no
// ConsoleOsEvidenceSource or ConsoleSessionChangeSource injection point:
// positive issuance always constructs and owns the concrete NSS/logind reader
// and concrete logind monitor after genuine TLS-bound GSS identity exists.
//
// Broker methods are single-threaded. Lease revocation/expiry observations use
// atomics so an R3 holder can observe terminal revocation safely. The broker
// owns no SSL/GSS object. R1/R2 owners must keep those alive during calls and
// call revoke() before transport teardown. A one-second lease deadline makes
// failure to continue revalidation fail closed.
class LinuxConsoleAdmissionBroker final
{
public:
    explicit LinuxConsoleAdmissionBroker(
        const ConsoleIdentityPolicy &policy) noexcept : policy_(policy) {}
    ~LinuxConsoleAdmissionBroker();

    LinuxConsoleAdmissionBroker(const LinuxConsoleAdmissionBroker &) = delete;
    LinuxConsoleAdmissionBroker &operator=(const LinuxConsoleAdmissionBroker &) = delete;

    [[nodiscard]] std::optional<LinuxConsoleAdmissionLease> issue(
        GssapiSpnegoAcceptor &acceptor,
        const SSL *activeServerTls,
        const ConsoleEvidenceRequest &request) noexcept;

    [[nodiscard]] bool revalidate(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const SSL *activeServerTls) noexcept;

    // Required R3 consumption gate. Permission checks and all current
    // provenance checks happen immediately before a protected transition.
    // A native session event can still race after the final logind poll;
    // callers must monitor nativeChangeFd() and revoke on disconnect/teardown.
    [[nodiscard]] bool authorizes(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const SSL *activeServerTls,
        std::uint32_t requiredPermissions) noexcept;

    // R3 Basic Settings handoff. This is the only positive entry into the
    // current McsSessionLifecycle: revalidate concrete native admission with
    // view permission immediately before letting R3 parse/retain state from
    // Connect Initial. No caller-supplied bool/proof can invoke the private
    // R3 transition. Any R3 parse/order failure revokes the whole lease.
    [[nodiscard]] rdp_server::server::transport::McsSessionIntake
    authorizeR3McsConnectInitial(
        const LinuxConsoleAdmissionLease &lease,
        GssapiSpnegoAcceptor &acceptor,
        const SSL *activeServerTls,
        rdp_server::server::transport::McsSessionLifecycle &session,
        std::span<const std::uint8_t> completeTpkt) noexcept;

    // Ordered R3 -> R2/GSS cancellation barrier. The caller must stop protocol
    // buffers first, call this, and only then release R1 TLS/socket ownership.
    // Idempotent and safe when no positive lease was ever issued.
    void revokeR3Session(
        GssapiSpnegoAcceptor &acceptor,
        rdp_server::server::transport::McsSessionLifecycle &session) noexcept;

    // Connection/R3 teardown path: terminally invalidates the capability and
    // clears the GSS context. Idempotent.
    void revoke(GssapiSpnegoAcceptor &acceptor) noexcept;

    [[nodiscard]] LinuxConsoleAdmissionState state() const noexcept;
    [[nodiscard]] int nativeChangeFd() const noexcept;
    [[nodiscard]] int nativeChangeEvents() const noexcept;

private:
    void revokeControl() noexcept;
    void clearRequest() noexcept;
    void deny(GssapiSpnegoAcceptor &acceptor) noexcept;
    [[nodiscard]] bool refreshDeadline(std::uint64_t generation) noexcept;
    [[nodiscard]] bool ownsActiveLease(
        const LinuxConsoleAdmissionLease &lease) const noexcept;
    [[nodiscard]] ConsoleEvidenceRequest requestView(
        const LinuxConsoleAdmissionLease &lease) const noexcept;

    const ConsoleIdentityPolicy &policy_;
    LinuxLogindReadOnlyEvidenceSource evidence_{};
    std::unique_ptr<LinuxLogindSessionChangeSource> changes_{};
    std::shared_ptr<LinuxConsoleAdmissionControl> control_{};
    std::array<char, 17> seat_{};
    std::array<char, 9> display_{};
    std::size_t seatLength_{};
    std::size_t displayLength_{};
    LinuxConsoleAdmissionState state_{LinuxConsoleAdmissionState::Ready};
};

} // namespace rdp_server::server::security
