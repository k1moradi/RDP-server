// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_console_admission.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <memory>
#include <new>
#include <utility>

namespace rdp_server::server::security
{

class LinuxConsoleAdmissionControl final
{
public:
    std::atomic<std::uint64_t> activeGeneration{};
    std::atomic<std::int64_t> validThroughSteadyMilliseconds{};
    const ConsoleIdentityPolicy *policy{};
    std::uint64_t policyGeneration{};
};

namespace
{

inline constexpr std::int64_t kAdmissionValidityMilliseconds = 1000;
std::atomic<std::uint64_t> nextAdmissionGeneration{1};

[[nodiscard]] std::optional<std::int64_t> steadyMilliseconds() noexcept
{
    const auto count = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    if (!std::in_range<std::int64_t>(count) || count < 0)
    {
        return std::nullopt;
    }
    return static_cast<std::int64_t>(count);
}

template <std::size_t Capacity>
[[nodiscard]] bool copyBounded(
    std::array<char, Capacity> &destination,
    std::size_t &length,
    std::string_view value) noexcept
{
    if (value.empty() || value.size() >= destination.size())
    {
        return false;
    }
    destination.fill('\0');
    std::copy(value.begin(), value.end(), destination.begin());
    length = value.size();
    return true;
}

} // namespace

LinuxConsoleAdmissionLease::LinuxConsoleAdmissionLease(
    std::shared_ptr<LinuxConsoleAdmissionControl> control,
    std::uint64_t admissionGeneration,
    std::string_view kerberosPrincipal,
    std::string_view unixAccount,
    const ConsoleCandidateSessionFingerprint &fingerprint,
    std::uint32_t permissions) noexcept
    : control_(std::move(control)),
      kerberosPrincipalLength_(kerberosPrincipal.size()),
      unixAccountLength_(unixAccount.size()),
      sessionIdLength_(fingerprint.sessionIdLength),
      localUid_(fingerprint.accountUid),
      sessionGeneration_(fingerprint.sessionGeneration),
      permissions_(permissions),
      admissionGeneration_(admissionGeneration)
{
    std::copy(kerberosPrincipal.begin(), kerberosPrincipal.end(),
              kerberosPrincipal_.begin());
    std::copy(unixAccount.begin(), unixAccount.end(), unixAccount_.begin());
    std::copy_n(
        fingerprint.sessionId.begin(), fingerprint.sessionIdLength,
        sessionId_.begin());
}

LinuxConsoleAdmissionLease::~LinuxConsoleAdmissionLease()
{
    revokeControl();
    clearMetadata();
}

LinuxConsoleAdmissionLease::LinuxConsoleAdmissionLease(
    LinuxConsoleAdmissionLease &&other) noexcept
    : control_(std::move(other.control_)),
      kerberosPrincipal_(other.kerberosPrincipal_),
      unixAccount_(other.unixAccount_),
      sessionId_(other.sessionId_),
      kerberosPrincipalLength_(other.kerberosPrincipalLength_),
      unixAccountLength_(other.unixAccountLength_),
      sessionIdLength_(other.sessionIdLength_),
      localUid_(other.localUid_),
      sessionGeneration_(other.sessionGeneration_),
      permissions_(other.permissions_),
      admissionGeneration_(other.admissionGeneration_)
{
    other.clearMetadata();
}

LinuxConsoleAdmissionLease &LinuxConsoleAdmissionLease::operator=(
    LinuxConsoleAdmissionLease &&other) noexcept
{
    if (this == &other)
    {
        return *this;
    }
    revokeControl();
    clearMetadata();
    control_ = std::move(other.control_);
    kerberosPrincipal_ = other.kerberosPrincipal_;
    unixAccount_ = other.unixAccount_;
    sessionId_ = other.sessionId_;
    kerberosPrincipalLength_ = other.kerberosPrincipalLength_;
    unixAccountLength_ = other.unixAccountLength_;
    sessionIdLength_ = other.sessionIdLength_;
    localUid_ = other.localUid_;
    sessionGeneration_ = other.sessionGeneration_;
    permissions_ = other.permissions_;
    admissionGeneration_ = other.admissionGeneration_;
    other.clearMetadata();
    return *this;
}

void LinuxConsoleAdmissionLease::revokeControl() noexcept
{
    if (!control_ || admissionGeneration_ == 0)
    {
        return;
    }
    std::uint64_t expected = admissionGeneration_;
    (void)control_->activeGeneration.compare_exchange_strong(
        expected, 0, std::memory_order_acq_rel, std::memory_order_acquire);
    control_->validThroughSteadyMilliseconds.store(
        0, std::memory_order_release);
}

void LinuxConsoleAdmissionLease::clearMetadata() noexcept
{
    kerberosPrincipal_.fill('\0');
    unixAccount_.fill('\0');
    sessionId_.fill('\0');
    kerberosPrincipalLength_ = 0;
    unixAccountLength_ = 0;
    sessionIdLength_ = 0;
    localUid_ = 0;
    sessionGeneration_ = 0;
    permissions_ = 0;
    admissionGeneration_ = 0;
}

bool LinuxConsoleAdmissionLease::isRevoked() const noexcept
{
    if (!control_ || admissionGeneration_ == 0 ||
        control_->activeGeneration.load(std::memory_order_acquire) !=
            admissionGeneration_)
    {
        return true;
    }

    const auto now = steadyMilliseconds();
    const std::int64_t deadline =
        control_->validThroughSteadyMilliseconds.load(
            std::memory_order_acquire);
    const bool policyChanged =
        control_->policy == nullptr ||
        control_->policy->generation() != control_->policyGeneration;
    if (!now.has_value() || deadline <= 0 || *now > deadline ||
        policyChanged)
    {
        std::uint64_t expected = admissionGeneration_;
        (void)control_->activeGeneration.compare_exchange_strong(
            expected, 0, std::memory_order_acq_rel,
            std::memory_order_acquire);
        control_->validThroughSteadyMilliseconds.store(
            0, std::memory_order_release);
        return true;
    }
    return false;
}

std::string_view LinuxConsoleAdmissionLease::kerberosPrincipal() const noexcept
{
    return isRevoked()
               ? std::string_view{}
               : std::string_view(
                     kerberosPrincipal_.data(), kerberosPrincipalLength_);
}

std::string_view LinuxConsoleAdmissionLease::unixAccount() const noexcept
{
    return isRevoked()
               ? std::string_view{}
               : std::string_view(unixAccount_.data(), unixAccountLength_);
}

std::string_view LinuxConsoleAdmissionLease::sessionId() const noexcept
{
    return isRevoked()
               ? std::string_view{}
               : std::string_view(sessionId_.data(), sessionIdLength_);
}

std::uint32_t LinuxConsoleAdmissionLease::localUid() const noexcept
{
    return isRevoked() ? 0 : localUid_;
}

std::uint64_t LinuxConsoleAdmissionLease::sessionGeneration() const noexcept
{
    return isRevoked() ? 0 : sessionGeneration_;
}

std::uint32_t LinuxConsoleAdmissionLease::permissionMask() const noexcept
{
    return isRevoked() ? 0 : permissions_;
}

std::uint64_t LinuxConsoleAdmissionLease::admissionGeneration() const noexcept
{
    return isRevoked() ? 0 : admissionGeneration_;
}

LinuxConsoleAdmissionBroker::~LinuxConsoleAdmissionBroker()
{
    revokeControl();
    clearRequest();
    changes_.reset();
    state_ = LinuxConsoleAdmissionState::Revoked;
}

void LinuxConsoleAdmissionBroker::revokeControl() noexcept
{
    if (control_ != nullptr)
    {
        control_->activeGeneration.store(0, std::memory_order_release);
        control_->validThroughSteadyMilliseconds.store(
            0, std::memory_order_release);
    }
}

void LinuxConsoleAdmissionBroker::clearRequest() noexcept
{
    seat_.fill('\0');
    display_.fill('\0');
    seatLength_ = 0;
    displayLength_ = 0;
}

void LinuxConsoleAdmissionBroker::deny(
    GssapiSpnegoAcceptor &acceptor) noexcept
{
    revokeControl();
    clearRequest();
    changes_.reset();
    acceptor.reject();
    state_ = LinuxConsoleAdmissionState::Revoked;
}

bool LinuxConsoleAdmissionBroker::refreshDeadline(
    std::uint64_t generation) noexcept
{
    if (control_ == nullptr || generation == 0 ||
        control_->activeGeneration.load(std::memory_order_acquire) !=
            generation)
    {
        return false;
    }
    const auto now = steadyMilliseconds();
    if (!now.has_value() ||
        *now > std::numeric_limits<std::int64_t>::max() -
                   kAdmissionValidityMilliseconds)
    {
        return false;
    }
    control_->validThroughSteadyMilliseconds.store(
        *now + kAdmissionValidityMilliseconds, std::memory_order_release);
    return control_->activeGeneration.load(std::memory_order_acquire) ==
           generation;
}

bool LinuxConsoleAdmissionBroker::ownsActiveLease(
    const LinuxConsoleAdmissionLease &lease) const noexcept
{
    return state_ == LinuxConsoleAdmissionState::Active &&
           control_ != nullptr &&
           lease.control_.get() == control_.get() &&
           lease.admissionGeneration_ != 0 &&
           control_->activeGeneration.load(std::memory_order_acquire) ==
               lease.admissionGeneration_ &&
           !lease.isRevoked();
}

ConsoleEvidenceRequest LinuxConsoleAdmissionBroker::requestView(
    const LinuxConsoleAdmissionLease &lease) const noexcept
{
    return {
        {lease.kerberosPrincipal_.data(), lease.kerberosPrincipalLength_},
        {lease.unixAccount_.data(), lease.unixAccountLength_},
        {seat_.data(), seatLength_},
        {display_.data(), displayLength_},
        lease.permissions_};
}

std::optional<LinuxConsoleAdmissionLease>
LinuxConsoleAdmissionBroker::issue(
    GssapiSpnegoAcceptor &acceptor,
    const SSL *activeServerTls,
    const ConsoleEvidenceRequest &request) noexcept
{
    if (state_ != LinuxConsoleAdmissionState::Ready)
    {
        deny(acceptor);
        return std::nullopt;
    }

    const std::uint64_t policyGeneration = policy_.generation();
    const std::string_view proven =
        acceptor.verifiedPrincipalForTls(activeServerTls);
    if (policyGeneration == 0 || proven.empty() ||
        proven != request.kerberosPrincipal ||
        !copyBounded(seat_, seatLength_, request.seat) ||
        !copyBounded(display_, displayLength_, request.display))
    {
        deny(acceptor);
        return std::nullopt;
    }

    // Establish the concrete native change monitor only after genuine GSS/TLS
    // identity exists, but before any NSS/logind identity/session sampling.
    try
    {
        changes_ = std::make_unique<LinuxLogindSessionChangeSource>();
    }
    catch (const std::bad_alloc &)
    {
        deny(acceptor);
        return std::nullopt;
    }

    if (changes_->nativeFd() < 0 || changes_->nativeEvents() <= 0 ||
        acceptor.verifiedPrincipalForTls(activeServerTls) != proven ||
        changes_->pollChange() != ConsoleSessionChange::None)
    {
        deny(acceptor);
        return std::nullopt;
    }

    ConsoleCandidateSessionFingerprint fingerprint{};
    if (ConsoleOsEvidenceInspector{}.inspectWithSessionFingerprint(
            policy_, request, evidence_, fingerprint) !=
            ConsoleEvidenceMatch::CandidateOnly ||
        changes_->pollChange() != ConsoleSessionChange::None ||
        fingerprint.sessionIdLength == 0 ||
        fingerprint.sessionIdLength >= 65 ||
        request.kerberosPrincipal.size() >= 129 ||
        request.unixAccount.size() >= 33 ||
        policy_.generation() != policyGeneration ||
        acceptor.verifiedPrincipalForTls(activeServerTls) != proven)
    {
        deny(acceptor);
        return std::nullopt;
    }

    std::shared_ptr<LinuxConsoleAdmissionControl> newControl;
    try
    {
        newControl = std::make_shared<LinuxConsoleAdmissionControl>();
    }
    catch (const std::bad_alloc &)
    {
        deny(acceptor);
        return std::nullopt;
    }

    const std::uint64_t generation =
        nextAdmissionGeneration.fetch_add(1, std::memory_order_relaxed);
    const auto now = steadyMilliseconds();
    if (generation == 0 || !now.has_value() ||
        *now > std::numeric_limits<std::int64_t>::max() -
                   kAdmissionValidityMilliseconds)
    {
        deny(acceptor);
        return std::nullopt;
    }

    newControl->policy = &policy_;
    newControl->policyGeneration = policyGeneration;
    newControl->validThroughSteadyMilliseconds.store(
        *now + kAdmissionValidityMilliseconds, std::memory_order_relaxed);
    newControl->activeGeneration.store(
        generation, std::memory_order_release);
    control_ = std::move(newControl);
    state_ = LinuxConsoleAdmissionState::Active;

    LinuxConsoleAdmissionLease lease{
        control_, generation, request.kerberosPrincipal,
        request.unixAccount, fingerprint, request.requestedPermissions};
    return std::optional<LinuxConsoleAdmissionLease>{std::move(lease)};
}

bool LinuxConsoleAdmissionBroker::revalidate(
    const LinuxConsoleAdmissionLease &lease,
    GssapiSpnegoAcceptor &acceptor,
    const SSL *activeServerTls) noexcept
{
    const std::string_view leasePrincipal{
        lease.kerberosPrincipal_.data(), lease.kerberosPrincipalLength_};
    if (!ownsActiveLease(lease) ||
        control_->policyGeneration != policy_.generation() ||
        acceptor.verifiedPrincipalForTls(activeServerTls) != leasePrincipal ||
        changes_ == nullptr ||
        changes_->pollChange() != ConsoleSessionChange::None)
    {
        deny(acceptor);
        return false;
    }

    ConsoleCandidateSessionFingerprint fingerprint{};
    if (ConsoleOsEvidenceInspector{}.inspectWithSessionFingerprint(
            policy_, requestView(lease), evidence_, fingerprint) !=
            ConsoleEvidenceMatch::CandidateOnly ||
        changes_->pollChange() != ConsoleSessionChange::None ||
        fingerprint.sessionIdLength != lease.sessionIdLength_ ||
        std::string_view(
            fingerprint.sessionId.data(), fingerprint.sessionIdLength) !=
            std::string_view(lease.sessionId_.data(), lease.sessionIdLength_) ||
        fingerprint.accountUid != lease.localUid_ ||
        fingerprint.consoleOwnerUid != lease.localUid_ ||
        fingerprint.sessionGeneration != lease.sessionGeneration_ ||
        acceptor.verifiedPrincipalForTls(activeServerTls) != leasePrincipal ||
        !refreshDeadline(lease.admissionGeneration_))
    {
        deny(acceptor);
        return false;
    }
    return !lease.isRevoked();
}

bool LinuxConsoleAdmissionBroker::authorizes(
    const LinuxConsoleAdmissionLease &lease,
    GssapiSpnegoAcceptor &acceptor,
    const SSL *activeServerTls,
    std::uint32_t requiredPermissions) noexcept
{
    if (requiredPermissions == 0 ||
        (requiredPermissions & ~kConsoleAllowedPermissions) != 0 ||
        (lease.permissions_ & requiredPermissions) != requiredPermissions)
    {
        deny(acceptor);
        return false;
    }
    return revalidate(lease, acceptor, activeServerTls);
}

rdp_server::server::transport::McsSessionIntake
LinuxConsoleAdmissionBroker::authorizeR3McsConnectInitial(
    const LinuxConsoleAdmissionLease &lease,
    GssapiSpnegoAcceptor &acceptor,
    const SSL *activeServerTls,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using rdp_server::server::transport::McsSessionIntake;
    if (!authorizes(
            lease, acceptor, activeServerTls, kConsoleViewPermission))
    {
        session.close();
        return McsSessionIntake::AdmissionDenied;
    }

    const auto result = session.onVerifiedR2ConnectInitial(
        lease.admissionGeneration_, lease.sessionGeneration_, completeTpkt);
    if (result != McsSessionIntake::AdmittedConnectInitial)
    {
        // A malformed/wrong-order MCS envelope terminates the same identity
        // capability; never retain a valid lease for replay on a fresh R3
        // owner after this connection-level protocol violation.
        revokeR3Session(acceptor, session);
    }
    return result;
}

bool LinuxConsoleAdmissionBroker::authorizeR3ProtectedTransition(
    const LinuxConsoleAdmissionLease &lease,
    GssapiSpnegoAcceptor &acceptor,
    const SSL *activeServerTls,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint32_t requiredPermissions) noexcept
{
    // Fence the R3 owner against this exact nonforgeable lease before any
    // potentially blocking native evidence sampling. Scalars are never used
    // as positive authority: the session method can only retain or revoke.
    session.revokeUnlessAdmissionBindingMatches(
        lease.admissionGeneration_, lease.sessionGeneration_);
    if (session.phase() ==
        rdp_server::server::transport::McsSessionPhase::Closed)
    {
        revoke(acceptor);
        return false;
    }

    if (!authorizes(
            lease, acceptor, activeServerTls, requiredPermissions))
    {
        // authorizes() already revokes R2/GSS. Drop R3 state in the same
        // serialized call so stale protocol state cannot survive that denial.
        session.close();
        return false;
    }

    // No R3 phase/write mutation occurs here. The sole R3 owner may perform
    // exactly one protected transition after this synchronous authorization;
    // it must call back here again before the next one.
    return true;
}

void LinuxConsoleAdmissionBroker::revokeR3Session(
    GssapiSpnegoAcceptor &acceptor,
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    // Protocol/session state dies before authentication and before the caller
    // releases R1 TLS/socket ownership.
    session.close();
    revoke(acceptor);
}

bool LinuxConsoleAdmissionBroker::onNativeSessionChangeReady(
    GssapiSpnegoAcceptor &acceptor,
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    if (state_ != LinuxConsoleAdmissionState::Active ||
        changes_ == nullptr)
    {
        revokeR3Session(acceptor, session);
        return false;
    }

    // The event loop observed readiness on the concrete broker-owned logind
    // monitor. Reclassify it synchronously so provider failure is also a
    // revocation event. None is only a spurious wake; it never authorizes use.
    if (changes_->pollChange() == ConsoleSessionChange::None)
    {
        return true;
    }

    // Keep teardown ordering deterministic: R3 drops all protocol state before
    // GSS/TLS-bound admission is invalidated. R1 may release TLS only later.
    revokeR3Session(acceptor, session);
    return false;
}

void LinuxConsoleAdmissionBroker::revoke(
    GssapiSpnegoAcceptor &acceptor) noexcept
{
    revokeControl();
    clearRequest();
    changes_.reset();
    acceptor.reject();
    state_ = LinuxConsoleAdmissionState::Revoked;
}

LinuxConsoleAdmissionState LinuxConsoleAdmissionBroker::state() const noexcept
{
    if (state_ == LinuxConsoleAdmissionState::Active &&
        (control_ == nullptr ||
         control_->activeGeneration.load(std::memory_order_acquire) == 0))
    {
        return LinuxConsoleAdmissionState::Revoked;
    }
    return state_;
}

int LinuxConsoleAdmissionBroker::nativeChangeFd() const noexcept
{
    return state() == LinuxConsoleAdmissionState::Active &&
                   changes_ != nullptr
               ? changes_->nativeFd()
               : -1;
}

int LinuxConsoleAdmissionBroker::nativeChangeEvents() const noexcept
{
    return state() == LinuxConsoleAdmissionState::Active &&
                   changes_ != nullptr
               ? changes_->nativeEvents()
               : -1;
}

} // namespace rdp_server::server::security
