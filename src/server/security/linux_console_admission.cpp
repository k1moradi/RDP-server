// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_console_admission.h"

#include "server/runtime/runtime_deployment_policy.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
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

struct R1HybridNlaSecurityView
{
    const SSL *activeServerTls{};
    rdp_server::server::transport::SecurityNegotiationProvenance provenance{};
};

[[nodiscard]] std::optional<R1HybridNlaSecurityView>
r1HybridNlaSecurityView(
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection) noexcept
{
    if (!connection.active())
    {
        return std::nullopt;
    }

    const SSL *activeServerTls = connection.establishedTls();
    const auto provenance = connection.securityNegotiationProvenance();
    if (activeServerTls == nullptr ||
        !hasHybridNlaNegotiationProvenance(provenance))
    {
        return std::nullopt;
    }
    return R1HybridNlaSecurityView{activeServerTls, *provenance};
}

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

[[nodiscard]] constexpr const char *yesNo(bool value) noexcept
{
    return value ? "yes" : "no";
}

[[nodiscard]] constexpr const char *generationMatchName(
    std::uint64_t startGeneration,
    std::uint64_t admissionGeneration) noexcept
{
    if (startGeneration == 0U || admissionGeneration == 0U)
        return "unavailable";
    return startGeneration == admissionGeneration ? "yes" : "no";
}

[[nodiscard]] constexpr const char *lockStateName(
    ConsoleDesktopLockState state) noexcept
{
    switch (state)
    {
    case ConsoleDesktopLockState::Unknown: return "unknown";
    case ConsoleDesktopLockState::Unlocked: return "unlocked";
    case ConsoleDesktopLockState::Locked: return "locked";
    }
    return "unknown";
}

void logNativeAdmissionFailure(
    const char *reason,
    const CurrentOwnerSharingAuthority *ownerAuthority,
    const LinuxLogindReadOnlyEvidenceSource &evidence,
    const LinuxLogindSessionChangeSource *changes) noexcept
{
    const auto &observation = evidence.diagnostics();
    const LinuxLogindMonitorDiagnostics monitor =
        changes != nullptr ? changes->diagnostics()
                           : LinuxLogindMonitorDiagnostics{};
    const auto ownerMismatch =
        ownerAuthority != nullptr
            ? ownerAuthority->lastAuthorizationMismatch()
            : OwnerSharingAuthorizationMismatch::NoActiveGrant;
    const auto type = observation.sessionType();
    const auto sessionClass = observation.sessionClass();
    const auto seat = observation.seat();
    const auto display = observation.display();
    const auto mismatchName =
        ownerSharingAuthorizationMismatchName(ownerMismatch);
    const auto evidenceName =
        linuxLogindObservationFailureName(observation.failure);
    const auto initialName =
        linuxLogindMonitorStateName(monitor.initialState);
    const auto baselineName =
        linuxLogindMonitorStateName(monitor.baselineState);
    const std::uint64_t startGrantGeneration =
        ownerAuthority != nullptr
            ? ownerAuthority->diagnosticGrantGeneration()
            : 0U;
    const std::uint64_t startSessionGeneration =
        ownerAuthority != nullptr
            ? ownerAuthority->diagnosticSessionGeneration()
            : 0U;
    const std::uint64_t admissionSessionGeneration =
        observation.sessionGeneration;

    // Fail-only and deliberately structural: no account name, raw session ID,
    // credential, token, clipboard byte or desktop content is emitted.
    std::fprintf(
        stderr,
        "native-admission: stage=admission; admission=%s "
        "start-admission=%.*s start-grant-generation=%llu "
        "start-session-generation=%llu admission-session-generation=%llu "
        "session-generation-match=%s logind=%s graphical-seat=%s "
        "active-session=%s type=%.*s class=%.*s seat=%.*s display=%.*s "
        "active=%s remote=%s lock=%s process-owner-match=%s "
        "session-generation-stable=%s evidence=%.*s "
        "login-monitor=%s monitor-initial=%.*s monitor-baseline=%.*s\n",
        reason,
        static_cast<int>(mismatchName.size()), mismatchName.data(),
        static_cast<unsigned long long>(startGrantGeneration),
        static_cast<unsigned long long>(startSessionGeneration),
        static_cast<unsigned long long>(admissionSessionGeneration),
        generationMatchName(startSessionGeneration, admissionSessionGeneration),
        yesNo(observation.systemdAvailable),
        yesNo(observation.graphicalSeatAvailable),
        yesNo(observation.activeSessionFound),
        static_cast<int>(type.size()), type.data(),
        static_cast<int>(sessionClass.size()), sessionClass.data(),
        static_cast<int>(seat.size()), seat.data(),
        static_cast<int>(display.size()), display.data(),
        yesNo(observation.active), yesNo(observation.remote),
        lockStateName(observation.lockState),
        yesNo(observation.processUidMatchesOwnerUid),
        yesNo(observation.sessionGenerationStable),
        static_cast<int>(evidenceName.size()), evidenceName.data(),
        yesNo(monitor.monitorAvailable),
        static_cast<int>(initialName.size()), initialName.data(),
        static_cast<int>(baselineName.size()), baselineName.data());
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
    ConsoleEvidenceAuthenticationKind authenticationKind,
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
      admissionGeneration_(admissionGeneration),
      authenticationKind_(authenticationKind)
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
      admissionGeneration_(other.admissionGeneration_),
      authenticationKind_(other.authenticationKind_)
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
    authenticationKind_ = other.authenticationKind_;
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
    authenticationKind_ =
        ConsoleEvidenceAuthenticationKind::KerberosPrincipal;
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
    personalDesktopPolicy_ = nullptr;
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
    LinuxAuthenticatedPrincipalProof &principalProof) noexcept
{
    revokeControl();
    clearRequest();
    changes_.reset();
    personalDesktopPolicy_ = nullptr;
    principalProof.revokeAuthenticatedProof();
    state_ = LinuxConsoleAdmissionState::Revoked;
}

void LinuxConsoleAdmissionBroker::denyAdmission(
    LinuxAuthenticatedPrincipalProof &principalProof,
    LinuxConsoleAdmissionFailureReason reason) noexcept
{
    lastAdmissionFailureReason_ =
        reason == LinuxConsoleAdmissionFailureReason::None
            ? LinuxConsoleAdmissionFailureReason::AdmissionRequestInvalid
            : reason;
    deny(principalProof);
}

bool LinuxConsoleAdmissionBroker::prepareAdmission(
    LinuxAuthenticatedPrincipalProof &principalProof,
    rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    const ConsoleEvidenceRequest &request,
    std::uint64_t &policyGeneration) noexcept
{
    using Failure = LinuxConsoleAdmissionFailureReason;
    policyGeneration = 0U;
    const auto reject = [&](Failure reason) noexcept {
        lastAdmissionFailureReason_ = reason;
        logNativeAdmissionFailure(
            linuxConsoleAdmissionFailureReasonName(reason).data(),
            ownerSharingAuthority_, evidence_, changes_.get());
        deny(principalProof);
        return false;
    };

    if (state_ != LinuxConsoleAdmissionState::Ready)
        return reject(Failure::AdmissionRequestInvalid);
    if (ownerSharingAuthority_ == nullptr ||
        !ownerSharingAuthority_->authorizes(request.requestedPermissions))
    {
        return reject(Failure::OwnerConsentMissing);
    }
    if (!r1HybridNlaSecurityView(connection))
        return reject(Failure::HybridTlsProvenanceInvalid);

    policyGeneration = policy_.generation();
    if (policyGeneration == 0U)
        return reject(Failure::PolicyGenerationChanged);
    if (!principalProof.pendingNativeAdmissionMatches(
            connection, request, policyGeneration))
    {
        return reject(Failure::AuthenticationProofMismatch);
    }
    if (!copyBounded(seat_, seatLength_, request.seat) ||
        !copyBounded(display_, displayLength_, request.display))
    {
        return reject(Failure::AdmissionRequestInvalid);
    }
    return true;
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
        lease.permissions_,
        lease.authenticationKind_};
}

std::optional<LinuxConsoleAdmissionLease>
LinuxConsoleAdmissionBroker::issueWithSources(
    LinuxAuthenticatedPrincipalProof &principalProof,
    rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    const ConsoleEvidenceRequest &request,
    std::uint64_t policyGeneration,
    ConsoleOsEvidenceSource &evidenceSource,
    ConsoleSessionChangeSource &changes,
    bool monitorAvailable,
    const LinuxLogindReadOnlyEvidenceSource *diagnosticEvidence,
    const LinuxLogindSessionChangeSource *diagnosticChanges) noexcept
{
    using Failure = LinuxConsoleAdmissionFailureReason;
    const auto reject = [&](Failure reason)
        -> std::optional<LinuxConsoleAdmissionLease> {
        lastAdmissionFailureReason_ = reason;
        if (diagnosticEvidence != nullptr)
        {
            logNativeAdmissionFailure(
                linuxConsoleAdmissionFailureReasonName(reason).data(),
                ownerSharingAuthority_, *diagnosticEvidence,
                diagnosticChanges);
        }
        deny(principalProof);
        return std::nullopt;
    };

    if (!monitorAvailable)
        return reject(Failure::SessionMonitorUnavailable);
    if (policy_.generation() != policyGeneration)
        return reject(Failure::PolicyGenerationChanged);
    if (!principalProof.pendingNativeAdmissionMatches(
            connection, request, policyGeneration))
    {
        return reject(Failure::AuthenticationProofMismatch);
    }

    const ConsoleSessionChange beforeEvidence = changes.pollChange();
    if (beforeEvidence != ConsoleSessionChange::None)
    {
        return reject(
            beforeEvidence == ConsoleSessionChange::Unavailable
                ? Failure::SessionMonitorUnavailable
                : Failure::SessionChangedBeforeSample);
    }

    ConsoleCandidateSessionFingerprint fingerprint{};
    const auto inspection =
        ConsoleOsEvidenceInspector{}.inspectWithSessionFingerprintDetailed(
            policy_, request, evidenceSource, fingerprint);
    if (inspection.match != ConsoleEvidenceMatch::CandidateOnly)
    {
        using Evidence = ConsoleEvidenceDenialReason;
        switch (inspection.denialReason)
        {
        case Evidence::None:
        case Evidence::AdmissionRequestInvalid:
            return reject(Failure::AdmissionRequestInvalid);
        case Evidence::AccountEvidenceUnavailable:
            return reject(Failure::AccountEvidenceUnavailable);
        case Evidence::AccountIdentityMismatch:
            return reject(Failure::AccountIdentityMismatch);
        case Evidence::ConsoleSessionUnavailable:
            return reject(Failure::ConsoleSessionUnavailable);
        case Evidence::ConsoleNotActive:
            return reject(Failure::ConsoleNotActive);
        case Evidence::ConsoleNotPhysical:
            return reject(Failure::ConsoleNotPhysical);
        case Evidence::ConsoleSessionInvalid:
            return reject(Failure::ConsoleSessionInvalid);
        case Evidence::SeatMismatch:
            return reject(Failure::SeatMismatch);
        case Evidence::DisplayMismatch:
            return reject(Failure::DisplayMismatch);
        case Evidence::ConsoleOwnerMismatch:
            return reject(Failure::ConsoleOwnerMismatch);
        case Evidence::EvidenceTooOld:
            return reject(Failure::EvidenceTooOld);
        case Evidence::PolicyMismatch:
            return reject(Failure::PolicyMismatch);
        }
    }

    const ConsoleSessionChange afterEvidence = changes.pollChange();
    if (afterEvidence != ConsoleSessionChange::None)
    {
        return reject(
            afterEvidence == ConsoleSessionChange::Unavailable
                ? Failure::SessionMonitorUnavailable
                : Failure::SessionChangedBeforeSample);
    }
    if (fingerprint.sessionIdLength == 0 ||
        fingerprint.sessionIdLength >= 65 ||
        request.kerberosPrincipal.size() >= 129 ||
        request.unixAccount.size() >= 33)
    {
        return reject(Failure::AdmissionRequestInvalid);
    }
    if (policy_.generation() != policyGeneration)
        return reject(Failure::PolicyGenerationChanged);
    if (!principalProof.pendingNativeAdmissionMatches(
            connection, request, policyGeneration))
    {
        return reject(Failure::AuthenticationProofMismatch);
    }

    std::shared_ptr<LinuxConsoleAdmissionControl> newControl;
    try
    {
        newControl = std::make_shared<LinuxConsoleAdmissionControl>();
    }
    catch (const std::bad_alloc &)
    {
        return reject(Failure::NativeProofCompletionFailed);
    }

    const std::uint64_t generation =
        nextAdmissionGeneration.fetch_add(1, std::memory_order_relaxed);
    const auto now = steadyMilliseconds();
    if (generation == 0 || !now.has_value() ||
        *now > std::numeric_limits<std::int64_t>::max() -
                   kAdmissionValidityMilliseconds)
    {
        return reject(Failure::NativeProofCompletionFailed);
    }

    if (!principalProof.completeNativeAdmission(
            connection, request, policyGeneration))
    {
        return reject(Failure::NativeProofCompletionFailed);
    }
    if (!connection.completeCredSspAdmission())
        return reject(Failure::CredSspAdmissionCompletionFailed);

    newControl->policy = &policy_;
    newControl->policyGeneration = policyGeneration;
    newControl->validThroughSteadyMilliseconds.store(
        *now + kAdmissionValidityMilliseconds, std::memory_order_relaxed);
    newControl->activeGeneration.store(
        generation, std::memory_order_release);
    control_ = std::move(newControl);
    state_ = LinuxConsoleAdmissionState::Active;
    lastAdmissionFailureReason_ = Failure::None;

    LinuxConsoleAdmissionLease lease{
        control_, generation, request.authenticationKind,
        request.kerberosPrincipal, request.unixAccount,
        fingerprint, request.requestedPermissions};
    return std::optional<LinuxConsoleAdmissionLease>{std::move(lease)};
}

std::optional<LinuxConsoleAdmissionLease>
LinuxConsoleAdmissionBroker::issue(
    LinuxAuthenticatedPrincipalProof &principalProof,
    rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    const ConsoleEvidenceRequest &request) noexcept
{
    lastAdmissionFailureReason_ = LinuxConsoleAdmissionFailureReason::None;
    std::uint64_t policyGeneration = 0U;
    if (!prepareAdmission(
            principalProof, connection, request, policyGeneration))
    {
        return std::nullopt;
    }

    try
    {
        changes_ = std::make_unique<LinuxLogindSessionChangeSource>();
    }
    catch (const std::bad_alloc &)
    {
        lastAdmissionFailureReason_ =
            LinuxConsoleAdmissionFailureReason::SessionMonitorUnavailable;
        logNativeAdmissionFailure(
            linuxConsoleAdmissionFailureReasonName(
                lastAdmissionFailureReason_).data(),
            ownerSharingAuthority_, evidence_, nullptr);
        deny(principalProof);
        return std::nullopt;
    }

    const bool monitorAvailable =
        changes_->nativeFd() >= 0 && changes_->nativeEvents() > 0;
    return issueWithSources(
        principalProof, connection, request, policyGeneration,
        evidence_, *changes_, monitorAvailable, &evidence_, changes_.get());
}

std::optional<LinuxConsoleAdmissionLease>
LinuxConsoleAdmissionBroker::issue(
    LinuxAuthenticatedPrincipalProof &principalProof,
    const SSL *activeServerTls,
    const ConsoleEvidenceRequest &request) noexcept
{
    // Compatibility only: an arbitrary SSL* cannot establish that the same
    // R1-owned connection selected NLA/HYBRID. Never sample native evidence
    // or preserve authentication-proof state through this route.
    (void)activeServerTls;
    (void)request;
    denyAdmission(
        principalProof,
        LinuxConsoleAdmissionFailureReason::HybridTlsProvenanceInvalid);
    return std::nullopt;
}

bool LinuxConsoleAdmissionBroker::revalidationChecksPass(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const SSL *activeServerTls) noexcept
{
    // Every protected R2 operation revalidates affirmative native authority.
    if (ownerSharingAuthority_ == nullptr ||
        !ownerSharingAuthority_->authorizes(lease.permissions_) ||
        !ownsActiveLease(lease) ||
        control_->policyGeneration != policy_.generation() ||
        !principalProof.revalidatesNativeAdmission(
            activeServerTls, requestView(lease),
            control_->policyGeneration) ||
        changes_ == nullptr ||
        changes_->pollChange() != ConsoleSessionChange::None)
    {
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
        !principalProof.revalidatesNativeAdmission(
            activeServerTls, requestView(lease),
            control_->policyGeneration) ||
        !refreshDeadline(lease.admissionGeneration_))
    {
        return false;
    }
    return !lease.isRevoked();
}

bool LinuxConsoleAdmissionBroker::authorizationChecksPass(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const SSL *activeServerTls,
    std::uint32_t requiredPermissions) noexcept
{
    return requiredPermissions != 0 &&
           (requiredPermissions & ~kConsoleAllowedPermissions) == 0 &&
           (lease.permissions_ & requiredPermissions) == requiredPermissions &&
           revalidationChecksPass(lease, principalProof, activeServerTls);
}

bool LinuxConsoleAdmissionBroker::revalidate(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection) noexcept
{
    const auto r1Security = r1HybridNlaSecurityView(connection);
    if (r1Security &&
        revalidationChecksPass(
            lease, principalProof, r1Security->activeServerTls))
    {
        return true;
    }
    deny(principalProof);
    return false;
}

bool LinuxConsoleAdmissionBroker::authorizes(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection,
    std::uint32_t requiredPermissions) noexcept
{
    const auto r1Security = r1HybridNlaSecurityView(connection);
    if (r1Security &&
        authorizationChecksPass(
            lease, principalProof, r1Security->activeServerTls,
            requiredPermissions))
    {
        return true;
    }
    deny(principalProof);
    return false;
}

rdp_server::server::transport::McsSessionIntake
LinuxConsoleAdmissionBroker::authorizeR3McsConnectInitial(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using rdp_server::server::transport::McsSessionIntake;
    const auto r1Security = r1HybridNlaSecurityView(connection);
    if (!r1Security ||
        !authorizationChecksPass(
            lease, principalProof, r1Security->activeServerTls,
            kConsoleViewPermission))
    {
        revokeR3Session(principalProof, session);
        return McsSessionIntake::AdmissionDenied;
    }

    const auto result = session.onVerifiedR2ConnectInitial(
        lease.admissionGeneration_, lease.sessionGeneration_, completeTpkt);
    if (result != McsSessionIntake::AdmittedConnectInitial)
    {
        // A malformed/wrong-order MCS envelope terminates the same identity
        // capability; never retain a valid lease for replay on a fresh R3
        // owner after this connection-level protocol violation.
        revokeR3Session(principalProof, session);
    }
    return result;
}

bool LinuxConsoleAdmissionBroker::authorizeR3ProtectedTransitionForEstablishedTls(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const SSL *activeServerTls,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint32_t requiredPermissions) noexcept
{
    // This private helper is reachable only after the caller derived an
    // established TLS pointer plus genuine HYBRID provenance from one live
    // R1 owner. Fence R3 before any potentially blocking native sampling.
    session.revokeUnlessAdmissionBindingMatches(
        lease.admissionGeneration_, lease.sessionGeneration_);
    if (session.phase() ==
        rdp_server::server::transport::McsSessionPhase::Closed)
    {
        revoke(principalProof);
        return false;
    }

    if (!authorizationChecksPass(
            lease, principalProof, activeServerTls, requiredPermissions))
    {
        // Preserve ordered R3 -> R2/authentication-proof teardown on every protected denial.
        revokeR3Session(principalProof, session);
        return false;
    }

    // No R3 phase/write mutation occurs here. The sole R3 owner may perform
    // exactly one protected transition after this synchronous authorization;
    // it must call back here again before the next one.
    return true;
}

bool LinuxConsoleAdmissionBroker::authorizeR3ProtectedTransition(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint32_t requiredPermissions) noexcept
{
    const auto r1Security = r1HybridNlaSecurityView(connection);
    if (!r1Security)
    {
        revokeR3Session(principalProof, session);
        return false;
    }
    return authorizeR3ProtectedTransitionForEstablishedTls(
        lease, principalProof, r1Security->activeServerTls, session,
        requiredPermissions);
}


std::optional<rdp_server::server::transport::McsConnectResponseWriteView>
LinuxConsoleAdmissionBroker::authorizeR3ConnectResponseWrite(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    const auto r1Security = r1HybridNlaSecurityView(connection);
    if (!r1Security ||
        !authorizeR3ProtectedTransitionForEstablishedTls(
            lease, principalProof, r1Security->activeServerTls, session,
            kConsoleViewPermission))
    {
        if (session.phase() !=
            rdp_server::server::transport::McsSessionPhase::Closed)
        {
            revokeR3Session(principalProof, session);
        }
        else
        {
            revoke(principalProof);
        }
        return std::nullopt;
    }

    const auto pending =
        session.prepareConnectResponseWrite(r1Security->provenance);
    if (!pending)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }
    return pending;
}

rdp_server::server::transport::McsConnectResponseWriteOutcome
LinuxConsoleAdmissionBroker::completeR3ConnectResponseWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome =
        rdp_server::server::transport::McsConnectResponseWriteOutcome;

    // Bytes may already have been accepted by R1/TLS after the pre-write
    // authorization. Do not let a late callback turn those bytes into durable
    // R3 writer/phase progress after policy, native session, GSS or TLS
    // provenance has gone stale.
    const auto r1Security = r1HybridNlaSecurityView(connection);
    if (lease == nullptr || !r1Security ||
        !authorizeR3ProtectedTransitionForEstablishedTls(
            *lease, principalProof, r1Security->activeServerTls, session,
            kConsoleViewPermission))
    {
        if (session.phase() !=
            rdp_server::server::transport::McsSessionPhase::Closed)
        {
            revokeR3Session(principalProof, session);
        }
        else
        {
            revoke(principalProof);
        }
        return Outcome::Rejected;
    }

    const auto outcome = session.completeConnectResponseWrite(
        replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return outcome;
}

rdp_server::server::transport::McsSessionIntake
LinuxConsoleAdmissionBroker::authorizeR3ErectDomain(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using rdp_server::server::transport::McsSessionIntake;
    const auto r1Security = r1HybridNlaSecurityView(connection);
    if (!r1Security ||
        !authorizeR3ProtectedTransitionForEstablishedTls(
            lease, principalProof, r1Security->activeServerTls, session,
            kConsoleViewPermission))
    {
        if (session.phase() !=
            rdp_server::server::transport::McsSessionPhase::Closed)
        {
            revokeR3Session(principalProof, session);
        }
        else
        {
            revoke(principalProof);
        }
        return McsSessionIntake::AdmissionDenied;
    }

    const auto result = session.onVerifiedR2ErectDomain(completeTpkt);
    if (result != McsSessionIntake::ErectDomainAccepted)
        revokeR3Session(principalProof, session);
    return result;
}

rdp_server::server::transport::McsSessionIntake
LinuxConsoleAdmissionBroker::authorizeR3AttachUser(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using rdp_server::server::transport::McsSessionIntake;
    if (!authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission))
        return McsSessionIntake::AdmissionDenied;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return McsSessionIntake::AdmissionDenied;
    }
    const auto result = session.onVerifiedR2AttachUser(*provenance, completeTpkt);
    if (result != McsSessionIntake::AttachUserAccepted)
        revokeR3Session(principalProof, session);
    return result;
}

std::optional<rdp_server::server::transport::McsConnectResponseWriteView>
LinuxConsoleAdmissionBroker::authorizeR3AttachUserConfirmWrite(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    if (!authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }
    const auto pending = session.prepareAttachUserConfirmWrite(*provenance);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

rdp_server::server::transport::McsConnectResponseWriteOutcome
LinuxConsoleAdmissionBroker::completeR3AttachUserConfirmWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome =
        rdp_server::server::transport::McsConnectResponseWriteOutcome;
    if (lease == nullptr ||
        !authorizeR3ProtectedTransition(
            *lease, principalProof, connection, session, kConsoleViewPermission))
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }
    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }
    const auto outcome = session.completeAttachUserConfirmWrite(
        *provenance, replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return outcome;
}

rdp_server::server::transport::McsJoinStartOutcome
LinuxConsoleAdmissionBroker::authorizeR3ChannelJoin(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using Outcome = rdp_server::server::transport::McsJoinStartOutcome;
    if (!authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission))
        return Outcome::Rejected;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto outcome = session.onVerifiedR2ChannelJoin(
        *provenance, completeTpkt);
    if (outcome == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return outcome;
}

std::optional<rdp_server::server::transport::McsConnectResponseWriteView>
LinuxConsoleAdmissionBroker::authorizeR3ChannelJoinConfirmWrite(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    if (!authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }
    const auto pending = session.prepareChannelJoinConfirmWrite(*provenance);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

rdp_server::server::transport::McsJoinWriteOutcome
LinuxConsoleAdmissionBroker::completeR3ChannelJoinConfirmWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome = rdp_server::server::transport::McsJoinWriteOutcome;
    if (lease == nullptr ||
        !authorizeR3ProtectedTransition(
            *lease, principalProof, connection, session, kConsoleViewPermission))
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }
    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto outcome = session.completeChannelJoinConfirmWrite(
        *provenance, replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return outcome;
}

std::optional<std::uint16_t>
LinuxConsoleAdmissionBroker::authorizeR3JoinedClipboardChannel(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    if (!authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleClipboardPermission))
        return std::nullopt;
    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }
    const auto channel = session.resolveVerifiedR2JoinedClipboardChannel(
        *provenance);
    if (session.phase() ==
        rdp_server::server::transport::McsSessionPhase::Closed)
        revokeR3Session(principalProof, session);
    return channel;
}

std::optional<rdp_server::server::transport::RdpClientInfoPacketSummary>
LinuxConsoleAdmissionBroker::authorizeR3ClientInfoPacket(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (!authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto accepted =
        session.acceptVerifiedR2ClientInfoPacket(*provenance, completeTpkt);
    if (!accepted)
        revokeR3Session(principalProof, session);
    return accepted;
}

std::optional<
    rdp_server::server::transport::RdpServerLicenseRequestWriteView>
LinuxConsoleAdmissionBroker::authorizeR3ServerLicenseRequestWrite(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::transport::RdpServerLicenseIdentity
        &identity,
    const rdp_server::server::transport::RdpLicensingServiceCredential
        &credential) noexcept
{
    if (!authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto pending = session.prepareServerLicenseRequestWrite(
        *provenance, identity, credential);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

rdp_server::server::transport::RdpServerLicenseRequestWriteOutcome
LinuxConsoleAdmissionBroker::completeR3ServerLicenseRequestWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome =
        rdp_server::server::transport::RdpServerLicenseRequestWriteOutcome;

    if (lease == nullptr ||
        !authorizeR3ProtectedTransition(
            *lease, principalProof, connection, session, kConsoleViewPermission))
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto outcome = session.completeServerLicenseRequestWrite(
        *provenance, replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return outcome;
}

std::optional<
    rdp_server::server::transport::RdpServerPlatformChallengeWriteView>
LinuxConsoleAdmissionBroker::authorizeR3ServerPlatformChallengeWrite(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    if (!authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto pending =
        session.prepareServerPlatformChallengeWrite(*provenance);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

rdp_server::server::transport::RdpServerPlatformChallengeWriteOutcome
LinuxConsoleAdmissionBroker::completeR3ServerPlatformChallengeWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome =
        rdp_server::server::transport::RdpServerPlatformChallengeWriteOutcome;
    if (lease == nullptr ||
        !authorizeR3ProtectedTransition(
            *lease, principalProof, connection, session, kConsoleViewPermission))
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto outcome = session.completeServerPlatformChallengeWrite(
        *provenance, replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return outcome;
}

std::optional<rdp_server::server::transport::RdpLicensingIntake>
LinuxConsoleAdmissionBroker::authorizeR3ClientLicensingMessage(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::transport::RdpLicensingServiceCredential
        &credential,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (!authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto accepted = session.acceptVerifiedR2ClientLicensingMessage(
        *provenance, credential, completeTpkt);
    if (!accepted)
        revokeR3Session(principalProof, session);
    return accepted;
}

bool LinuxConsoleAdmissionBroker::personalDesktopPolicyMatches(
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) const noexcept
{
    return personalDesktopPolicy_ == &deploymentPolicy &&
           deploymentPolicy.usesPersonalTerminalServerLicensingFlow() &&
           deploymentPolicy.requiresNativeSessionRevocation() &&
           deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() ==
               1U;
}

bool LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopTransition(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (!personalDesktopPolicyMatches(deploymentPolicy) ||
        !authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission))
    {
        revokeR3Session(principalProof, session);
        return false;
    }
    return true;
}

bool LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopLicensingMode(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (personalDesktopPolicy_ != nullptr ||
        !deploymentPolicy.usesPersonalTerminalServerLicensingFlow() ||
        !deploymentPolicy.requiresNativeSessionRevocation() ||
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() !=
            1U ||
        !authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission) ||
        !session.selectVerifiedR2PersonalDesktopLicensingMode())
    {
        revokeR3Session(principalProof, session);
        return false;
    }

    personalDesktopPolicy_ = &deploymentPolicy;
    return true;
}

std::optional<rdp_server::server::transport::RdpServerLicenseRequestWriteView>
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopServerLicenseRequestWrite(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    const rdp_server::server::transport::RdpServerLicenseIdentity &identity,
    const rdp_server::server::transport::RdpLicensingServiceCredential
        &credential) noexcept
{
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto pending = session.prepareServerLicenseRequestWrite(
        *provenance, identity, credential);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

rdp_server::server::transport::RdpServerLicenseRequestWriteOutcome
LinuxConsoleAdmissionBroker::completeR3PersonalDesktopServerLicenseRequestWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome =
        rdp_server::server::transport::RdpServerLicenseRequestWriteOutcome;

    if (lease == nullptr ||
        !authorizeR3PersonalDesktopTransition(
            *lease, principalProof, connection, session, deploymentPolicy))
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto outcome = session.completeServerLicenseRequestWrite(
        *provenance, replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return outcome;
}

std::optional<rdp_server::server::transport::RdpLicensingIntake>
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopClientLicensingMessage(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    const rdp_server::server::transport::RdpLicensingServiceCredential
        &credential,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto accepted = session.acceptVerifiedR2ClientLicensingMessage(
        *provenance, credential, completeTpkt);
    if (!accepted)
        revokeR3Session(principalProof, session);
    return accepted;
}

std::optional<
    rdp_server::server::transport::RdpPersonalDesktopValidClientWriteView>
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopValidClientWrite(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto pending =
        session.preparePersonalDesktopValidClientWrite(*provenance);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

rdp_server::server::transport::RdpPersonalDesktopValidClientWriteOutcome
LinuxConsoleAdmissionBroker::completeR3PersonalDesktopValidClientWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome = rdp_server::server::transport::
        RdpPersonalDesktopValidClientWriteOutcome;

    if (lease == nullptr ||
        !authorizeR3PersonalDesktopTransition(
            *lease, principalProof, connection, session, deploymentPolicy))
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto outcome = session.completePersonalDesktopValidClientWrite(
        *provenance, replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return outcome;
}

std::optional<rdp_server::server::transport::RdpDemandActiveProfileView>
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopDemandActiveProfile(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    rdp_server::server::transport::RdpDemandActiveFeature features) noexcept
{
    std::uint32_t requiredPermissions = kConsoleViewPermission;
    if (rdp_server::server::transport::hasRdpDemandActiveFeature(
            features,
            rdp_server::server::transport::RdpDemandActiveFeature::
                SlowPathInput))
        requiredPermissions |= kConsoleInputPermission;

    if (!personalDesktopPolicyMatches(deploymentPolicy) ||
        !authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, requiredPermissions))
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto profile =
        session.prepareVerifiedR2DemandActiveProfile(*provenance, features);
    if (!profile)
        revokeR3Session(principalProof, session);
    return profile;
}

std::optional<rdp_server::server::transport::RdpShareActivationWriteView>
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopShareActivation(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    const rdp_server::server::transport::RdpDemandActiveProfileView
        &profile) noexcept
{
    std::uint32_t requiredPermissions = kConsoleViewPermission;
    if (rdp_server::server::transport::hasRdpDemandActiveFeature(
            profile.features(),
            rdp_server::server::transport::RdpDemandActiveFeature::
                SlowPathInput))
        requiredPermissions |= kConsoleInputPermission;

    if (!personalDesktopPolicyMatches(deploymentPolicy) ||
        !authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, requiredPermissions))
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto pending =
        session.beginVerifiedR2ShareActivation(*provenance, profile);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

std::optional<rdp_server::server::transport::RdpShareActivationWriteView>
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopShareActivationWrite(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto pending =
        session.pendingVerifiedR2ShareActivationWrite(*provenance);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

rdp_server::server::transport::RdpShareActivationWriteOutcome
LinuxConsoleAdmissionBroker::completeR3PersonalDesktopShareActivationWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome =
        rdp_server::server::transport::RdpShareActivationWriteOutcome;

    if (lease == nullptr ||
        !authorizeR3PersonalDesktopTransition(
            *lease, principalProof, connection, session, deploymentPolicy))
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto outcome = session.completeVerifiedR2ShareActivationWrite(
        *provenance, replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return outcome;
}

rdp_server::server::transport::RdpShareActivationClientIntake
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopShareActivationPdu(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using Intake =
        rdp_server::server::transport::RdpShareActivationClientIntake;

    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return Intake::Rejected;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Intake::Rejected;
    }

    const auto intake =
        session.acceptVerifiedR2ShareActivationPdu(
            *provenance, completeTpkt);
    if (intake == Intake::Rejected || intake == Intake::Closed)
        revokeR3Session(principalProof, session);
    return intake;
}

std::optional<rdp_server::server::transport::RdpGraphicsDvcWriteView>
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopGraphicsDynamicVirtualChannel(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto pending =
        session.beginVerifiedR2GraphicsDynamicVirtualChannel(*provenance);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

std::optional<rdp_server::server::transport::RdpGraphicsDvcWriteView>
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopGraphicsDynamicVirtualChannelWrite(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto pending =
        session.pendingVerifiedR2GraphicsDynamicVirtualChannelWrite(
            *provenance);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

rdp_server::server::transport::RdpGraphicsDvcWriteOutcome
LinuxConsoleAdmissionBroker::completeR3PersonalDesktopGraphicsDynamicVirtualChannelWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    using Outcome = rdp_server::server::transport::RdpGraphicsDvcWriteOutcome;

    if (lease == nullptr ||
        !authorizeR3PersonalDesktopTransition(
            *lease, principalProof, connection, session, deploymentPolicy))
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }

    const auto outcome =
        session.completeVerifiedR2GraphicsDynamicVirtualChannelWrite(
            *provenance, replySequence, writeSliceSequence, acceptedBytes);
    if (outcome == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return outcome;
}


rdp_server::server::transport::RdpPostShareTpktRoute
LinuxConsoleAdmissionBroker::classifyR3PersonalDesktopPostShareTpkt(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return {};

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return {};
    }

    const auto route =
        session.classifyVerifiedR2PostShareTpkt(*provenance, completeTpkt);
    // Never expose a stale route after native admission changes.
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return {};
    return route;
}

rdp_server::server::transport::RdpGraphicsDvcClientIntake
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopGraphicsDynamicVirtualChannelPdu(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    using Intake = rdp_server::server::transport::RdpGraphicsDvcClientIntake;

    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return Intake::Rejected;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Intake::Rejected;
    }

    const auto intake =
        session.acceptVerifiedR2GraphicsDynamicVirtualChannelPdu(
            *provenance, completeTpkt);
    if (intake == Intake::Rejected || intake == Intake::Closed)
        revokeR3Session(principalProof, session);
    return intake;
}



rdp_server::server::transport::RdpGraphicsFrameAcknowledgeIntake
LinuxConsoleAdmissionBroker::consumeR3PersonalDesktopGraphicsFrameAcknowledge(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    using Intake = rdp_server::server::transport::RdpGraphicsFrameAcknowledgeIntake;
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return Intake::Rejected;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Intake::Rejected;
    }

    const auto result =
        session.consumeVerifiedR2GraphicsFrameAcknowledge(*provenance);
    if (result == Intake::Rejected ||
        !authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
    {
        revokeR3Session(principalProof, session);
        return Intake::Rejected;
    }
    return result;
}

rdp_server::server::transport::RdpGraphicsFramePublicationReadiness
LinuxConsoleAdmissionBroker::preflightR3PersonalDesktopGraphicsFramePublication(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint32_t frameId) noexcept
{
    using Readiness =
        rdp_server::server::transport::RdpGraphicsFramePublicationReadiness;
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return Readiness::Rejected;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Readiness::Rejected;
    }

    const auto readiness =
        session.preflightVerifiedR2GraphicsFramePublication(
            *provenance, frameId);

    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return Readiness::Rejected;

    if (readiness == Readiness::Rejected)
        revokeR3Session(principalProof, session);
    return readiness;
}

rdp_server::server::transport::RdpGraphicsSurfaceReconfiguration
LinuxConsoleAdmissionBroker::beginR3PersonalDesktopGraphicsSurfaceReconfiguration(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    ::PixelSize desktopGeometry) noexcept
{
    using Decision =
        rdp_server::server::transport::RdpGraphicsSurfaceReconfiguration;
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return Decision::Rejected;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Decision::Rejected;
    }

    const Decision result =
        session.beginVerifiedR2GraphicsSurfaceReconfiguration(
            *provenance, desktopGeometry);
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return Decision::Rejected;

    if (result == Decision::Rejected)
        revokeR3Session(principalProof, session);
    return result;
}

std::optional<rdp_server::server::transport::RdpGraphicsDvcWriteView>
LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopClearCodecFramePublication(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint32_t frameId,
    ::FramebufferView framebuffer) noexcept
{
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return std::nullopt;

    const auto provenance =
        connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto pending =
        session.beginVerifiedR2GraphicsClearCodecFramePublication(
            *provenance, frameId, framebuffer);
    if (!pending)
        revokeR3Session(principalProof, session);
    return pending;
}

bool LinuxConsoleAdmissionBroker::
cancelR3PersonalDesktopUnwrittenGraphicsFrame(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return false;

    const auto provenance =
        connection.securityNegotiationProvenance();
    if (!provenance ||
        !session.cancelVerifiedR2UnwrittenGraphicsFrame(
            *provenance))
    {
        revokeR3Session(principalProof, session);
        return false;
    }
    return true;
}

bool LinuxConsoleAdmissionBroker::
authorizeR3PersonalDesktopClipboardTransition(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (lease == nullptr ||
        !personalDesktopPolicyMatches(deploymentPolicy) ||
        !authorizeR3ProtectedTransition(
            *lease, principalProof, connection, session,
            kConsoleViewPermission | kConsoleClipboardPermission))
    {
        revokeR3Session(principalProof, session);
        return false;
    }
    return true;
}

bool LinuxConsoleAdmissionBroker::visitR3PersonalDesktopClipboardChannel(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    rdp_server::server::transport::RdpClipboardChannelVisitor visitor) noexcept
{
    if (!visitor ||
        !authorizeR3PersonalDesktopClipboardTransition(
            lease, principalProof, connection, session, deploymentPolicy))
    {
        revokeR3Session(principalProof, session);
        return false;
    }
    const auto provenance = connection.securityNegotiationProvenance();
    const auto route = provenance
        ? session.resolveVerifiedR2ActivatedClipboardChannel(*provenance)
        : std::nullopt;
    if (!route || !visitor.visit(visitor.context, *route))
    {
        revokeR3Session(principalProof, session);
        return false;
    }
    return true;
}

bool LinuxConsoleAdmissionBroker::dispatchR3PersonalDesktopClipboardTpkt(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt,
    rdp_server::server::transport::RdpClipboardCompletePduSink sink) noexcept
{
    if (!sink ||
        !authorizeR3PersonalDesktopClipboardTransition(
            lease, principalProof, connection, session, deploymentPolicy))
    {
        revokeR3Session(principalProof, session);
        return false;
    }
    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return false;
    }

    std::span<const std::uint8_t> completePdu;
    const auto result = session.acceptVerifiedR2ClipboardTpkt(
        *provenance, completeTpkt, completePdu);
    if (result == rdp_server::server::transport::RdpClipboardChunkIntake::Rejected)
    {
        revokeR3Session(principalProof, session);
        return false;
    }
    if (result == rdp_server::server::transport::RdpClipboardChunkIntake::NeedMore)
        return true;

    // A complete PDU is the only publication seam. Reauthorize *again*
    // immediately before the synchronous R8 callback, which must not retain
    // the borrowed PDU span or reenter this connection event loop.
    if (!authorizeR3PersonalDesktopClipboardTransition(
            lease, principalProof, connection, session, deploymentPolicy) ||
        !session.verifiedR2ApplicationTrafficReady(*provenance) ||
        !sink.consume(sink.context, completePdu))
    {
        revokeR3Session(principalProof, session);
        return false;
    }
    return true;
}

std::optional<
    rdp_server::server::transport::RdpClipboardStaticChannelWriteView>
LinuxConsoleAdmissionBroker::queueR3PersonalDesktopClipboardPdu(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completePdu) noexcept
{
    if (!authorizeR3PersonalDesktopClipboardTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return std::nullopt;
    const auto provenance = connection.securityNegotiationProvenance();
    const auto result = provenance
        ? session.queueVerifiedR2ClipboardPdu(*provenance, completePdu)
        : std::nullopt;
    if (!result)
        revokeR3Session(principalProof, session);
    return result;
}

std::optional<
    rdp_server::server::transport::RdpClipboardStaticChannelWriteView>
LinuxConsoleAdmissionBroker::pendingR3PersonalDesktopClipboardWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (!authorizeR3PersonalDesktopClipboardTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return std::nullopt;
    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }
    const auto result = session.pendingVerifiedR2ClipboardWrite(*provenance);
    if (session.phase() ==
        rdp_server::server::transport::McsSessionPhase::Closed)
        revokeR3Session(principalProof, session);
    return result;
}

rdp_server::server::transport::RdpClipboardWriteOutcome
LinuxConsoleAdmissionBroker::completeR3PersonalDesktopClipboardWrite(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::uint64_t generation, std::uint64_t replySequence,
    std::uint64_t writeSliceSequence, std::size_t acceptedBytes) noexcept
{
    using Outcome = rdp_server::server::transport::RdpClipboardWriteOutcome;
    if (!authorizeR3PersonalDesktopClipboardTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return Outcome::Rejected;
    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return Outcome::Rejected;
    }
    const auto result = session.completeVerifiedR2ClipboardWrite(
        *provenance, generation, replySequence, writeSliceSequence,
        acceptedBytes);
    if (result == Outcome::Rejected)
        revokeR3Session(principalProof, session);
    return result;
}

bool LinuxConsoleAdmissionBroker::dispatchR3PersonalDesktopSlowPathInputPdu(
    const LinuxConsoleAdmissionLease *lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy,
    std::span<const std::uint8_t> completeTpkt,
    rdp_server::server::transport::RdpSlowPathInputEventSink sink) noexcept
{
    using rdp_server::server::transport::RdpSlowPathInputEvent;
    constexpr std::uint32_t requiredIngressPermissions =
        kConsoleViewPermission | kConsoleInputPermission;

    if (lease == nullptr || !sink ||
        !personalDesktopPolicyMatches(deploymentPolicy) ||
        !authorizeR3ProtectedTransition(
            *lease, principalProof, connection, session,
            requiredIngressPermissions))
    {
        revokeR3Session(principalProof, session);
        return false;
    }

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return false;
    }

    const auto input =
        session.routeVerifiedR2SlowPathInputPdu(*provenance, completeTpkt);
    if (!input)
    {
        revokeR3Session(principalProof, session);
        return false;
    }

    for (std::size_t index = 0; index < input->eventCount; ++index)
    {
        RdpSlowPathInputEvent event{};
        if (!input->eventAt(index, event) ||
            !personalDesktopPolicyMatches(deploymentPolicy) ||
            !authorizeR3ProtectedTransition(
                *lease, principalProof, connection, session,
                kConsoleInputPermission))
        {
            revokeR3Session(principalProof, session);
            return false;
        }

        const auto currentProvenance =
            connection.securityNegotiationProvenance();
        if (!currentProvenance || *currentProvenance != *provenance ||
            !session.verifiedR2ApplicationTrafficReady(
                *currentProvenance) ||
            !sink.dispatch(sink.context, event))
        {
            revokeR3Session(principalProof, session);
            return false;
        }
    }
    return true;
}

bool LinuxConsoleAdmissionBroker::authorizeR3PersonalDesktopApplicationTraffic(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::runtime::RuntimeDeploymentPolicy
        &deploymentPolicy) noexcept
{
    if (!authorizeR3PersonalDesktopTransition(
            lease, principalProof, connection, session, deploymentPolicy))
        return false;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance ||
        !session.verifiedR2ApplicationTrafficReady(*provenance))
    {
        revokeR3Session(principalProof, session);
        return false;
    }
    return true;
}

std::optional<rdp_server::server::transport::RdpLicensingIntake>
LinuxConsoleAdmissionBroker::authorizeR3ClientPlatformChallengeResponse(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection &connection,
    rdp_server::server::transport::McsSessionLifecycle &session,
    const rdp_server::server::transport::RdpLicensingServiceCredential
        &credential,
    std::span<const std::uint8_t> completeTpkt) noexcept
{
    if (!authorizeR3ProtectedTransition(
            lease, principalProof, connection, session, kConsoleViewPermission))
        return std::nullopt;

    const auto provenance = connection.securityNegotiationProvenance();
    if (!provenance)
    {
        revokeR3Session(principalProof, session);
        return std::nullopt;
    }

    const auto accepted =
        session.acceptVerifiedR2ClientPlatformChallengeResponse(
            *provenance, credential, completeTpkt);
    if (!accepted)
        revokeR3Session(principalProof, session);
    return accepted;
}

void LinuxConsoleAdmissionBroker::revokeR3Session(
    LinuxAuthenticatedPrincipalProof &principalProof,
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    // Protocol/session state dies before authentication and before the caller
    // releases R1 TLS/socket ownership.
    session.close();
    revoke(principalProof);
}

bool LinuxConsoleAdmissionBroker::onNativeSessionChangeReady(
    LinuxAuthenticatedPrincipalProof &principalProof,
    rdp_server::server::transport::McsSessionLifecycle &session) noexcept
{
    if (state_ != LinuxConsoleAdmissionState::Active ||
        changes_ == nullptr)
    {
        revokeR3Session(principalProof, session);
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
    // TLS/authenticated-proof-bound admission is invalidated. R1 may release TLS only later.
    revokeR3Session(principalProof, session);
    return false;
}

void LinuxConsoleAdmissionBroker::revoke(
    LinuxAuthenticatedPrincipalProof &principalProof) noexcept
{
    revokeControl();
    clearRequest();
    changes_.reset();
    personalDesktopPolicy_ = nullptr;
    principalProof.revokeAuthenticatedProof();
    state_ = LinuxConsoleAdmissionState::Revoked;
}

bool LinuxConsoleAdmissionBroker::visitNativeDesktopSelection(
    const LinuxConsoleAdmissionLease &lease,
    LinuxAuthenticatedPrincipalProof &principalProof,
    const rdp_server::server::transport::OwnedPreauthTcpConnection
        &connection,
    LinuxNativeDesktopSelectionVisitor visitor,
    void *context) noexcept
{
    const auto before = r1HybridNlaSecurityView(connection);
    if (visitor == nullptr || !before ||
        !authorizationChecksPass(
            lease, principalProof, before->activeServerTls,
            kConsoleViewPermission))
    {
        deny(principalProof);
        return false;
    }

    const LinuxNativeDesktopSelectionView selection{
        std::string_view(lease.sessionId_.data(), lease.sessionIdLength_),
        std::string_view(seat_.data(), seatLength_),
        std::string_view(display_.data(), displayLength_),
        lease.admissionGeneration_, lease.sessionGeneration_};

    if (!visitor(selection, context))
    {
        deny(principalProof);
        return false;
    }

    // The consumer may allocate/open its native owner synchronously. Re-sample
    // every R1/R2/native fact after it returns so a concurrent logout/session
    // replacement cannot turn the just-consumed selector into authorization.
    const auto after = r1HybridNlaSecurityView(connection);
    if (!after ||
        !revalidationChecksPass(lease, principalProof, after->activeServerTls))
    {
        deny(principalProof);
        return false;
    }
    return true;
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
