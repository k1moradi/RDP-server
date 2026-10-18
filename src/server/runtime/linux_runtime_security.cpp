// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_runtime_security.h"

#include "runtime_deployment_policy.h"
#include "server/security/linux_logind_console_evidence.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace rdp_server::server::runtime
{
namespace
{

constexpr std::size_t kMaximumKeytabBytes = 1024U * 1024U;
constexpr std::size_t kMaximumPathComponentBytes = 255;
constexpr std::string_view kFilePrefix{"FILE:"};
constexpr std::string_view kProcFdPrefix{"FILE:/proc/self/fd/"};

struct SensitiveCopyBuffer final
{
    std::array<unsigned char, 16384> bytes{};

    ~SensitiveCopyBuffer()
    {
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }

    SensitiveCopyBuffer() = default;
    SensitiveCopyBuffer(const SensitiveCopyBuffer &) = delete;
    SensitiveCopyBuffer &operator=(const SensitiveCopyBuffer &) = delete;
};

[[nodiscard]] bool isPrivateKeytab(
    int descriptor, struct stat &information) noexcept
{
    return descriptor >= 0 &&
           ::fstat(descriptor, &information) == 0 &&
           S_ISREG(information.st_mode) &&
           information.st_size > 2 &&
           information.st_size <=
               static_cast<off_t>(kMaximumKeytabBytes) &&
           information.st_uid == ::geteuid() &&
           (information.st_mode & S_IRUSR) != 0 &&
           (information.st_mode & (S_IRWXG | S_IRWXO)) == 0;
}

[[nodiscard]] int openPrivateKeytab(std::string_view keytabUri) noexcept
{
    if (!keytabUri.starts_with("FILE:/") ||
        keytabUri.size() <= kFilePrefix.size() + 1U ||
        keytabUri.size() > 4096U ||
        keytabUri.find('\0') != std::string_view::npos)
    {
        return -1;
    }

    std::string_view path = keytabUri.substr(kFilePrefix.size());
    if (path.size() < 2U || path.front() != '/')
    {
        return -1;
    }

    int parentDescriptor =
        ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parentDescriptor < 0)
    {
        return -1;
    }

    path.remove_prefix(1);
    while (true)
    {
        const std::size_t separator = path.find('/');
        const std::string_view component = path.substr(0, separator);
        if (component.empty() || component == "." || component == ".." ||
            component.size() > kMaximumPathComponentBytes)
        {
            (void)::close(parentDescriptor);
            return -1;
        }

        std::array<char, kMaximumPathComponentBytes + 1U> terminatedComponent{};
        std::copy(component.begin(), component.end(), terminatedComponent.begin());

        const bool leaf = separator == std::string_view::npos;
        const int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
            (leaf ? 0 : O_DIRECTORY);
        const int openedDescriptor =
            ::openat(parentDescriptor, terminatedComponent.data(), flags);
        (void)::close(parentDescriptor);
        if (openedDescriptor < 0)
        {
            return -1;
        }

        if (leaf)
        {
            struct stat information {};
            if (!isPrivateKeytab(openedDescriptor, information))
            {
                (void)::close(openedDescriptor);
                return -1;
            }
            return openedDescriptor;
        }

        parentDescriptor = openedDescriptor;
        path.remove_prefix(separator + 1U);
    }
}

[[nodiscard]] ssize_t preadRetry(
    int descriptor, void *buffer, std::size_t bytes,
    off_t offset) noexcept
{
    ssize_t result = -1;
    do
    {
        result = ::pread(descriptor, buffer, bytes, offset);
    }
    while (result < 0 && errno == EINTR);
    return result;
}

[[nodiscard]] bool pwriteAll(
    int descriptor, const unsigned char *buffer, std::size_t bytes,
    off_t offset) noexcept
{
    std::size_t written = 0;
    while (written < bytes)
    {
        ssize_t result = -1;
        do
        {
            result = ::pwrite(
                descriptor, buffer + written, bytes - written,
                offset + static_cast<off_t>(written));
        }
        while (result < 0 && errno == EINTR);

        if (result <= 0)
        {
            return false;
        }
        written += static_cast<std::size_t>(result);
    }
    return true;
}

[[nodiscard]] bool sameKeytabSnapshotFacts(
    const struct stat &before, const struct stat &after) noexcept
{
    return before.st_dev == after.st_dev &&
           before.st_ino == after.st_ino &&
           before.st_size == after.st_size &&
           before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
           before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
           before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
           before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
}

[[nodiscard]] int createSealedKeytabSnapshot(
    int sourceDescriptor) noexcept
{
#if !defined(SYS_memfd_create)
    (void)sourceDescriptor;
    return -1;
#else
    struct stat before {};
    if (!isPrivateKeytab(sourceDescriptor, before))
    {
        return -1;
    }

    const long rawSnapshotDescriptor = ::syscall(
        SYS_memfd_create, "rdp-server-keytab",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (rawSnapshotDescriptor < 0)
    {
        return -1;
    }
    const int snapshotDescriptor =
        static_cast<int>(rawSnapshotDescriptor);

    SensitiveCopyBuffer copyBuffer;
    off_t offset = 0;
    bool copied = true;
    while (offset < before.st_size)
    {
        const auto remaining =
            static_cast<std::uint64_t>(before.st_size - offset);
        const std::size_t requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(
                remaining, copyBuffer.bytes.size()));
        const ssize_t bytesRead = preadRetry(
            sourceDescriptor, copyBuffer.bytes.data(), requested, offset);
        if (bytesRead <= 0)
        {
            copied = false;
            break;
        }
        const auto count = static_cast<std::size_t>(bytesRead);
        if (!pwriteAll(
                snapshotDescriptor, copyBuffer.bytes.data(), count, offset))
        {
            copied = false;
            break;
        }
        offset += static_cast<off_t>(count);
    }

    const ssize_t extraRead = copied
        ? preadRetry(
              sourceDescriptor, copyBuffer.bytes.data(), 1U,
              before.st_size)
        : -1;
    struct stat after {};
    const bool sourceStable =
        copied && extraRead == 0 &&
        isPrivateKeytab(sourceDescriptor, after) &&
        sameKeytabSnapshotFacts(before, after);

    constexpr int requiredSeals =
        F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    const bool sealsAdded =
        sourceStable &&
        ::fchmod(snapshotDescriptor, S_IRUSR) == 0 &&
        ::fcntl(snapshotDescriptor, F_ADD_SEALS, requiredSeals) == 0;
    const int observedSeals =
        sealsAdded ? ::fcntl(snapshotDescriptor, F_GET_SEALS) : -1;
    const bool sealed =
        observedSeals >= 0 &&
        (observedSeals & requiredSeals) == requiredSeals;
    if (!sealed)
    {
        (void)::close(snapshotDescriptor);
        return -1;
    }
    return snapshotDescriptor;
#endif
}

[[nodiscard]] std::string_view descriptorKeytabUri(
    int keytabDescriptor,
    std::array<char, 64> &buffer) noexcept
{
    if (keytabDescriptor < 0 ||
        kProcFdPrefix.size() + 20U + 1U > buffer.size())
    {
        return {};
    }

    auto output = std::copy(
        kProcFdPrefix.begin(), kProcFdPrefix.end(), buffer.begin());
    const auto result = std::to_chars(
        output, buffer.end() - 1, keytabDescriptor);
    if (result.ec != std::errc{})
    {
        return {};
    }
    *result.ptr = '\0';
    return std::string_view(
        buffer.data(), static_cast<std::size_t>(result.ptr - buffer.data()));
}

[[nodiscard]] bool configureAcceptorFromDescriptor(
    std::string_view servicePrincipal,
    int keytabDescriptor,
    rdp_server::server::security::GssapiSpnegoAcceptor &acceptor) noexcept
{
    std::array<char, 64> keytabUriBytes{};
    const std::string_view keytabUri =
        descriptorKeytabUri(keytabDescriptor, keytabUriBytes);
    if (keytabUri.empty())
    {
        acceptor.reject();
        return false;
    }
    return acceptor.configure(servicePrincipal, keytabUri);
}

} // namespace

LinuxRuntimeSecurityConfiguration::~LinuxRuntimeSecurityConfiguration()
{
    closeKeytab();
    clearServicePrincipal();
}

void LinuxRuntimeSecurityConfiguration::closeKeytab() noexcept
{
    if (keytabDescriptor_ >= 0)
    {
        (void)::close(keytabDescriptor_);
        keytabDescriptor_ = -1;
    }
}

void LinuxRuntimeSecurityConfiguration::clearServicePrincipal() noexcept
{
    servicePrincipal_.fill('\0');
    servicePrincipalLength_ = 0;
}

bool LinuxRuntimeSecurityConfiguration::configure(
    std::string_view servicePrincipal,
    std::string_view keytabUri,
    const rdp_server::server::security::ConsoleIdentityRuleInput &rule)
    noexcept
{
    return configureInternal(
        servicePrincipal, keytabUri, rule, {}, false);
}

#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
bool LinuxRuntimeSecurityConfiguration::configure(
    std::string_view servicePrincipal,
    std::string_view keytabUri,
    const rdp_server::server::security::ConsoleIdentityRuleInput &rule,
    std::string_view pamServiceName) noexcept
{
    return configureInternal(
        servicePrincipal, keytabUri, rule, pamServiceName, true);
}
#endif

bool LinuxRuntimeSecurityConfiguration::configureInternal(
    std::string_view servicePrincipal,
    std::string_view keytabUri,
    const rdp_server::server::security::ConsoleIdentityRuleInput &rule,
    std::string_view pamServiceName,
    bool requirePamVerifier) noexcept
{
    if (attempted_)
    {
        return false;
    }
    attempted_ = true;

#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    if (requirePamVerifier && !passwordVerifier_.configure(pamServiceName))
    {
        return false;
    }
#else
    if (requirePamVerifier || !pamServiceName.empty())
    {
        return false;
    }
#endif

    if (servicePrincipal.empty() ||
        servicePrincipal.size() >= servicePrincipal_.size() ||
        servicePrincipal.find('\0') != std::string_view::npos)
    {
        return false;
    }

    const int openedKeytab = openPrivateKeytab(keytabUri);
    if (openedKeytab < 0)
    {
        return false;
    }
    const int snapshotKeytab =
        createSealedKeytabSnapshot(openedKeytab);
    (void)::close(openedKeytab);
    if (snapshotKeytab < 0)
    {
        return false;
    }
    keytabDescriptor_ = snapshotKeytab;

    if (policy_.add(rule) !=
        rdp_server::server::security::ConsoleRuleError::None)
    {
        closeKeytab();
        return false;
    }

    std::copy(servicePrincipal.begin(), servicePrincipal.end(),
              servicePrincipal_.begin());
    servicePrincipalLength_ = servicePrincipal.size();
    servicePrincipal_[servicePrincipalLength_] = '\0';

    // Probe exactly the R2 provider that live connections will use. GSS
    // credential acquisition loads the explicit acceptor key and does not
    // authenticate a client or contact a KDC. The procfd names a sealed
    // anonymous snapshot, so neither pathname replacement nor later writes to
    // the configured source inode can change per-connection credentials.
    rdp_server::server::security::GssapiSpnegoAcceptor probe;
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    if (requirePamVerifier &&
        (!probe.bindConsoleIdentityPolicy(policy_) ||
         !probe.bindLinuxPamPasswordVerifier(passwordVerifier_)))
    {
        closeKeytab();
        clearServicePrincipal();
        return false;
    }
#endif
    if (!configureAcceptorFromDescriptor(
            std::string_view(
                servicePrincipal_.data(), servicePrincipalLength_),
            keytabDescriptor_, probe))
    {
        closeKeytab();
        clearServicePrincipal();
        return false;
    }

    configured_ = true;
    return true;
}

bool LinuxRuntimeSecurityConfiguration::replaceAuthorizedIdentity(
    const rdp_server::server::security::ConsoleIdentityRuleInput &rule)
    noexcept
{
    return configured_ &&
           policy_.replaceSingle(rule) ==
               rdp_server::server::security::ConsoleRuleError::None;
}

bool LinuxRuntimeSecurityConfiguration::revokeAuthorizedIdentity() noexcept
{
    return configured_ && policy_.revokeAll();
}

LinuxRuntimeSecurityPreflightVerdict
LinuxRuntimeSecurityConfiguration::preflightPersonalDesktopAdmission(
    const RuntimeDeploymentPolicy &deploymentPolicy,
    const rdp_server::server::security::ConsoleEvidenceRequest &request)
    const noexcept
{
    LinuxRuntimeSecurityPreflightVerdict verdict{};
    verdict.gssAcceptorCredentialAvailable =
        configured_ && keytabDescriptor_ >= 0 &&
        servicePrincipalLength_ != 0U;
    verdict.identityPolicyConfigured =
        configured_ && policy_.size() != 0U && policy_.generation() != 0U;
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    verdict.pamServiceConfigured =
        configured_ && passwordVerifier_.configured() &&
        !passwordVerifier_.serviceName().empty();
#endif
    verdict.personalDesktopPolicyConfigured =
        deploymentPolicy.usesPersonalTerminalServerLicensingFlow() &&
        deploymentPolicy.requiresNativeSessionRevocation() &&
        deploymentPolicy.maximumInteractiveConsoleSessionsPerConnection() ==
            1U;

    if (!verdict.gssAcceptorCredentialAvailable ||
        !verdict.pamServiceConfigured ||
        !verdict.identityPolicyConfigured ||
        !verdict.personalDesktopPolicyConfigured)
    {
        return verdict;
    }

    rdp_server::server::security::LinuxLogindReadOnlyEvidenceSource evidence;
    const rdp_server::server::security::ConsoleOsEvidenceInspector inspector;
    verdict.nativeSessionEvidenceAvailable =
        inspector.inspect(policy_, request, evidence) ==
        rdp_server::server::security::ConsoleEvidenceMatch::CandidateOnly;

    // Preflight is intentionally non-authorizing. Only the per-connection
    // broker can set authenticated admission by minting its private lease.
    verdict.authenticatedAdmission = false;
    return verdict;
}

bool LinuxRuntimeSecurityConfiguration::configureAcceptor(
    rdp_server::server::security::GssapiSpnegoAcceptor &acceptor)
    const noexcept
{
    if (!configured_ || keytabDescriptor_ < 0 ||
        servicePrincipalLength_ == 0 || policy_.size() == 0U ||
        policy_.generation() == 0U)
    {
        acceptor.reject();
        return false;
    }
    if (!acceptor.bindConsoleIdentityPolicy(policy_))
    {
        return false;
    }
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    if (passwordVerifier_.configured() &&
        !acceptor.bindLinuxPamPasswordVerifier(passwordVerifier_))
    {
        return false;
    }
#endif
    return configureAcceptorFromDescriptor(
        std::string_view(servicePrincipal_.data(), servicePrincipalLength_),
        keytabDescriptor_, acceptor);
}

std::string_view
LinuxRuntimeSecurityConfiguration::servicePrincipal() const noexcept
{
    if (!configured_)
    {
        return {};
    }
    return std::string_view(
        servicePrincipal_.data(), servicePrincipalLength_);
}

#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
std::string_view
LinuxRuntimeSecurityConfiguration::pamServiceName() const noexcept
{
    return configured_ ? passwordVerifier_.serviceName() : std::string_view{};
}
#endif

const rdp_server::server::security::ConsoleIdentityPolicy *
LinuxRuntimeSecurityConfiguration::policy() const noexcept
{
    return configured_ ? &policy_ : nullptr;
}

} // namespace rdp_server::server::runtime
