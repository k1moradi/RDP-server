// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_runtime_security.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <string_view>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rdp_server::server::runtime
{
namespace
{

constexpr std::size_t kMaximumKeytabBytes = 1024U * 1024U;
constexpr std::size_t kMaximumPathComponentBytes = 255;
constexpr std::string_view kFilePrefix{"FILE:"};
constexpr std::string_view kProcFdPrefix{"FILE:/proc/self/fd/"};

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
            const bool privateRegularKeytab =
                ::fstat(openedDescriptor, &information) == 0 &&
                S_ISREG(information.st_mode) &&
                information.st_size > 2 &&
                information.st_size <=
                    static_cast<off_t>(kMaximumKeytabBytes) &&
                information.st_uid == ::geteuid() &&
                (information.st_mode & S_IRUSR) != 0 &&
                (information.st_mode & (S_IRWXG | S_IRWXO)) == 0;
            if (!privateRegularKeytab)
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
    if (attempted_)
    {
        return false;
    }
    attempted_ = true;

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
    keytabDescriptor_ = openedKeytab;

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
    // authenticate a client or contact a KDC. Supplying /proc/self/fd keeps
    // acquisition tied to the already-opened, permission-checked keytab.
    rdp_server::server::security::GssapiSpnegoAcceptor probe;
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

bool LinuxRuntimeSecurityConfiguration::configureAcceptor(
    rdp_server::server::security::GssapiSpnegoAcceptor &acceptor)
    const noexcept
{
    if (!configured_ || keytabDescriptor_ < 0 ||
        servicePrincipalLength_ == 0)
    {
        acceptor.reject();
        return false;
    }
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

const rdp_server::server::security::ConsoleIdentityPolicy *
LinuxRuntimeSecurityConfiguration::policy() const noexcept
{
    return configured_ ? &policy_ : nullptr;
}

} // namespace rdp_server::server::runtime
