// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include "host_control.h"
#include "server/runtime/runtime_host_control.h"
#if defined(__linux__)
#include "server/runtime/linux_runtime_host_control.h"
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
#include "server/runtime/linux_runtime_security.h"
#include "server/runtime/runtime_configuration.h"
#include "server/runtime/runtime_licensing_context.h"
#include "server/runtime/runtime_tls_context.h"
#endif
#endif

#include <QApplication>

#include <string_view>
#include <utility>

namespace
{
[[nodiscard]] const char* requestedConfigurationPath(
    int argc, char** argv, bool& invalid) noexcept
{
    invalid = false;
    const char* path = nullptr;
    for (int index = 1; index < argc; ++index)
    {
        if (argv[index] == nullptr ||
            std::string_view{argv[index]} != "--config")
            continue;
        if (path != nullptr || index + 1 >= argc ||
            argv[index + 1] == nullptr || *argv[index + 1] == '\0')
        {
            invalid = true;
            return nullptr;
        }
        path = argv[++index];
    }
    return path;
}

#if defined(__linux__) && defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
struct LinuxDesktopProvisioningContext final
{
    rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration*
        security{};
    rdp_server::server::runtime::RuntimeServerTlsContext* tls{};
    rdp_server::server::runtime::RuntimeLicensingContext* licensing{};
};

[[nodiscard]] constexpr
rdp_server::server::runtime::RuntimeConfigurationCapabilities
linuxDesktopConfigurationCapabilities() noexcept
{
    rdp_server::server::runtime::RuntimeConfigurationCapabilities
        capabilities{true, false};
#if defined(RDP_SERVER_HAVE_LINUX_PAM_PASSWORD_VERIFIER)
    capabilities.linuxPam = true;
#endif
    return capabilities;
}

[[nodiscard]] bool provisionLinuxDesktop(
    const rdp_server::server::runtime::RuntimeConfigurationView&
        configuration,
    void* rawContext) noexcept
{
    auto* context =
        static_cast<LinuxDesktopProvisioningContext*>(rawContext);
    if (context == nullptr || context->security == nullptr ||
        context->tls == nullptr || context->licensing == nullptr)
        return false;

    if (!rdp_server::server::runtime::
            configureLinuxRuntimeSecurityFromConfiguration(
                configuration, *context->security))
        return false;

    using Field =
        rdp_server::server::runtime::RuntimeConfigurationField;
    auto tls =
        rdp_server::server::runtime::RuntimeServerTlsContext::
            fromCredentialFiles(
                configuration.field(Field::TlsCertificate),
                configuration.field(Field::TlsPrivateKey));
    if (!tls ||
        !rdp_server::server::runtime::
            configureRuntimeLicensingContextFromConfiguration(
                configuration, *context->licensing))
        return false;

    *context->tls = std::move(tls);
    return true;
}
#endif
} // namespace

int main(int argc, char** argv)
{
    bool invalidConfigurationArgument = false;
    const char* configurationPath =
        requestedConfigurationPath(
            argc, argv, invalidConfigurationArgument);
    if (invalidConfigurationArgument)
        return 2;

    QApplication application(argc, argv);
#if defined(__linux__)
#if defined(RDP_SERVER_HAVE_LINUX_HOST_SECURITY)
    if (configurationPath != nullptr)
    {
        rdp_server::server::runtime::LinuxRuntimeSecurityConfiguration
            securityConfiguration;
        rdp_server::server::runtime::RuntimeServerTlsContext tlsContext;
        rdp_server::server::runtime::RuntimeLicensingContext
            licensingContext;
        LinuxDesktopProvisioningContext provisioning{
            &securityConfiguration, &tlsContext, &licensingContext};
        if (!rdp_server::server::runtime::visitRuntimeConfigurationFile(
                configurationPath,
                linuxDesktopConfigurationCapabilities(),
                &provisionLinuxDesktop, &provisioning))
            return 2;

        rdp_server::server::runtime::LinuxRuntimeHostControl runtime{
            securityConfiguration, tlsContext};
        rdp::gui::HostControl control(runtime);
        rdp::gui::DesktopWindow window(control);
        window.show();
        return application.exec();
    }
#else
    if (configurationPath != nullptr)
        return 2;
#endif

    // Ordinary GUI-only builds remain explicitly unprovisioned and fail closed.
    rdp_server::server::runtime::LinuxRuntimeHostControl runtime;
#else
    if (configurationPath != nullptr)
        return 2;
    rdp_server::server::runtime::UnavailableRuntimeHostControl runtime;
#endif
    rdp::gui::HostControl control(runtime);
    rdp::gui::DesktopWindow window(control);
    window.show();
    return application.exec();
}
