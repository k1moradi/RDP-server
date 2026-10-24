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
#include <QTimer>

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
    rdp_server::server::runtime::LinuxRuntimeAdmissionConfiguration*
        admission{};
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
        context->tls == nullptr || context->admission == nullptr ||
        context->licensing == nullptr)
        return false;

    if (!rdp_server::server::runtime::
            configureLinuxRuntimeSecurityFromConfiguration(
                configuration, *context->security) ||
        !rdp_server::server::runtime::
            configureLinuxRuntimeAdmissionFromConfiguration(
                configuration, *context->security, *context->admission))
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
        rdp_server::server::runtime::LinuxRuntimeAdmissionConfiguration
            admissionConfiguration;
        rdp_server::server::runtime::RuntimeLicensingContext
            licensingContext;
        LinuxDesktopProvisioningContext provisioning{
            &securityConfiguration, &tlsContext,
            &admissionConfiguration, &licensingContext};
        if (!rdp_server::server::runtime::visitRuntimeConfigurationFile(
                configurationPath,
                linuxDesktopConfigurationCapabilities(),
                &provisionLinuxDesktop, &provisioning))
            return 2;

        rdp_server::server::runtime::LinuxRuntimeHostControl runtime{
            securityConfiguration, tlsContext,
            admissionConfiguration, licensingContext};
        rdp::gui::HostControl control(runtime);
        rdp::gui::DesktopWindow window(control);

        // R10 remains on the Qt owner thread. Each tick performs at most one
        // bounded protocol operation and a zero-wait readiness observation;
        // there is no worker thread, blocking poll or second socket owner.
        QTimer runtimeServiceTimer;
        runtimeServiceTimer.setInterval(25);
        QObject::connect(
            &runtimeServiceTimer, &QTimer::timeout, &window,
            [&runtime] { (void)runtime.serviceOnce(); });
        runtimeServiceTimer.start();

        // Status projection is deliberately slower than protocol servicing so
        // interface enumeration/UI layout cannot become the network scheduler.
        QTimer statusRefreshTimer;
        statusRefreshTimer.setInterval(250);
        QObject::connect(
            &statusRefreshTimer, &QTimer::timeout, &window,
            [&window] { window.refresh(); });
        statusRefreshTimer.start();

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
#if defined(__linux__)
    // The canonical no-argument product path owns the same bounded R10 service
    // loop as the expert --config path. Construction/provisioning alone never
    // opens a listener; only the user's explicit Sharing action can do that.
    QTimer runtimeServiceTimer;
    runtimeServiceTimer.setInterval(25);
    QObject::connect(
        &runtimeServiceTimer, &QTimer::timeout, &window,
        [&runtime] { (void)runtime.serviceOnce(); });
    runtimeServiceTimer.start();

    QTimer statusRefreshTimer;
    statusRefreshTimer.setInterval(250);
    QObject::connect(
        &statusRefreshTimer, &QTimer::timeout, &window,
        [&window] { window.refresh(); });
    statusRefreshTimer.start();
#endif
    window.show();
    return application.exec();
}
