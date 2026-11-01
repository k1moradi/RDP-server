// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_launch_options.h"
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
#elif defined(__APPLE__)
#include "server/runtime/mac_runtime_host_control.h"
#endif

#include <QApplication>
#include <QTimer>

#include <array>
#include <cstdio>
#include <span>
#include <string_view>
#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif
#include <utility>

namespace
{
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
    // Deny malformed argv and all argv-password variants before Qt or R10.
    std::array<std::string_view, rdp::gui::kDesktopMaximumArguments> arguments{};
    if (argc < 1 || argv == nullptr ||
        static_cast<std::size_t>(argc) > arguments.size())
    {
        std::fputs("rdp-server-desktop: invalid option\n", stderr);
        return 2;
    }
    for (int index = 0; index < argc; ++index)
    {
        if (argv[index] == nullptr)
        {
            std::fputs("rdp-server-desktop: invalid option\n", stderr);
            return 2;
        }
        arguments[static_cast<std::size_t>(index)] = argv[index];
    }
    rdp::gui::DesktopLaunchOptions launch;
    if (rdp::gui::parseDesktopLaunchOptions(
            std::span{arguments}.first(static_cast<std::size_t>(argc)),
            launch) != rdp::gui::DesktopLaunchError::None)
    {
        std::fputs("rdp-server-desktop: invalid or conflicting option\n", stderr);
        return 2;
    }
    if (launch.help)
    {
        std::fputs(
            "Usage: rdp-server-desktop [--username NAME] [--password-stdin] [--enable]\n"
            "       rdp-server-desktop --help\n"
            "       rdp-server-desktop --config FILE  (Linux expert mode)\n"
            "Sharing requires a separate owner confirmation in the GUI.\n",
            stdout);
        return 0;
    }

    const char* configurationPath =
        launch.configurationPath.empty() ? nullptr :
        launch.configurationPath.data();
#if !defined(__linux__)
    if (configurationPath != nullptr)
    {
        std::fputs("rdp-server-desktop: expert config unavailable\n", stderr);
        return 2;
    }
#endif
    QString startupPassword;
    if (launch.passwordFromStdin)
    {
#if defined(_WIN32)
        const bool terminalInput = _isatty(_fileno(stdin)) != 0;
#else
        const bool terminalInput = isatty(fileno(stdin)) != 0;
#endif
        if (terminalInput)
        {
            std::fputs("rdp-server-desktop: redirected password input required\n", stderr);
            return 3;
        }
        std::array<char, rdp::gui::kDesktopMaximumPasswordBytes + 1U>
            privateInput{};
        std::size_t passwordLength = 0;
        const auto inputResult =
            rdp::gui::readDesktopPasswordLine(stdin, privateInput, passwordLength);
        if (inputResult != rdp::gui::DesktopLaunchError::None)
        {
            rdp::gui::wipeDesktopPassword(privateInput);
            std::fputs("rdp-server-desktop: invalid private password input\n", stderr);
            return 3;
        }
        startupPassword = QString::fromUtf8(
            privateInput.data(), static_cast<qsizetype>(passwordLength));
        rdp::gui::wipeDesktopPassword(privateInput);
    }
    const QString startupUsername = launch.usernameProvided
        ? QString::fromUtf8(
              launch.username.data(), static_cast<qsizetype>(launch.username.size()))
        : QString{};

    QApplication application(argc, argv);
    // This is a Qt-only handoff. R2 exclusively owns future saved preferences.
    const auto applyLaunch = [&](rdp::gui::DesktopWindow& window) {
        const bool applied = window.applyStartupOptions(
            launch.usernameProvided ? &startupUsername : nullptr,
            launch.passwordFromStdin ? &startupPassword : nullptr,
            launch.requestSharingConfirmation);
        if (!startupPassword.isEmpty())
        {
            startupPassword.fill(QChar{u'\0'});
            startupPassword.clear();
        }
        return applied;
    };
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
        if (!applyLaunch(window))
        {
            std::fputs("rdp-server-desktop: password surface unavailable\n", stderr);
            return 3;
        }

        // Drain only a finite burst of already-actionable owner work.
        QTimer runtimeServiceTimer;
        runtimeServiceTimer.setInterval(
            rdp_server::server::runtime::kLinuxRuntimeServiceWaitMilliseconds);
        runtimeServiceTimer.setSingleShot(true);
        QObject::connect(
            &runtimeServiceTimer, &QTimer::timeout, &window,
            [&runtime, &runtimeServiceTimer] {
                const auto burst =
                    rdp_server::server::runtime::
                        serviceLinuxRuntimeBoundedBurst(
                            [&runtime] { return runtime.serviceOnce(); });
                runtimeServiceTimer.start(
                    burst.immediateReschedule
                        ? 0
                        : rdp_server::server::runtime::
                              kLinuxRuntimeServiceWaitMilliseconds);
            });
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

    // Normal zero-argument startup owns the complete application-lifetime
    // runtime aggregate. Construction provisions only local prerequisites;
    // the R1 listener still requires explicit Sharing after credentials,
    // owner permission and endpoint revalidation.
    rdp_server::server::runtime::LinuxPortableDesktopRuntime applicationRuntime;
    auto& runtime = applicationRuntime.hostControl();
#elif defined(__APPLE__)
    if (configurationPath != nullptr)
        return 2;
    rdp_server::server::runtime::MacPortableDesktopRuntime applicationRuntime;
    auto& runtime = applicationRuntime.hostControl();
#else
    if (configurationPath != nullptr)
        return 2;
    rdp_server::server::runtime::UnavailableRuntimeHostControl runtime;
#endif
    rdp::gui::HostControl control(runtime);
    rdp::gui::DesktopWindow window(control);
    if (!applyLaunch(window))
    {
        std::fputs("rdp-server-desktop: password surface unavailable\n", stderr);
        return 3;
    }
#if defined(__linux__) || defined(__APPLE__)
    QTimer runtimeServiceTimer;
#if defined(__linux__)
    runtimeServiceTimer.setInterval(
        rdp_server::server::runtime::kLinuxRuntimeServiceWaitMilliseconds);
    runtimeServiceTimer.setSingleShot(true);
    QObject::connect(
        &runtimeServiceTimer, &QTimer::timeout, &window,
        [&applicationRuntime, &runtimeServiceTimer] {
            const auto burst =
                rdp_server::server::runtime::
                    serviceLinuxRuntimeBoundedBurst(
                        [&applicationRuntime] {
                            return applicationRuntime.serviceOnce();
                        });
            runtimeServiceTimer.start(
                burst.immediateReschedule
                    ? 0
                    : rdp_server::server::runtime::
                          kLinuxRuntimeServiceWaitMilliseconds);
        });
#else
    runtimeServiceTimer.setInterval(25);
    QObject::connect(
        &runtimeServiceTimer, &QTimer::timeout, &window,
        [&applicationRuntime] { (void)applicationRuntime.serviceOnce(); });
#endif
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
