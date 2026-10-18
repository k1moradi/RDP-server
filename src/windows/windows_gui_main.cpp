// SPDX-License-Identifier: GPL-3.0-or-later
// R6 Windows launcher consumes the shared R7 Qt UI. R2/R10 alone authorize
// authenticated host admission; this binary never creates such authority.
#include "desktop_window.h"
#include "host_control.h"
#include "server/runtime/runtime_host_control.h"

#include <QApplication>
#include <QByteArray>
#include <QPushButton>
#include <string_view>

namespace
{
[[nodiscard]] int verifyOfflineGui(rdp::gui::DesktopWindow &window,
                                    rdp::gui::HostControl &control,
                                    const bool exerciseStartDenial)
{
    const auto status = control.status();
    if (status.controlAvailable || status.credentialsConfigured ||
        status.desktopAuthorized || status.sharing || window.canStart())
        return 2;

    auto *startButton = window.findChild<QPushButton *>("startSharing");
    auto *stopButton = window.findChild<QPushButton *>("stopSharing");
    auto *passwordField = window.findChild<QWidget *>("password");
    if (!startButton || !stopButton || !passwordField ||
        startButton->isEnabled() || stopButton->isEnabled() ||
        passwordField->isEnabled() || window.blockedReason().isEmpty())
        return 3;

    if (exerciseStartDenial)
    {
        const rdp::gui::HostRequest request{};
        const bool accepted = control.start(request);
        startButton->click();
        window.refresh();
        if (accepted || control.status().sharing || window.canStart() ||
            startButton->isEnabled() || stopButton->isEnabled())
            return 4;
    }
    return 0;
}
} // namespace

int main(int argc, char *argv[])
{
    const bool offlineSelfTest =
        argc == 2 && std::string_view{argv[1]} == "--offline-self-test";
    const bool offlineStartDenialTest =
        argc == 2 && std::string_view{argv[1]} == "--offline-start-denial-test";
    if (offlineSelfTest || offlineStartDenialTest)
        // The portable Windows contract guarantees qwindows.dll, not Qt's
        // developer-only offscreen platform plugin. Keep command-mode
        // verification hidden by never showing the window, but initialize
        // through the same packaged platform plugin as normal launch.
        qputenv("QT_QPA_PLATFORM", QByteArray("windows"));

    QApplication application(argc, argv);
    rdp_server::server::runtime::UnavailableRuntimeHostControl runtime;
    rdp::gui::HostControl control(runtime);
    rdp::gui::DesktopWindow window(control);
    if (offlineSelfTest || offlineStartDenialTest)
        return verifyOfflineGui(window, control, offlineStartDenialTest);

    window.show();
    return application.exec();
}
