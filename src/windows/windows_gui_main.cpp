// SPDX-License-Identifier: GPL-3.0-or-later
// R6 Windows launcher consumes the shared R7 Qt UI. R2/R10 alone authorize
// authenticated host admission; this binary never creates such authority.
#include "desktop_window.h"
#include "host_control.h"

#include <QApplication>
#include <QByteArray>
#include <QPushButton>
#include <string_view>

namespace
{
[[nodiscard]] int verifyOfflineGui(rdp::gui::DesktopWindow &window,
                                    rdp::gui::UnavailableHostControl &control,
                                    const bool exerciseStartDenial)
{
    const auto status = control.status();
    if (status.controlAvailable || status.credentialProviderReady ||
        status.desktopAuthorized || status.sharing || window.canStart())
    {
        return 2;
    }

    auto *startButton = window.findChild<QPushButton *>("startSharing");
    auto *stopButton = window.findChild<QPushButton *>("stopSharing");
    auto *passwordField = window.findChild<QWidget *>("password");
    if (!startButton || !stopButton || !passwordField ||
        startButton->isEnabled() || stopButton->isEnabled() ||
        passwordField->isEnabled() || window.blockedReason().isEmpty())
    {
        return 3;
    }

    if (exerciseStartDenial)
    {
        // Disabled button clicks have no effect, and direct host control
        // refuses Start independently of the GUI's view of readiness.
        const rdp::gui::HostRequest request{};
        const bool accepted = control.start(request);
        startButton->click();
        window.refresh();
        if (accepted || control.status().sharing || window.canStart() ||
            startButton->isEnabled() || stopButton->isEnabled())
        {
            return 4;
        }
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
    {
        // CI starts no native window and opens no listener or permission UI.
        // Loading Qt verifies the genuine plugin/runtime dependency path.
        qputenv("QT_QPA_PLATFORM", QByteArray("offscreen"));
    }

    QApplication application(argc, argv);
    rdp::gui::UnavailableHostControl control;
    rdp::gui::DesktopWindow window(control);
    if (offlineSelfTest || offlineStartDenialTest)
    {
        return verifyOfflineGui(window, control, offlineStartDenialTest);
    }

    window.show();
    return application.exec();
}
