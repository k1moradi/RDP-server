// SPDX-License-Identifier: GPL-3.0-or-later
// R6 Windows user-mode shell. R7 owns the future common GUI; R2/R10 own
// authentication/admission and host control. This shell never starts a server.
#include <QApplication>
#include <QCoreApplication>
#include <QLabel>
#include <QMainWindow>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>
#include <QString>
#include <string_view>

int main(int argc, char *argv[])
{
    // Offline CTest mode runs before Qt initialization: no display, network,
    // filesystem, firewall, elevation or persistent configuration is accessed.
    if (argc == 2 && std::string_view{argv[1]} == "--offline-self-test")
    {
        return 0;
    }

    QApplication application(argc, argv);
    QMainWindow window;
    window.setWindowTitle(QStringLiteral("RDP-server — Windows LAN sharing"));
    window.resize(520, 340);

    auto *centralWidget = new QWidget(&window);
    auto *layout = new QVBoxLayout(centralWidget);
    auto *modeLabel = new QLabel(QStringLiteral("Mode: LAN sharing (not available yet)"), centralWidget);
    auto *addressLabel = new QLabel(QStringLiteral("Address: not listening"), centralWidget);
    auto *sessionsLabel = new QLabel(QStringLiteral("Sessions: 0 (host inactive)"), centralWidget);
    auto *credentialLabel = new QLabel(
        QStringLiteral("Access account: unavailable until R2 supplies an OS-backed CredSSP provider."), centralWidget);
    credentialLabel->setWordWrap(true);
    auto *reasonLabel = new QLabel(
        QStringLiteral("Start blocked: Windows authenticated SID/WTS admission and the R10 interactive-session owner are not implemented. An observed console token or TLS connection is insufficient."), centralWidget);
    reasonLabel->setWordWrap(true);
    auto *accountButton = new QPushButton(QStringLiteral("Configure access account"), centralWidget);
    accountButton->setEnabled(false);
    auto *startButton = new QPushButton(QStringLiteral("Start Sharing"), centralWidget);
    startButton->setEnabled(false);
    auto *stopButton = new QPushButton(QStringLiteral("Stop Sharing"), centralWidget);
    stopButton->setEnabled(false);

    layout->addWidget(modeLabel);
    layout->addWidget(addressLabel);
    layout->addWidget(sessionsLabel);
    layout->addWidget(credentialLabel);
    layout->addWidget(accountButton);
    layout->addWidget(reasonLabel);
    layout->addWidget(startButton);
    layout->addWidget(stopButton);
    layout->addStretch();
    window.setCentralWidget(centralWidget);
    window.show();
    return application.exec();
}
