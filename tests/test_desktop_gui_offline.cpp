// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include <QApplication>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <cassert>
using namespace rdp::gui;
struct FakeHost final : HostControl {
    HostStatus snapshot;
    int startCalls = 0;
    int stopCalls = 0;
    HostStatus status() const override { return snapshot; }
    bool start(const HostRequest&) override { ++startCalls; return false; }
    void stopAndRevoke() override { ++stopCalls; snapshot.sharing = false; snapshot.revoked = {"Revoked"}; }
};
int main(int argc, char** argv) {
    QApplication application(argc, argv);
    FakeHost host;
    {
        DesktopWindow window(host);
        assert(host.startCalls == 0 && !window.canStart());
        auto* next = window.findChild<QPushButton*>("nextPage");
        auto* back = window.findChild<QPushButton*>("backPage");
        auto* start = window.findChild<QPushButton*>("startSharing");
        auto* stop = window.findChild<QPushButton*>("stopSharing");
        auto* secret = window.findChild<QLineEdit*>("password");
        auto* confirm = window.findChild<QLineEdit*>("confirmation");
        auto* interfaceSelection = window.findChild<QComboBox*>("lanInterface");
        auto* clients = window.findChild<QLabel*>("clientStatus");
        assert(next && back && start && stop && secret && confirm && interfaceSelection && clients);
        for (int page = 0; page < 5; ++page) next->click();
        assert(!start->isEnabled() && !stop->isEnabled());
        assert(!secret->isEnabled() && !confirm->isEnabled());
        secret->setText("test-only-secret");
        confirm->setText("does-not-match");
        assert(!window.blockedReason().contains("test-only-secret"));
        host.snapshot.controlAvailable = true;
        host.snapshot.credentialProviderReady = true;
        host.snapshot.desktopAuthorized = true;
        host.snapshot.desktop = "Real desktop candidate";
        host.snapshot.tlsReady = true;
        host.snapshot.firewallReady = true;
        host.snapshot.captureInputReady = true;
        interfaceSelection->addItem("Local private LAN", "192.168.0.10");
        interfaceSelection->setCurrentIndex(1);
        window.refresh();
        assert(window.canStart() && start->isEnabled());
        start->click();
        assert(host.startCalls == 1 && !host.snapshot.sharing); // fake cannot grant sharing
        host.snapshot.sharing = true; // independent status-rendering-only fixture
        host.snapshot.lanAddress = "192.168.0.10:3389";
        host.snapshot.clients = {"Local test client"};
        host.snapshot.authenticationFailures = {"Rejected identity"};
        host.snapshot.disconnected = {"Disconnected client"};
        window.refresh();
        assert(stop->isEnabled() && clients->text().contains("Rejected identity"));
        stop->click();
        assert(host.stopCalls == 1 && !host.snapshot.sharing);
        assert(clients->text().contains("Revoked"));
        for (int page = 0; page < 5; ++page) back->click();
        window.close();
    }
    UnavailableHostControl production;
    assert(!production.status().controlAvailable && !production.start({}));
    return 0;
}
