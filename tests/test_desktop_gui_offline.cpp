// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include <QApplication>
#include <QClipboard>
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
    bool refuseStop = false;
    HostStatus status() const override { return snapshot; }
    bool start(const HostRequest&) override { ++startCalls; return false; }
    void stopAndRevoke() override {
        ++stopCalls;
        if (!refuseStop) {
            snapshot.sharing = false;
            snapshot.startPending = false;
            snapshot.revoked = {"Revoked"};
        }
    }
};
int main(int argc, char** argv) {
    QApplication application(argc, argv);
    FakeHost host;
    if (argc > 1 && QString::fromLocal8Bit(argv[1]) == "close") {
        DesktopWindow window(host);
        window.show();
        application.processEvents();
        host.snapshot.startPending = true;
        host.refuseStop = true;
        window.refresh();
        assert(!window.close());
        assert(window.isVisible() && host.stopCalls == 1);
        host.refuseStop = false;
        assert(window.close());
        assert(host.stopCalls == 2 && !host.snapshot.startPending);
        return 0;
    }
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
        auto* copy = window.findChild<QPushButton*>("copyLanAddress");
        assert(next && back && start && stop && secret && confirm && interfaceSelection && clients);
        assert(copy && !copy->isEnabled());
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
        host.snapshot.approvedLanInterfaces = {"192.168.0.10"};
        window.refresh();
        assert(!window.canStart());
        interfaceSelection->setCurrentIndex(1);
        window.refresh();
        secret->setEnabled(true); // Test-only confirmation branch; production stays disabled.
        confirm->setEnabled(true);
        assert(!window.canStart() && window.blockedReason().contains("confirmation mismatch"));
        assert(!window.blockedReason().contains("test-only-secret"));
        confirm->setText("test-only-secret");
        assert(window.canStart());
        secret->setEnabled(false);
        confirm->setEnabled(false);
        assert(window.canStart() && start->isEnabled());
        start->click();
        assert(host.startCalls == 1 && !host.snapshot.sharing); // fake cannot grant sharing
        assert(!copy->isEnabled());
        host.snapshot.sharing = true; // independent status-rendering-only fixture
        host.snapshot.lanAddress = "192.168.0.10:3389";
        host.snapshot.clients = {"Local test client"};
        host.snapshot.authenticationFailures = {"Rejected identity"};
        host.snapshot.disconnected = {"Disconnected client"};
        window.refresh();
        assert(stop->isEnabled() && copy->isEnabled() && clients->text().contains("Rejected identity"));
        copy->click();
        assert(application.clipboard()->text() == "192.168.0.10:3389");
        host.snapshot.approvedLanInterfaces.clear();
        window.refresh();
        assert(!window.canStart());
        stop->click();
        assert(host.stopCalls == 1 && !host.snapshot.sharing && !copy->isEnabled());
        assert(clients->text().contains("Revoked"));
        for (int page = 0; page < 5; ++page) back->click();
        window.close();
    }
    UnavailableHostControl production;
    assert(!production.status().controlAvailable && !production.start({}));
    return 0;
}
