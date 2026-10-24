// SPDX-License-Identifier: GPL-3.0-or-later
#include "desktop_window.h"
#include "host_control.h"
#include "server/runtime/linux_runtime_host_control.h"
#include "server/security/console_os_evidence.h"
#include "server/security/linux_logind_console_evidence.h"

#include <QAbstractButton>
#include <QApplication>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTabWidget>
#include <QWidget>

#include <cassert>
#include <cstdint>
#include <optional>
#include <string_view>

using namespace rdp::gui;
using namespace rdp_server::server::runtime;
using namespace rdp_server::server::security;

namespace
{
class OwnerPhysicalX11Evidence final : public ConsoleOsEvidenceSource
{
public:
    [[nodiscard]] ConsoleAccountObservation readUnixAccount(
        std::string_view) noexcept override
    {
        return {};
    }

    [[nodiscard]] ConsoleSessionObservation readActiveConsole() noexcept override
    {
        return {
            ConsoleEvidenceReadStatus::Observed,
            "owner-x11", "seat0", ":42", kOwnerUid, 91U, kNowMilliseconds,
            true, true, kOwnerUid, ConsoleDesktopLockState::Unlocked, false};
    }

    [[nodiscard]] std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override
    {
        return kNowMilliseconds;
    }

    static constexpr std::uint32_t kOwnerUid = 1000U;
    static constexpr std::uint64_t kNowMilliseconds = 10'000U;
};
} // namespace

int main(int argc, char** argv)
{
#if !defined(RDP_SERVER_OWNER_ACCEPTANCE_TEST_UI)
    (void)argc;
    (void)argv;
    return 77;
#else
    QApplication application(argc, argv);

    OwnerPhysicalX11Evidence evidence;
    const ConsoleSessionObservation observed = evidence.readActiveConsole();
    assert(observed.status == ConsoleEvidenceReadStatus::Observed);
    assert(observed.active && observed.physical && !observed.remote);
    assert(observed.seat == "seat0");
    assert(observed.display == ":42");
    assert(observed.ownerUid == OwnerPhysicalX11Evidence::kOwnerUid);
    assert(observed.localProcessUid == OwnerPhysicalX11Evidence::kOwnerUid);
    assert(observed.lockState == ConsoleDesktopLockState::Unlocked);

    const auto selected = selectCurrentPhysicalX11Desktop(evidence);
    assert(selected.eligible());
    assert(selected.display() == ":42");
    assert(selected.ownerUid == OwnerPhysicalX11Evidence::kOwnerUid);
    assert(selected.sessionGeneration == 91U);

    LinuxRuntimeHostControl runtime(evidence);
    const RuntimeHostStatus before = runtime.status();
    assert(before.product.controlAvailable);
    assert(before.product.nativeDesktopTargetAvailable);
    assert(before.product.nativeDesktopTarget == ":42");
    assert(!before.product.credentialsConfigured);
    assert(!before.product.ownerAuthorized);
    assert(before.product.sharingPermission.canRequest);
    assert(!before.product.sharingPermission.activeGrant);
    assert(before.product.sharingPermission.denial ==
           RuntimeSharingPermissionDenial::PermissionRequired);
    assert(!before.listenerAvailable);
    assert(before.boundEndpoint.empty());
    assert(!before.graphicsReady);
    assert(!before.nativeDesktopReady);
    assert(!before.firstLiveGraphicsTrace.firstFramebufferAvailable);
    assert(!before.product.credentialCapabilities.standalonePassword);
    static_assert(!kStandalonePasswordProductCapabilityApproved);

    if (!before.product.recommendedEndpoint.valid())
        return 77;

    HostControl host(runtime);
    const HostStatus projected = host.status();
    assert(projected.desktop == QStringLiteral("Physical X11 desktop :42"));
    assert(projected.sharingPermission.canRequest);
    assert(!projected.desktopAuthorized);
    assert(projected.recommendedAddress ==
           QString::fromStdString(before.product.recommendedEndpoint.address));

    DesktopWindow window(host);
    auto* tabs = window.findChild<QTabWidget*>("settingsTabs");
    auto* mainTab = window.findChild<QWidget*>("mainTab");
    auto* username = window.findChild<QLineEdit*>("standaloneUsername");
    auto* password = window.findChild<QLineEdit*>("sessionPassword");
    auto* confirmation =
        window.findChild<QLineEdit*>("sessionPasswordConfirm");
    auto* sharing = window.findChild<QAbstractButton*>("sharingToggle");
    auto* permission =
        window.findChild<QPushButton*>("requestHostPermission");
    auto* address = window.findChild<QLabel*>("connectionAddress");
    auto* copy = window.findChild<QPushButton*>("copyLanAddress");

    assert(tabs && mainTab && username && password && confirmation);
    assert(sharing && permission && address && copy);
    assert(tabs->isEnabled() && mainTab->isEnabled());

    assert(!username->isHidden());
    assert(!password->isHidden());
    assert(!confirmation->isHidden());
    assert(username->isEnabled() && !username->isReadOnly());
    assert(password->isEnabled() && !password->isReadOnly());
    assert(confirmation->isEnabled() && !confirmation->isReadOnly());
    assert(username->focusPolicy() != Qt::NoFocus);
    assert(password->focusPolicy() != Qt::NoFocus);
    assert(confirmation->focusPolicy() != Qt::NoFocus);
    assert(password->echoMode() == QLineEdit::Password);
    assert(confirmation->echoMode() == QLineEdit::Password);

    assert(address->text() ==
           QStringLiteral("Local address: ") +
               QString::fromStdString(before.product.recommendedEndpoint.address));
    assert(!copy->isEnabled());
    assert(!permission->isEnabled());
    assert(!window.canStart());

    username->setText(QStringLiteral("rdp-owner"));
    password->setText(QStringLiteral("fixture-entry"));
    confirmation->setText(QStringLiteral("different"));
    window.refresh();
    assert(!window.canStart());

    confirmation->setText(password->text());
    window.refresh();

    assert(username->isEnabled() && !username->isReadOnly());
    assert(password->isEnabled() && !password->isReadOnly());
    assert(confirmation->isEnabled() && !confirmation->isReadOnly());
    assert(username->text() == QStringLiteral("rdp-owner"));
    assert(password->text() == QStringLiteral("fixture-entry"));
    assert(confirmation->text() == password->text());
    assert(window.canStart());
    assert(sharing->isEnabled());

    const RuntimeHostStatus after = runtime.status();
    assert(after.product.nativeDesktopTargetAvailable);
    assert(after.product.nativeDesktopTarget == ":42");
    assert(after.product.sharingPermission.canRequest);
    assert(!after.product.sharingPermission.activeGrant);
    assert(!after.product.credentialsConfigured);
    assert(!after.product.ownerAuthorized);
    assert(after.ownerGrant.state == RuntimeOwnerGrantState::Unavailable);
    assert(!after.listenerAvailable);
    assert(after.selectedEndpoint.empty());
    assert(after.boundEndpoint.empty());
    assert(!after.graphicsReady);
    assert(!after.nativeDesktopReady);
    assert(!after.firstLiveGraphicsTrace.firstFramebufferAvailable);
    return 0;
#endif
}
