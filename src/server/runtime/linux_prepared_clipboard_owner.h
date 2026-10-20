// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "clipboard/clipboard_protocol.h"
#include "linux_runtime_connection.h"
#include "runtime_deployment_policy.h"
#include "server/clipboard/r3_clipboard_transfer_bridge.h"
#include "x11/x11_clipboard_adapter.h"
#include "x11/x11_desktop_resources.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>

namespace rdp_server::server::runtime
{

// Production R8 activation remains blocked until the first real Windows App
// video/input/Stop acceptance is recorded. Keep this hard gate false in M1;
// the prepared route below is still compiled and reviewed in ordinary builds.
inline constexpr bool kLinuxProductionClipboardActivationApproved = false;

// Owned by exactly one serialized R10 accepted-client/native lifetime. It
// borrows R5's XCB owner and never owns R1/R2/R3. The R2 admission/session pair
// is retained only as stale-work provenance; every clipboard transition still
// re-enters R2.
class LinuxPreparedClipboardOwner final {
public:
    using Connection =
        rdp_server::server::runtime::LinuxRuntimeConnection;
    using Policy =
        rdp_server::server::runtime::RuntimeDeploymentPolicy;
    using Bridge =
        rdp_server::server::clipboard::R3ClipboardTransferBridge;
    using Adapter = ::X11ClipboardAdapter;
    using Clock = std::chrono::steady_clock;

    LinuxPreparedClipboardOwner() noexcept = default;
    ~LinuxPreparedClipboardOwner() noexcept { retire(); }

    LinuxPreparedClipboardOwner(const LinuxPreparedClipboardOwner&) = delete;
    LinuxPreparedClipboardOwner& operator=(
        const LinuxPreparedClipboardOwner&) = delete;

    [[nodiscard]] bool prepare(
        ::X11DesktopResources& desktop, std::uint64_t admissionGeneration,
        std::uint64_t sessionGeneration) noexcept {
        if (!kLinuxProductionClipboardActivationApproved) {
            return true;
        }
        xcb_connection_t* nativeConnection = desktop.nativeConnection();
        if (nativeConnection == nullptr ||
            desktop.rootWindow() == XCB_WINDOW_NONE ||
            admissionGeneration == 0U || sessionGeneration == 0U) {
            return false;
        }

        // No image/file/directory transfer is exposed by the first production
        // activation. Existing richer R8 machinery remains offline-only.
        bridge_.emplace(0U, true);
        adapter_.emplace(
            bridge_->transfer(), *nativeConnection, desktop.rootWindow(),
            Adapter::PresentationScope::UnicodeTextOnly);
        if (!adapter_->valid()) {
            retire();
            return false;
        }

        admissionGeneration_ = admissionGeneration;
        sessionGeneration_ = sessionGeneration;
        return true;
    }

    [[nodiscard]] bool active() const noexcept {
        return bridge_.has_value() && adapter_.has_value() &&
               adapter_->valid();
    }

    [[nodiscard]] bool generationsMatch(
        std::uint64_t admissionGeneration,
        std::uint64_t sessionGeneration) const noexcept {
        return !active() ||
               (admissionGeneration_ == admissionGeneration &&
                sessionGeneration_ == sessionGeneration);
    }

    [[nodiscard]] ::X11EventSink* eventSink() noexcept {
        return active() ? static_cast<::X11EventSink*>(&*adapter_) : nullptr;
    }

    [[nodiscard]] bool dispatchAuthenticatedTpkt(
        Connection& connection, const Policy& policy,
        std::span<const std::uint8_t> completeTpkt) noexcept {
        return active() &&
               connection.visitPersonalDesktopClipboardChannel(
                   policy, bridge_->channelVisitor()) &&
               connection.dispatchPersonalDesktopClipboardTpkt(
                   policy, completeTpkt, bridge_->completePduSink());
    }

    [[nodiscard]] bool serviceAfterNetworkDispatch(
        Connection& connection, const Policy& policy,
        Clock::time_point now) noexcept {
        if (!active()) {
            return true;
        }
        if (!queuePendingApplicationPdu(connection, policy)) {
            return false;
        }

        // A non-text remote offer is a valid CLIPRDR exchange but must not
        // claim the native clipboard during the first acceptance phase.
        (void)adapter_->publishCurrentRemoteOffer(now);
        return adapter_->servicePendingPaste(now);
    }

    [[nodiscard]] bool serviceNative(
        Connection& connection, const Policy& policy,
        Clock::time_point now, bool mayStartRemoteFetch) noexcept {
        if (!active()) {
            return true;
        }
        if (!adapter_->servicePendingPaste(now)) {
            return false;
        }
        if (!mayStartRemoteFetch || writePending_) {
            return true;
        }

        const auto fetch = adapter_->pendingRemoteFetch();
        if (!fetch) {
            return true;
        }
        if (fetch->kind !=
                rdp_server::server::clipboard::RemoteTransfer::PasteKind::
                    UnicodeText ||
            fetch->formatId != rdp_server::clipboard::kFormatUnicodeText) {
            return false;
        }

        // The native request is intent only. Fresh R2 clipboard permission and
        // the exact R3 route are required before staging the Unicode request.
        if (!connection.visitPersonalDesktopClipboardChannel(
                policy, bridge_->channelVisitor()) ||
            !bridge_->beginFormatDataRequest(fetch->formatId) ||
            !queuePendingApplicationPdu(connection, policy) ||
            !adapter_->markRemoteFetchStarted(fetch->pasteSequence)) {
            return false;
        }
        return true;
    }

    [[nodiscard]] bool writePending() const noexcept {
        return active() && writePending_;
    }

    [[nodiscard]] bool advanceTlsWrite(
        Connection& connection, const Policy& policy,
        bool readable, bool writable) noexcept {
        using Step =
            rdp_server::server::runtime::LinuxClipboardTlsWriteStatus;
        if (!writePending()) {
            return true;
        }

        const auto result =
            connection.advancePersonalDesktopClipboardTlsWrite(
                policy, readable, writable);
        if (result.acceptedBytes != 0U &&
            !bridge_->recordAcceptedWriteReceipt(
                result.routeGeneration, result.replySequence,
                result.writeSliceSequence, result.offeredBytes,
                result.acceptedBytes, result.receipt)) {
            return false;
        }

        switch (result.status) {
        case Step::Progress:
        case Step::NeedRead:
        case Step::NeedWrite:
            return true;
        case Step::Delivered:
            writePending_ = false;
            return true;
        case Step::AdmissionDenied:
        case Step::Invalid:
        case Step::Closed:
            return false;
        }
        return false;
    }

    void retire() noexcept {
        // X11 INCR/paste spans may borrow RemoteTransfer storage. Cancel them
        // before retiring bridge/source state, then discard response/receipt
        // identity before this R10 candidate can be replaced.
        if (adapter_) {
            adapter_->disconnect();
            adapter_.reset();
        }
        if (bridge_) {
            bridge_->retireR3ChannelState();
            bridge_.reset();
        }
        writePending_ = false;
        admissionGeneration_ = 0U;
        sessionGeneration_ = 0U;
    }

private:
    [[nodiscard]] bool queuePendingApplicationPdu(
        Connection& connection, const Policy& policy) noexcept {
        const auto applicationPdu = bridge_->pendingApplicationPdu();
        if (applicationPdu.empty() || writePending_) {
            return true;
        }

        const auto write =
            connection.queuePersonalDesktopClipboardPdu(
                policy, applicationPdu);
        if (!write || !bridge_->bindQueuedWrite(*write)) {
            return false;
        }
        writePending_ = true;
        return true;
    }

    // Declaration order is intentional: adapter_ is explicitly disconnected
    // before bridge_ clears RemoteTransfer, and both die before R5/R1 owners.
    std::optional<Bridge> bridge_{};
    std::optional<Adapter> adapter_{};
    std::uint64_t admissionGeneration_{};
    std::uint64_t sessionGeneration_{};
    bool writePending_{};
};

} // namespace rdp_server::server::runtime
