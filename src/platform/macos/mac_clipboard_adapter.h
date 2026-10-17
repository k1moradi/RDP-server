// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "mac_clipboard_file_destination.h"
#include "server/clipboard/remote_transfer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace rdp::macos
{

// Borrowed current-generation content passed synchronously to the native seam.
// The native implementation copies the selected representations before return.
struct MacClipboardNativeContent final
{
    std::string_view utf8Text{};
    std::span<const std::string_view> fileUrls{};
    std::span<const std::byte> pngBytes{};
    bool hasText{};
    bool hasPng{};
    bool hasFileUrls{};
};

// Allocation-free native pasteboard seam. Production callbacks are backed by
// NSPasteboard only on Apple; ordinary CTests inject deterministic operations
// and never read or mutate the host pasteboard.
struct MacClipboardNativeOperations final
{
    void *context{};
    bool (*readChangeCount)(void *, std::uint64_t &) noexcept{};
    bool (*replaceContents)(
        void *, const MacClipboardNativeContent &) noexcept{};
    bool (*clearContents)(void *) noexcept{};
};

// Native macOS pasteboard presentation for one RemoteTransfer owner.
//
// RemoteTransfer remains the sole CLIPRDR generation/data owner. This adapter
// owns only native publication state and is event-loop/thread confined. It
// never performs virtual-channel I/O, waits for RDP data, or grants session
// authorization. Only already-verified current-generation UTF-8 text and
// genuine named PNG are copied to the pasteboard.
class MacClipboardAdapter final
{
public:
    using RemoteTransfer =
        rdp_server::server::clipboard::RemoteTransfer;
    using RemoteFileDestinationPlan =
        rdp_server::server::clipboard::RemoteFileDestinationPlan;

    MacClipboardAdapter(
        RemoteTransfer &remoteTransfer,
        MacClipboardNativeOperations nativeOperations) noexcept;
    ~MacClipboardAdapter() noexcept;

    MacClipboardAdapter(const MacClipboardAdapter &) = delete;
    MacClipboardAdapter &operator=(const MacClipboardAdapter &) = delete;
    MacClipboardAdapter(MacClipboardAdapter &&) = delete;
    MacClipboardAdapter &operator=(MacClipboardAdapter &&) = delete;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] bool ownsPasteboard() const noexcept;
    [[nodiscard]] std::uint64_t publicationGeneration() const noexcept;
    [[nodiscard]] std::uint64_t publicationChangeCount() const noexcept;

    // Replace the general pasteboard only with data already verified by the
    // current RemoteTransfer generation. A local takeover yields that remote
    // generation so repeated publication cannot immediately steal it back.
    [[nodiscard]] bool publishReadyRemoteGeneration() noexcept;

    // Publish exactly one completed caller-selected local file URL. The
    // destination must be Complete and still belong to the current remote
    // generation. Partial files and stale completed generations are refused.
    [[nodiscard]] bool publishCompletedFileDestination(
        const MacClipboardFileDestination &destination) noexcept;

    // Atomically publish one complete current-generation planned set as
    // multiple file NSURL objects. Input order is irrelevant; publication
    // follows the committed plan's exact remote descriptor index order.
    [[nodiscard]] bool publishCompletedFileDestinations(
        const RemoteFileDestinationPlan &plan,
        std::span<const MacClipboardFileDestination *const>
            destinations) noexcept;

    // Compare the native pasteboard change count with the count recorded after
    // publication. A mismatch means another owner took the pasteboard.
    [[nodiscard]] bool observePasteboardChange() noexcept;

    // Call when RemoteTransfer's generation changes. Immediate pasteboard data
    // from the old generation is cleared only while its recorded change count
    // still proves this adapter owns the pasteboard.
    void onRemoteGenerationChanged() noexcept;

    // Idempotent. Clear our publication only if change-count ownership still
    // matches; never erase a newer local application's pasteboard contents.
    void disconnect() noexcept;

private:
    [[nodiscard]] bool nativeOperationsValid() const noexcept;
    [[nodiscard]] bool refreshNativeOwnership() noexcept;
    [[nodiscard]] bool clearOwnedPublication() noexcept;
    [[nodiscard]] bool collectCompletedFileUrls(
        const RemoteFileDestinationPlan *plan,
        std::span<const MacClipboardFileDestination *const>
            destinations,
        std::uint64_t generation,
        std::array<std::string_view,
                   RemoteTransfer::kMaximumRemoteFiles> &fileUrls) const noexcept;
    [[nodiscard]] bool publishCompletedFileDestinationsInternal(
        const RemoteFileDestinationPlan *plan,
        std::span<const MacClipboardFileDestination *const>
            destinations) noexcept;
    void clearPublicationState() noexcept;
    void finishDeferredActions() noexcept;

    RemoteTransfer &remoteTransfer_;
    MacClipboardNativeOperations nativeOperations_{};
    std::uint64_t publicationGeneration_{};
    std::uint64_t yieldedGeneration_{};
    std::uint64_t publicationChangeCount_{};
    bool textPublished_{};
    bool pngPublished_{};
    bool fileUrlPublished_{};
    bool ownsPasteboard_{};
    bool operationInProgress_{};
    bool generationChangeRequested_{};
    bool disconnectRequested_{};
    bool closed_{};
};

#if defined(__APPLE__)
// Dormant production AppKit callbacks. A future authorized macOS desktop
// aggregate may construct the adapter with this seam; the factory itself does
// not read or write pasteboard contents and grants no R2/R3 authority.
[[nodiscard]] MacClipboardNativeOperations
makeMacClipboardNativeOperations() noexcept;
#endif

} // namespace rdp::macos
