// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include <xcb/xcb.h>

#include "server/clipboard/remote_transfer.h"
#include "x11_event_dispatch.h"

/**
 * Small allocation-free native XCB call table used by the clipboard adapter.
 *
 * Production uses the borrowed R5 connection. Tests inject deterministic
 * operations without opening an X server. The context and every borrowed XCB
 * object must outlive X11ClipboardAdapter; the adapter never owns or closes
 * the connection.
 */
struct X11ClipboardNativeOperations
{
    void *context{};
    xcb_atom_t (*internAtom)(void *, std::string_view) noexcept{};
    xcb_window_t (*createOwnerWindow)(void *, xcb_window_t) noexcept{};
    bool (*destroyWindow)(void *, xcb_window_t) noexcept{};
    bool (*setSelectionOwner)(void *, xcb_window_t, xcb_atom_t) noexcept{};
    xcb_window_t (*selectionOwner)(void *, xcb_atom_t) noexcept{};
    bool (*changeProperty)(void *, xcb_window_t, xcb_atom_t, xcb_atom_t,
                           std::uint8_t,
                           std::span<const std::byte>) noexcept{};
    bool (*selectTransferEvents)(void *, xcb_window_t,
                                 std::uint32_t &) noexcept{};
    bool (*restoreEventMask)(void *, xcb_window_t, std::uint32_t) noexcept{};
    bool (*deleteProperty)(void *, xcb_window_t, xcb_atom_t) noexcept{};
    bool (*sendSelectionNotify)(
        void *, const xcb_selection_notify_event_t &) noexcept{};
};

/**
 * Publish one RemoteTransfer generation through the X11 CLIPBOARD selection.
 *
 * This object owns only native X11 selection state. RemoteTransfer remains the
 * sole clipboard generation, response and pending-paste owner. The adapter
 * borrows R5's single XCB connection and is event-loop confined: construct,
 * publish, handle, service and disconnect it on the same serialized XCB/R8
 * owner thread. Disconnect this adapter before the borrowed R5 owner.
 */
class X11ClipboardAdapter final : public X11EventSink
{
public:
    using RemoteTransfer = rdp_server::server::clipboard::RemoteTransfer;
    using PasteClock = RemoteTransfer::PasteClock;

    // Keep direct and incremental property writes below a conservative
    // single-request ceiling. INCR never duplicates the full payload.
    static constexpr std::size_t kMaximumDirectPropertyBytes = 64U * 1024U;
    static constexpr std::size_t kIncrChunkBytes = 64U * 1024U;
    static constexpr auto kPasteTimeout = std::chrono::seconds{2};
    static constexpr auto kIncrTimeout = std::chrono::seconds{5};

    enum class Source : std::uint8_t
    {
        None,
        RemoteRdp,
        LocalNative,
        SelfGeneratedNativeTransition,
    };

    struct RemoteFetchRequest
    {
        std::uint64_t pasteSequence{};
        std::uint64_t generation{};
        std::uint32_t formatId{};
        RemoteTransfer::PasteKind kind{RemoteTransfer::PasteKind::UnicodeText};
    };

    X11ClipboardAdapter(RemoteTransfer &remoteTransfer,
                        xcb_connection_t &connection,
                        xcb_window_t rootWindow) noexcept;
    X11ClipboardAdapter(RemoteTransfer &remoteTransfer,
                        X11ClipboardNativeOperations nativeOperations,
                        xcb_window_t rootWindow) noexcept;
    ~X11ClipboardAdapter() noexcept override;

    X11ClipboardAdapter(const X11ClipboardAdapter &) = delete;
    X11ClipboardAdapter &operator=(const X11ClipboardAdapter &) = delete;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] xcb_window_t ownerWindow() const noexcept;
    [[nodiscard]] xcb_atom_t clipboardAtom() const noexcept;
    [[nodiscard]] xcb_atom_t targetsAtom() const noexcept;
    [[nodiscard]] xcb_atom_t utf8StringAtom() const noexcept;
    [[nodiscard]] xcb_atom_t pngAtom() const noexcept;
    [[nodiscard]] xcb_atom_t incrAtom() const noexcept;
    [[nodiscard]] bool incrTransferActive() const noexcept;
    [[nodiscard]] std::size_t incrBytesSent() const noexcept;
    [[nodiscard]] std::uint64_t publicationGeneration() const noexcept;
    [[nodiscard]] std::uint64_t ownershipEpoch() const noexcept;
    [[nodiscard]] bool ownsClipboard() const noexcept;
    [[nodiscard]] Source contentSource() const noexcept;
    [[nodiscard]] Source lastOwnershipTransitionSource() const noexcept;

    /**
     * Publish the current accepted remote generation if UTF8_STRING and/or
     * registered PNG can be represented. A local takeover suppresses
     * republishing the same generation. PRIMARY is never touched.
     */
    [[nodiscard]] bool publishCurrentRemoteOffer(
        PasteClock::time_point now) noexcept;

    /**
     * Poll the one R8 paste receipt without blocking and complete that exact
     * SelectionRequest once terminal. Borrowed R8 views survive only the
     * synchronous property write call.
     */
    [[nodiscard]] bool servicePendingPaste(
        PasteClock::time_point now) noexcept;

    /**
     * R3 may consume this intent through its authorized single writer. This
     * adapter owns no virtual channel and emits no RDP bytes.
     */
    [[nodiscard]] std::optional<RemoteFetchRequest>
    pendingRemoteFetch() const noexcept;
    [[nodiscard]] bool markRemoteFetchStarted(
        std::uint64_t pasteSequence) noexcept;

    void handle(const xcb_generic_event_t &event) noexcept override;
    void handleAt(const xcb_generic_event_t &event,
                  PasteClock::time_point now) noexcept;

    // An observation naming our owner is a self echo. Any other owner yields.
    void observeClipboardOwner(xcb_window_t owner) noexcept;

    // Idempotent; call before the borrowed R5 XCB owner is disconnected.
    void disconnect() noexcept;

private:
    struct Atoms
    {
        xcb_atom_t clipboard{XCB_ATOM_NONE};
        xcb_atom_t targets{XCB_ATOM_NONE};
        xcb_atom_t utf8String{XCB_ATOM_NONE};
        xcb_atom_t png{XCB_ATOM_NONE};
        xcb_atom_t incr{XCB_ATOM_NONE};
    };

    struct PendingSelectionRequest
    {
        xcb_selection_request_event_t request{};
        xcb_atom_t property{XCB_ATOM_NONE};
        std::uint64_t publicationGeneration{};
        std::uint64_t ownershipEpoch{};
        std::uint64_t pasteSequence{};
        std::uint32_t remoteFormatId{};
        RemoteTransfer::PasteKind kind{RemoteTransfer::PasteKind::UnicodeText};
        bool remoteFetchStarted{};
        bool active{};
    };

    struct IncrTransfer
    {
        xcb_selection_request_event_t request{};
        xcb_atom_t property{XCB_ATOM_NONE};
        xcb_atom_t propertyType{XCB_ATOM_NONE};
        std::span<const std::byte> bytes{};
        std::size_t offset{};
        std::uint32_t previousEventMask{};
        PasteClock::time_point deadline{};
        std::uint64_t publicationGeneration{};
        std::uint64_t ownershipEpoch{};
        bool active{};
    };

    [[nodiscard]] static X11ClipboardNativeOperations
    makeXcbOperations(xcb_connection_t &connection) noexcept;
    [[nodiscard]] bool nativeOperationsValid() const noexcept;
    [[nodiscard]] bool currentPublicationValid() const noexcept;
    [[nodiscard]] bool remoteTextOffered() const noexcept;
    [[nodiscard]] std::uint32_t remotePngFormatId() const noexcept;
    [[nodiscard]] xcb_atom_t requestProperty(
        const xcb_selection_request_event_t &request) const noexcept;

    void handleSelectionRequest(const xcb_selection_request_event_t &request,
                                PasteClock::time_point now) noexcept;
    void handleSelectionClear(const xcb_selection_clear_event_t &clear) noexcept;
    void beginDelayedRequest(const xcb_selection_request_event_t &request,
                             xcb_atom_t property,
                             RemoteTransfer::PasteKind kind,
                             std::uint32_t remoteFormatId,
                             PasteClock::time_point now) noexcept;
    [[nodiscard]] bool publishTargets(
        const xcb_selection_request_event_t &request,
        xcb_atom_t property) noexcept;
    [[nodiscard]] bool publishText(
        const xcb_selection_request_event_t &request,
        xcb_atom_t property, std::string_view text,
        PasteClock::time_point now) noexcept;
    [[nodiscard]] bool publishPng(
        const xcb_selection_request_event_t &request,
        xcb_atom_t property,
        const RemoteTransfer::VerifiedImage &image,
        PasteClock::time_point now) noexcept;
    [[nodiscard]] bool beginIncrTransfer(
        const xcb_selection_request_event_t &request,
        xcb_atom_t property, xcb_atom_t propertyType,
        std::span<const std::byte> bytes,
        PasteClock::time_point now) noexcept;
    [[nodiscard]] bool serviceIncrTransfer(
        PasteClock::time_point now) noexcept;
    void handlePropertyNotify(const xcb_property_notify_event_t &property,
                              PasteClock::time_point now) noexcept;
    void handleDestroyNotify(const xcb_destroy_notify_event_t &destroy) noexcept;
    void cancelIncrTransfer(bool requestorDestroyed) noexcept;
    [[nodiscard]] bool publishPropertyAndNotify(
        const xcb_selection_request_event_t &request,
        xcb_atom_t property, xcb_atom_t propertyType, std::uint8_t format,
        std::span<const std::byte> bytes) noexcept;
    [[nodiscard]] bool sendFailureNotify(
        const xcb_selection_request_event_t &request) noexcept;
    [[nodiscard]] bool sendNotify(
        const xcb_selection_request_event_t &request,
        xcb_atom_t property) noexcept;
    void failPendingSelection() noexcept;
    void cancelPendingForOwnerLoss() noexcept;
    void yieldToLocalOwner() noexcept;
    void releaseNativeOwnership() noexcept;
    void clearPublicationState() noexcept;

    RemoteTransfer &remoteTransfer_;
    X11ClipboardNativeOperations nativeOperations_{};
    xcb_window_t rootWindow_{XCB_WINDOW_NONE};
    xcb_window_t ownerWindow_{XCB_WINDOW_NONE};
    Atoms atoms_{};
    PendingSelectionRequest pending_{};
    IncrTransfer incr_{};
    std::uint64_t publicationGeneration_{};
    std::uint64_t ownershipEpoch_{};
    std::uint64_t yieldedGeneration_{};
    bool textOffered_{};
    bool pngOffered_{};
    bool ownsClipboard_{};
    bool valid_{};
    Source contentSource_{Source::None};
    Source lastOwnershipTransitionSource_{Source::None};
};
