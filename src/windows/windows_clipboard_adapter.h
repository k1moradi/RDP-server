// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/clipboard/remote_transfer.h"
#include "windows_clipboard_file_destination.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace rdp_server::windows
{

using WindowsClipboardFormat = std::uint32_t;
using WindowsClipboardWindowToken = std::uintptr_t;

// Allocation-free native Win32 call seam. Production callbacks are backed by
// User32/GlobalAlloc on Windows; ordinary tests inject deterministic callbacks
// and never open the host clipboard.
struct WindowsClipboardNativeOperations final
{
    void *context{};
    WindowsClipboardFormat (*registerFormat)(
        void *, std::string_view) noexcept{};
    bool (*openClipboard)(
        void *, WindowsClipboardWindowToken) noexcept{};
    bool (*emptyClipboard)(void *) noexcept{};
    bool (*setDelayedFormat)(
        void *, WindowsClipboardFormat) noexcept{};
    bool (*setFormatBytes)(
        void *, WindowsClipboardFormat, std::span<const std::byte>) noexcept{};
    bool (*closeClipboard)(void *) noexcept{};
    WindowsClipboardWindowToken (*clipboardOwner)(void *) noexcept{};
};

// Native Windows clipboard presentation for one RemoteTransfer owner.
//
// RemoteTransfer remains the sole CLIPRDR generation/data owner. This adapter
// owns only native publication state and is event-loop/thread confined. It
// never performs virtual-channel I/O, waits for RDP data, or grants session
// authorization. Only already-verified current-generation bytes are announced
// to Win32, so WM_RENDERFORMAT can complete synchronously without network I/O.
class WindowsClipboardAdapter final
{
public:
    using RemoteTransfer =
        rdp_server::server::clipboard::RemoteTransfer;

    static constexpr WindowsClipboardFormat kUnicodeTextFormat = 13U;
    static constexpr WindowsClipboardFormat kFileDropFormat = 15U;
    static constexpr WindowsClipboardFormat kDibFormat = 8U;
    static constexpr WindowsClipboardFormat kDibV5Format = 17U;
    static constexpr std::size_t kMaximumNativeTextBytes =
        2U * 1024U * 1024U + 2U;

    WindowsClipboardAdapter(
        RemoteTransfer &remoteTransfer,
        WindowsClipboardNativeOperations nativeOperations,
        WindowsClipboardWindowToken ownerWindow) noexcept;
    ~WindowsClipboardAdapter() noexcept;

    WindowsClipboardAdapter(const WindowsClipboardAdapter &) = delete;
    WindowsClipboardAdapter &operator=(const WindowsClipboardAdapter &) = delete;
    WindowsClipboardAdapter(WindowsClipboardAdapter &&) = delete;
    WindowsClipboardAdapter &operator=(WindowsClipboardAdapter &&) = delete;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] bool ownsClipboard() const noexcept;
    [[nodiscard]] std::uint64_t publicationGeneration() const noexcept;
    [[nodiscard]] WindowsClipboardFormat pngFormat() const noexcept;

    // Publish delayed-rendering entries only for content already verified by
    // RemoteTransfer for its current generation. A local takeover suppresses
    // reclaiming that same generation; a later RDP generation may publish.
    [[nodiscard]] bool publishReadyRemoteGeneration() noexcept;

    // Publish one completed caller-selected local path as CF_HDROP. The
    // destination path is local capability metadata, never a remote name.
    [[nodiscard]] bool publishCompletedFileDestination(
        const WindowsClipboardFileDestination &destination) noexcept;

    // WM_RENDERFORMAT boundary. The caller MUST NOT open the clipboard first;
    // this method only copies already-ready bytes into the requested format.
    [[nodiscard]] bool renderFormat(
        WindowsClipboardFormat format) noexcept;

    // WM_RENDERALLFORMATS boundary. This method opens the clipboard itself,
    // verifies that ownerWindow still owns it, renders every delayed format,
    // then closes it. No RDP request or wait is started.
    [[nodiscard]] bool renderAllBeforeOwnerDestroy() noexcept;

    // Call from WM_DESTROYCLIPBOARD. A takeover by another application yields
    // the current remote generation instead of timer-driven reclaiming.
    void onDestroyClipboard() noexcept;

    // Idempotent; clears our delayed native publication when still owner.
    // Disconnect this adapter before destroying its owner window.
    void disconnect() noexcept;

private:
    [[nodiscard]] bool nativeOperationsValid() const noexcept;
    [[nodiscard]] bool currentPublicationValid() const noexcept;
    [[nodiscard]] WindowsClipboardFormat publishedImageNativeFormat() const noexcept;
    [[nodiscard]] bool renderFormatInternal(
        WindowsClipboardFormat format) noexcept;
    [[nodiscard]] bool encodeNativeUnicodeText(
        std::string_view text, std::vector<std::uint8_t> &bytes) const noexcept;
    [[nodiscard]] bool encodeFileDrop(
        std::u16string_view absolutePath,
        std::vector<std::uint8_t> &bytes) const noexcept;
    void clearPublicationState() noexcept;
    void finishDeferredDisconnect() noexcept;

    RemoteTransfer &remoteTransfer_;
    WindowsClipboardNativeOperations nativeOperations_{};
    WindowsClipboardWindowToken ownerWindow_{};
    WindowsClipboardFormat pngFormat_{};
    std::uint64_t publicationGeneration_{};
    std::uint64_t yieldedGeneration_{};
    RemoteTransfer::VerifiedImageFormat publishedImageFormat_{
        RemoteTransfer::VerifiedImageFormat::Png};
    bool textPublished_{};
    bool imagePublished_{};
    bool textRendered_{};
    bool imageRendered_{};
    bool fileDropPublished_{};
    bool ownsClipboard_{};
    bool operationInProgress_{};
    bool selfReplacingPublication_{};
    bool disconnectRequested_{};
    bool closed_{};
};

#ifdef _WIN32
// Dormant production Win32 callbacks. A future authorized Windows desktop
// aggregate supplies its HWND token and routes WM_RENDER* / WM_DESTROYCLIPBOARD
// to WindowsClipboardAdapter; this factory itself opens no clipboard.
[[nodiscard]] WindowsClipboardNativeOperations
makeWindowsClipboardNativeOperations() noexcept;
#endif

} // namespace rdp_server::windows
