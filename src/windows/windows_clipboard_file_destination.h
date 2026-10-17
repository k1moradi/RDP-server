// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/clipboard/remote_transfer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace rdp_server::windows
{

using WindowsClipboardFileHandleToken = std::uintptr_t;

// Native file-operation seam for one caller-selected Windows destination.
// Production uses Win32 file handles; ordinary cross-platform tests inject
// deterministic operations and never touch a user file.
struct WindowsClipboardFileNativeOperations final
{
    void *context{};
    bool (*duplicateWritableRegularFile)(
        void *, WindowsClipboardFileHandleToken,
        WindowsClipboardFileHandleToken &) noexcept{};
    bool (*resizeFile)(
        void *, WindowsClipboardFileHandleToken,
        std::uint64_t) noexcept{};
    bool (*writeFileAt)(
        void *, WindowsClipboardFileHandleToken,
        std::uint64_t, std::span<const std::byte>) noexcept{};
    bool (*flushFile)(
        void *, WindowsClipboardFileHandleToken) noexcept{};
    void (*closeFile)(
        void *, WindowsClipboardFileHandleToken) noexcept{};
};

// One bounded Windows native destination for a single RemoteTransfer file.
//
// RemoteTransfer remains the sole clipboard generation/FileContents owner.
// This class owns only a duplicate of the caller-selected native file handle
// and sequential local materialization progress. It exposes request intents,
// binds exact RemoteTransfer receipts, and never serializes/sends CLIPRDR.
//
// Thread-safety: event-loop/thread confined. The caller's original handle
// remains caller-owned but must not be used for file-position-sensitive I/O
// while this destination is active because Win32 DuplicateHandle aliases the
// same underlying file object/file pointer.
class WindowsClipboardFileDestination final
{
public:
    using RemoteTransfer =
        rdp_server::server::clipboard::RemoteTransfer;

    static constexpr std::size_t kMaximumLocalPathCodeUnits = 32767U;

    enum class Status : std::uint8_t
    {
        Idle,
        NeedSizeRequest,
        NeedRangeRequest,
        RequestInFlight,
        Complete,
        Cancelled,
        SourceReplaced,
        RemoteFailure,
        ProtocolError,
        UnsupportedFileSize,
        NativeError,
    };

    struct RequestIntent final
    {
        RemoteTransfer::FileContentsKind kind{
            RemoteTransfer::FileContentsKind::Size};
        std::uint64_t generation{};
        std::size_t fileIndex{};
        std::uint64_t offset{};
        std::size_t requestedBytes{};
    };

    WindowsClipboardFileDestination(
        RemoteTransfer &remoteTransfer,
        WindowsClipboardFileNativeOperations nativeOperations) noexcept;
    ~WindowsClipboardFileDestination() noexcept;

    WindowsClipboardFileDestination(
        const WindowsClipboardFileDestination &) = delete;
    WindowsClipboardFileDestination &operator=(
        const WindowsClipboardFileDestination &) = delete;
    WindowsClipboardFileDestination(
        WindowsClipboardFileDestination &&) = delete;
    WindowsClipboardFileDestination &operator=(
        WindowsClipboardFileDestination &&) = delete;

    [[nodiscard]] bool valid() const noexcept;

    // Begin one current-generation, non-directory file materialization.
    // The token identifies a caller-selected writable destination; the remote
    // FILEDESCRIPTORW leaf name is metadata only and never becomes a path.
    [[nodiscard]] bool begin(
        std::size_t fileIndex,
        WindowsClipboardFileHandleToken destinationHandle) noexcept;
    [[nodiscard]] bool begin(
        std::size_t fileIndex,
        WindowsClipboardFileHandleToken destinationHandle,
        std::u16string_view localAbsolutePath) noexcept;
    [[nodiscard]] std::optional<std::u16string_view>
    completedFilePath() const noexcept;

    [[nodiscard]] std::optional<RequestIntent>
    nextRequestIntent() noexcept;

    // Joined R3 FileContents receipts pass their nested .request here.
    [[nodiscard]] bool bindRequest(
        const RemoteTransfer::FileContentsRequestReceipt &receipt) noexcept;

    // Consume an already-parsed result synchronously. ReceivedRange bytes are
    // borrowed from the caller-owned complete PDU only for this call.
    [[nodiscard]] bool acceptResult(
        const RemoteTransfer::FileContentsResult &result) noexcept;

    void onRemoteGenerationChanged() noexcept;
    void cancel() noexcept;

    [[nodiscard]] Status status() const noexcept { return status_; }
    [[nodiscard]] bool active() const noexcept;
    [[nodiscard]] std::uint64_t generation() const noexcept
    {
        return sourceGeneration_;
    }
    [[nodiscard]] std::size_t fileIndex() const noexcept
    {
        return fileIndex_;
    }
    [[nodiscard]] std::span<const char16_t> sourceName() const noexcept
    {
        return {sourceName_.data(), sourceNameLength_};
    }
    [[nodiscard]] bool expectedSizeKnown() const noexcept
    {
        return expectedSizeKnown_;
    }
    [[nodiscard]] std::uint64_t expectedSize() const noexcept
    {
        return expectedSizeKnown_ ? expectedSize_ : 0U;
    }
    [[nodiscard]] std::uint64_t bytesWritten() const noexcept
    {
        return bytesWritten_;
    }

private:
    [[nodiscard]] bool beginInternal(
        std::size_t fileIndex,
        WindowsClipboardFileHandleToken destinationHandle,
        std::u16string_view localAbsolutePath) noexcept;
    [[nodiscard]] bool nativeOperationsValid() const noexcept;
    [[nodiscard]] bool ensureSourceCurrent() noexcept;
    [[nodiscard]] bool finishComplete() noexcept;
    void discardPartial(Status terminalStatus) noexcept;
    void closeDestination() noexcept;

    RemoteTransfer &remoteTransfer_;
    WindowsClipboardFileNativeOperations nativeOperations_{};
    std::array<char16_t, 260> sourceName_{};
    std::u16string localAbsolutePath_{};
    std::size_t sourceNameLength_{};
    RemoteTransfer::FileContentsRequestReceipt activeRequest_{};
    std::uint64_t sourceGeneration_{};
    std::uint64_t sourceEpoch_{};
    std::uint64_t expectedSize_{};
    std::uint64_t bytesWritten_{};
    std::size_t fileIndex_{};
    WindowsClipboardFileHandleToken destinationHandle_{};
    Status status_{Status::Idle};
    bool expectedSizeKnown_{};
    bool closed_{};
};

#ifdef _WIN32
// Production Win32 operations. The factory opens no path and performs no I/O;
// begin() acts only on the caller-selected HANDLE token.
[[nodiscard]] WindowsClipboardFileNativeOperations
makeWindowsClipboardFileNativeOperations() noexcept;
#endif

} // namespace rdp_server::windows
