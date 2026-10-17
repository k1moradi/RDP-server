// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/clipboard/remote_transfer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace rdp::macos
{

using MacClipboardFileDescriptorToken = std::int64_t;
inline constexpr MacClipboardFileDescriptorToken
    kInvalidMacClipboardFileDescriptor = -1;

// Native file-operation seam for one caller-selected macOS destination.
// Production uses POSIX file descriptors; ordinary cross-platform tests inject
// deterministic operations and never touch a user file.
struct MacClipboardFileNativeOperations final
{
    void *context{};
    bool (*duplicateWritableRegularFile)(
        void *, MacClipboardFileDescriptorToken,
        MacClipboardFileDescriptorToken &) noexcept{};
    bool (*resizeFile)(
        void *, MacClipboardFileDescriptorToken,
        std::uint64_t) noexcept{};
    bool (*writeFileAt)(
        void *, MacClipboardFileDescriptorToken,
        std::uint64_t, std::span<const std::byte>) noexcept{};
    bool (*flushFile)(
        void *, MacClipboardFileDescriptorToken) noexcept{};
    void (*closeFile)(
        void *, MacClipboardFileDescriptorToken) noexcept{};
};

// One bounded macOS native destination for a single RemoteTransfer file.
//
// RemoteTransfer remains the sole clipboard generation/FileContents owner.
// This class owns only a duplicate of the caller-selected local descriptor
// and sequential local materialization progress. It exposes request intents,
// binds exact RemoteTransfer receipts, and never serializes/sends CLIPRDR.
//
// Thread-safety: event-loop/thread confined. The caller's original descriptor
// remains caller-owned. Remote FILEDESCRIPTORW names are metadata only and are
// never resolved into local filesystem paths.
class MacClipboardFileDestination final
{
public:
    using RemoteTransfer =
        rdp_server::server::clipboard::RemoteTransfer;

    // Caller-selected local file URL metadata for completed Finder/pasteboard
    // handoff. Non-ASCII path bytes must be percent-encoded by the caller.
    static constexpr std::size_t kMaximumLocalFileUrlBytes = 4096U;

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

    MacClipboardFileDestination(
        RemoteTransfer &remoteTransfer,
        MacClipboardFileNativeOperations nativeOperations) noexcept;
    ~MacClipboardFileDestination() noexcept;

    MacClipboardFileDestination(
        const MacClipboardFileDestination &) = delete;
    MacClipboardFileDestination &operator=(
        const MacClipboardFileDestination &) = delete;
    MacClipboardFileDestination(
        MacClipboardFileDestination &&) = delete;
    MacClipboardFileDestination &operator=(
        MacClipboardFileDestination &&) = delete;

    [[nodiscard]] bool valid() const noexcept;

    // Begin one current-generation, non-directory file materialization.
    // The token identifies a caller-selected writable destination descriptor;
    // the remote leaf name never becomes a path.
    [[nodiscard]] bool begin(
        std::size_t fileIndex,
        MacClipboardFileDescriptorToken destinationDescriptor) noexcept;

    // Optional handoff-aware overload. localFileUrl is caller-selected local
    // metadata bound to this exact destination capability; it is never
    // constructed from the remote FILEDESCRIPTORW name. Only strict file:///
    // URLs are retained.
    [[nodiscard]] bool begin(
        std::size_t fileIndex,
        MacClipboardFileDescriptorToken destinationDescriptor,
        std::string_view localFileUrl) noexcept;

    // Available only after exact-size completion, flush and duplicate close.
    // The returned view borrows this destination object.
    [[nodiscard]] std::optional<std::string_view>
    completedFileUrl() const noexcept;

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
        MacClipboardFileDescriptorToken destinationDescriptor,
        std::string_view localFileUrl) noexcept;
    [[nodiscard]] bool nativeOperationsValid() const noexcept;
    [[nodiscard]] bool ensureSourceCurrent() noexcept;
    [[nodiscard]] bool finishComplete() noexcept;
    void discardPartial(Status terminalStatus) noexcept;
    void closeDestination() noexcept;

    RemoteTransfer &remoteTransfer_;
    MacClipboardFileNativeOperations nativeOperations_{};
    std::array<char16_t, 260> sourceName_{};
    std::array<char, kMaximumLocalFileUrlBytes> localFileUrl_{};
    std::size_t sourceNameLength_{};
    std::size_t localFileUrlLength_{};
    RemoteTransfer::FileContentsRequestReceipt activeRequest_{};
    std::uint64_t sourceGeneration_{};
    std::uint64_t sourceEpoch_{};
    std::uint64_t expectedSize_{};
    std::uint64_t bytesWritten_{};
    std::size_t fileIndex_{};
    MacClipboardFileDescriptorToken destinationDescriptor_{
        kInvalidMacClipboardFileDescriptor};
    Status status_{Status::Idle};
    bool expectedSizeKnown_{};
    bool closed_{};
};

#if defined(__APPLE__)
// Production POSIX operations. The factory opens no path and performs no I/O;
// begin() acts only on the caller-selected descriptor token.
[[nodiscard]] MacClipboardFileNativeOperations
makeMacClipboardFileNativeOperations() noexcept;
#endif

} // namespace rdp::macos
