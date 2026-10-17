// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "server/clipboard/remote_transfer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace rdp::linux_platform
{

// One bounded native file destination for a single RemoteTransfer file.
//
// This object owns only a duplicated local destination descriptor and
// sequential materialization progress. RemoteTransfer remains the sole
// clipboard generation, descriptor, streamId and response owner. The caller
// must obtain/authorize each FileContents request through the existing R3/R8
// route, then bind that exact receipt before delivering its parsed result here.
//
// All methods are single-thread-affine. The borrowed descriptor passed to
// begin() remains caller-owned; this class duplicates it with CLOEXEC and owns
// only the duplicate. Do not publish or hand the destination to a consumer
// until status() is Complete.
class LinuxClipboardFileDestination final
{
public:
    using RemoteTransfer =
        rdp_server::server::clipboard::RemoteTransfer;

    // Bound caller-supplied local file URIs used by native clipboard handoff.
    // Non-ASCII path bytes must be percent-encoded by the caller.
    static constexpr std::size_t kMaximumLocalFileUriBytes = 4096U;

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

    explicit LinuxClipboardFileDestination(
        RemoteTransfer &remoteTransfer) noexcept;
    ~LinuxClipboardFileDestination() noexcept;

    LinuxClipboardFileDestination(
        const LinuxClipboardFileDestination &) = delete;
    LinuxClipboardFileDestination &operator=(
        const LinuxClipboardFileDestination &) = delete;
    LinuxClipboardFileDestination(
        LinuxClipboardFileDestination &&) = delete;
    LinuxClipboardFileDestination &operator=(
        LinuxClipboardFileDestination &&) = delete;

    // Start one current-generation regular-file copy into a caller-selected
    // writable regular file. O_APPEND and read-only descriptors are rejected
    // because they cannot preserve protocol offsets. Remote leaf names are
    // copied only as metadata and are never resolved as local paths.
    [[nodiscard]] bool begin(
        std::size_t fileIndex, int destinationDescriptor) noexcept;

    // Optional handoff-aware overload. The URI is caller-selected local
    // metadata bound to this exact destination capability; it is never
    // constructed from the remote FILEDESCRIPTORW name. Only strict local
    // file:/// URIs are retained.
    [[nodiscard]] bool begin(
        std::size_t fileIndex, int destinationDescriptor,
        std::string_view localFileUri) noexcept;

    // Available only after exact-size completion and fsync/duplicate close.
    // The returned view borrows this destination object.
    [[nodiscard]] std::optional<std::string_view>
    completedFileUri() const noexcept;

    // Return the exact next R8 request shape. This never serializes or sends
    // protocol bytes and never reserves a RemoteTransfer request slot.
    [[nodiscard]] std::optional<RequestIntent>
    nextRequestIntent() noexcept;

    // Bind only the exact RemoteTransfer receipt created for the preceding
    // intent. Joined R3 receipts pass their nested .request here.
    [[nodiscard]] bool bindRequest(
        const RemoteTransfer::FileContentsRequestReceipt &receipt) noexcept;

    // Synchronously consume one already-parsed RemoteTransfer result. RANGE
    // bytes are borrowed only through this call and are written directly to
    // the duplicated descriptor before return.
    [[nodiscard]] bool acceptResult(
        const RemoteTransfer::FileContentsResult &result) noexcept;

    // Call after a new clipboard offer is accepted. An unlocked destination
    // cannot continue across generations; partial native bytes are truncated.
    void onRemoteGenerationChanged() noexcept;

    // Best-effort local cancellation. This does NOT cancel or reassign an RDP
    // request already owned by RemoteTransfer; that response must still be
    // cancelled before submission or drained by the authoritative owner.
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
    [[nodiscard]] std::uint64_t activeRequestSequence() const noexcept
    {
        return status_ == Status::RequestInFlight ?
            activeRequest_.sequence : 0U;
    }

private:
    [[nodiscard]] bool beginInternal(
        std::size_t fileIndex, int destinationDescriptor,
        std::string_view localFileUri) noexcept;
    [[nodiscard]] bool ensureSourceCurrent() noexcept;
    [[nodiscard]] bool finishComplete() noexcept;
    void discardPartial(Status terminalStatus) noexcept;
    void closeDestination() noexcept;

    RemoteTransfer &remoteTransfer_;
    std::array<char16_t, 260> sourceName_{};
    std::array<char, kMaximumLocalFileUriBytes> localFileUri_{};
    std::size_t sourceNameLength_{};
    std::size_t localFileUriLength_{};
    RemoteTransfer::FileContentsRequestReceipt activeRequest_{};
    std::uint64_t sourceGeneration_{};
    std::uint64_t sourceEpoch_{};
    std::uint64_t expectedSize_{};
    std::uint64_t bytesWritten_{};
    std::size_t fileIndex_{};
    int destinationDescriptor_{-1};
    Status status_{Status::Idle};
    bool expectedSizeKnown_{};
};

} // namespace rdp::linux_platform
