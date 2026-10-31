// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_clipboard_file_destination.h"

#include <algorithm>
#include <limits>

#if defined(__APPLE__)
#include <cerrno>
#include <climits>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace rdp::macos
{
namespace
{

[[nodiscard]] bool isHexDigit(const char character) noexcept
{
    return (character >= '0' && character <= '9') ||
           (character >= 'a' && character <= 'f') ||
           (character >= 'A' && character <= 'F');
}

[[nodiscard]] bool validLocalFileUrl(
    const std::string_view url) noexcept
{
    constexpr std::string_view kLocalFilePrefix{"file:///"};
    if (url.empty())
    {
        return true;
    }
    if (url.size() <= kLocalFilePrefix.size() ||
        url.size() >
            MacClipboardFileDestination::kMaximumLocalFileUrlBytes ||
        !url.starts_with(kLocalFilePrefix))
    {
        return false;
    }

    for (std::size_t index = kLocalFilePrefix.size();
         index < url.size(); ++index)
    {
        const unsigned char byte =
            static_cast<unsigned char>(url[index]);
        if (byte <= 0x20U || byte >= 0x7fU ||
            url[index] == '\\' || url[index] == '?' ||
            url[index] == '#')
        {
            return false;
        }
        if (url[index] == '%')
        {
            if (index + 2U >= url.size() ||
                !isHexDigit(url[index + 1U]) ||
                !isHexDigit(url[index + 2U]))
            {
                return false;
            }
            index += 2U;
        }
    }
    return true;
}

} // namespace

MacClipboardFileDestination::MacClipboardFileDestination(
    RemoteTransfer &remoteTransfer,
    MacClipboardFileNativeOperations nativeOperations) noexcept
    : remoteTransfer_(remoteTransfer),
      nativeOperations_(nativeOperations),
      closed_(!nativeOperationsValid())
{
}

MacClipboardFileDestination::~MacClipboardFileDestination() noexcept
{
    if (active())
    {
        discardPartial(Status::Cancelled);
    }
    else
    {
        closeDestination();
    }
    closed_ = true;
}

bool MacClipboardFileDestination::nativeOperationsValid() const noexcept
{
    return nativeOperations_.duplicateWritableRegularFile != nullptr &&
           nativeOperations_.resizeFile != nullptr &&
           nativeOperations_.writeFileAt != nullptr &&
           nativeOperations_.flushFile != nullptr &&
           nativeOperations_.closeFile != nullptr;
}

bool MacClipboardFileDestination::valid() const noexcept
{
    return !closed_;
}

bool MacClipboardFileDestination::active() const noexcept
{
    return !closed_ &&
           (status_ == Status::NeedSizeRequest ||
            status_ == Status::NeedRangeRequest ||
            status_ == Status::RequestInFlight);
}

void MacClipboardFileDestination::closeDestination() noexcept
{
    if (destinationDescriptor_ == kInvalidMacClipboardFileDescriptor)
    {
        return;
    }
    // Detach the owned duplicate before calling out. A synchronous native
    // close callback may revoke the source and re-enter destination cleanup.
    const MacClipboardFileDescriptorToken ownedToken = destinationDescriptor_;
    destinationDescriptor_ = kInvalidMacClipboardFileDescriptor;
    nativeOperations_.closeFile(
        nativeOperations_.context, ownedToken);
}

void MacClipboardFileDestination::discardPartial(
    const Status terminalStatus) noexcept
{
    // Terminal state precedes native callbacks so their synchronous
    // generation notifications cannot recursively truncate/close this owner.
    status_ = terminalStatus;
    bool discarded = true;
    if (destinationDescriptor_ != kInvalidMacClipboardFileDescriptor)
    {
        discarded = nativeOperations_.resizeFile(
            nativeOperations_.context, destinationDescriptor_, 0U);
        closeDestination();
    }
    activeRequest_ = {};
    localFileUrl_.fill(0);
    localFileUrlLength_ = 0;
    status_ = discarded ? terminalStatus : Status::NativeError;
}

bool MacClipboardFileDestination::ensureSourceCurrent() noexcept
{
    if (!active())
    {
        return false;
    }
    if (!remoteTransfer_.synchronized())
    {
        discardPartial(Status::ProtocolError);
        return false;
    }
    if (remoteTransfer_.generation() != sourceGeneration_ ||
        remoteTransfer_.sourceEpoch() != sourceEpoch_)
    {
        discardPartial(Status::SourceReplaced);
        return false;
    }
    return true;
}

bool MacClipboardFileDestination::finishComplete() noexcept
{
    if (destinationDescriptor_ == kInvalidMacClipboardFileDescriptor ||
        !expectedSizeKnown_ || bytesWritten_ != expectedSize_)
    {
        discardPartial(Status::ProtocolError);
        return false;
    }
    if (!ensureSourceCurrent())
    {
        return false;
    }

    // Resize, flush and close are distinct synchronous callback boundaries.
    // A successful write check is not terminal publication authority.
    const bool resized = nativeOperations_.resizeFile(
        nativeOperations_.context, destinationDescriptor_, expectedSize_);
    if (!ensureSourceCurrent())
    {
        return false;
    }
    if (!resized)
    {
        discardPartial(Status::NativeError);
        return false;
    }

    const bool flushed = nativeOperations_.flushFile(
        nativeOperations_.context, destinationDescriptor_);
    if (!ensureSourceCurrent())
    {
        return false;
    }
    if (!flushed)
    {
        discardPartial(Status::NativeError);
        return false;
    }

    closeDestination();
    // A reentrant close notification cannot make a retired generation
    // Complete. The duplicate is already closed; no local path is published.
    if (!ensureSourceCurrent())
    {
        return false;
    }
    activeRequest_ = {};
    status_ = Status::Complete;
    return true;
}

bool MacClipboardFileDestination::begin(
    const std::size_t fileIndex,
    const MacClipboardFileDescriptorToken destinationDescriptor) noexcept
{
    return beginInternal(fileIndex, destinationDescriptor, {});
}

bool MacClipboardFileDestination::begin(
    const std::size_t fileIndex,
    const MacClipboardFileDescriptorToken destinationDescriptor,
    const std::string_view localFileUrl) noexcept
{
    if (localFileUrl.empty())
    {
        return false;
    }
    return beginInternal(
        fileIndex, destinationDescriptor, localFileUrl);
}

std::optional<std::string_view>
MacClipboardFileDestination::completedFileUrl() const noexcept
{
    if (status_ != Status::Complete || localFileUrlLength_ == 0 ||
        !remoteTransfer_.synchronized() ||
        remoteTransfer_.generation() != sourceGeneration_ ||
        remoteTransfer_.sourceEpoch() != sourceEpoch_)
    {
        return std::nullopt;
    }
    return std::string_view{
        localFileUrl_.data(), localFileUrlLength_};
}

bool MacClipboardFileDestination::beginInternal(
    const std::size_t fileIndex,
    const MacClipboardFileDescriptorToken destinationDescriptor,
    const std::string_view localFileUrl) noexcept
{
    if (closed_ || status_ != Status::Idle ||
        destinationDescriptor < 0 ||
        !validLocalFileUrl(localFileUrl) ||
        !remoteTransfer_.synchronized() ||
        !remoteTransfer_.fileStreamingAvailable())
    {
        return false;
    }

    const auto file = remoteTransfer_.remoteFile(fileIndex);
    if (!file || file->directory || file->name.empty() ||
        file->name.size() >= sourceName_.size())
    {
        return false;
    }

    MacClipboardFileDescriptorToken duplicate{
        kInvalidMacClipboardFileDescriptor};
    if (!nativeOperations_.duplicateWritableRegularFile(
            nativeOperations_.context,
            destinationDescriptor, duplicate) ||
        duplicate < 0)
    {
        status_ = Status::NativeError;
        return false;
    }

    destinationDescriptor_ = duplicate;
    if (!nativeOperations_.resizeFile(
            nativeOperations_.context,
            destinationDescriptor_, 0U))
    {
        discardPartial(Status::NativeError);
        return false;
    }

    std::copy(
        file->name.begin(), file->name.end(),
        sourceName_.begin());
    sourceNameLength_ = file->name.size();
    localFileUrl_.fill(0);
    localFileUrlLength_ = localFileUrl.size();
    std::copy(
        localFileUrl.begin(), localFileUrl.end(),
        localFileUrl_.begin());
    sourceGeneration_ = remoteTransfer_.generation();
    sourceEpoch_ = remoteTransfer_.sourceEpoch();
    fileIndex_ = fileIndex;
    expectedSizeKnown_ = file->sizeKnown;
    expectedSize_ = file->sizeKnown ? file->size : 0U;
    bytesWritten_ = 0U;
    activeRequest_ = {};

    if (!expectedSizeKnown_)
    {
        status_ = Status::NeedSizeRequest;
        return true;
    }
    if (expectedSize_ == 0U)
    {
        status_ = Status::NeedRangeRequest;
        return finishComplete();
    }
    status_ = Status::NeedRangeRequest;
    return true;
}

std::optional<MacClipboardFileDestination::RequestIntent>
MacClipboardFileDestination::nextRequestIntent() noexcept
{
    if (status_ != Status::NeedSizeRequest &&
        status_ != Status::NeedRangeRequest)
    {
        return std::nullopt;
    }
    if (!ensureSourceCurrent())
    {
        return std::nullopt;
    }

    if (status_ == Status::NeedSizeRequest)
    {
        return RequestIntent{
            RemoteTransfer::FileContentsKind::Size,
            sourceGeneration_,
            fileIndex_,
            0U,
            8U,
        };
    }

    if (!expectedSizeKnown_ || bytesWritten_ >= expectedSize_)
    {
        discardPartial(Status::ProtocolError);
        return std::nullopt;
    }

    const std::uint64_t remaining = expectedSize_ - bytesWritten_;
    const std::size_t requestedBytes =
        static_cast<std::size_t>(std::min<std::uint64_t>(
            remaining,
            RemoteTransfer::kMaximumFileContentsChunkBytes));
    return RequestIntent{
        RemoteTransfer::FileContentsKind::Range,
        sourceGeneration_,
        fileIndex_,
        bytesWritten_,
        requestedBytes,
    };
}

bool MacClipboardFileDestination::bindRequest(
    const RemoteTransfer::FileContentsRequestReceipt &receipt) noexcept
{
    const auto intent = nextRequestIntent();
    if (!intent)
    {
        return false;
    }

    if (receipt.sequence == 0U || receipt.streamId == 0U ||
        receipt.clipDataId != 0U ||
        receipt.kind != intent->kind ||
        receipt.generation != intent->generation ||
        receipt.fileIndex != intent->fileIndex ||
        receipt.offset != intent->offset ||
        receipt.requestedBytes != intent->requestedBytes)
    {
        discardPartial(Status::ProtocolError);
        return false;
    }

    activeRequest_ = receipt;
    status_ = Status::RequestInFlight;
    return true;
}

bool MacClipboardFileDestination::acceptResult(
    const RemoteTransfer::FileContentsResult &result) noexcept
{
    if (status_ != Status::RequestInFlight)
    {
        return false;
    }

    if (result.sequence != activeRequest_.sequence ||
        result.generation != activeRequest_.generation ||
        result.streamId != activeRequest_.streamId ||
        result.clipDataId != 0U ||
        result.fileIndex != activeRequest_.fileIndex ||
        result.offset != activeRequest_.offset)
    {
        discardPartial(Status::ProtocolError);
        return false;
    }

    switch (result.status)
    {
    case RemoteTransfer::FileContentsStatus::RemoteFailure:
        discardPartial(Status::RemoteFailure);
        return false;
    case RemoteTransfer::FileContentsStatus::DiscardedPreviousGeneration:
        discardPartial(Status::SourceReplaced);
        return false;
    case RemoteTransfer::FileContentsStatus::Invalid:
    case RemoteTransfer::FileContentsStatus::ProtocolError:
        discardPartial(Status::ProtocolError);
        return false;
    case RemoteTransfer::FileContentsStatus::ReceivedSize:
        if (activeRequest_.kind !=
                RemoteTransfer::FileContentsKind::Size)
        {
            discardPartial(Status::ProtocolError);
            return false;
        }
        if (!ensureSourceCurrent())
        {
            return false;
        }
        expectedSizeKnown_ = true;
        expectedSize_ = result.fileSize;
        activeRequest_ = {};
        if (expectedSize_ == 0U)
        {
            status_ = Status::NeedRangeRequest;
            return finishComplete();
        }
        status_ = Status::NeedRangeRequest;
        return true;
    case RemoteTransfer::FileContentsStatus::ReceivedRange:
        break;
    }

    if (activeRequest_.kind !=
            RemoteTransfer::FileContentsKind::Range ||
        !expectedSizeKnown_ || result.bytes.empty() ||
        bytesWritten_ != activeRequest_.offset ||
        bytesWritten_ > expectedSize_ ||
        result.bytes.size() > activeRequest_.requestedBytes ||
        result.bytes.size() > expectedSize_ - bytesWritten_)
    {
        discardPartial(Status::ProtocolError);
        return false;
    }
    if (!ensureSourceCurrent())
    {
        return false;
    }

    if (!nativeOperations_.writeFileAt(
            nativeOperations_.context,
            destinationDescriptor_, bytesWritten_,
            std::as_bytes(result.bytes)))
    {
        discardPartial(Status::NativeError);
        return false;
    }

    // Native operations are synchronous, but the injected/platform boundary
    // can re-enter source ownership before it returns. Never commit bytes from
    // a clipboard generation that was replaced during the native write.
    if (!ensureSourceCurrent())
    {
        return false;
    }

    bytesWritten_ += result.bytes.size();
    activeRequest_ = {};
    if (bytesWritten_ == expectedSize_)
    {
        status_ = Status::NeedRangeRequest;
        return finishComplete();
    }
    status_ = Status::NeedRangeRequest;
    return true;
}

void MacClipboardFileDestination::onRemoteGenerationChanged() noexcept
{
    if (active())
    {
        (void)ensureSourceCurrent();
    }
}

void MacClipboardFileDestination::cancel() noexcept
{
    if (active())
    {
        discardPartial(Status::Cancelled);
    }
}

#if defined(__APPLE__)
namespace
{

[[nodiscard]] int nativeDescriptor(
    const MacClipboardFileDescriptorToken token) noexcept
{
    if (token < 0 ||
        token > static_cast<MacClipboardFileDescriptorToken>(INT_MAX))
    {
        return -1;
    }
    return static_cast<int>(token);
}

[[nodiscard]] bool macDuplicateWritableRegularFile(
    void *, const MacClipboardFileDescriptorToken sourceToken,
    MacClipboardFileDescriptorToken &duplicateToken) noexcept
{
    duplicateToken = kInvalidMacClipboardFileDescriptor;
    const int source = nativeDescriptor(sourceToken);
    if (source < 0)
    {
        return false;
    }

    struct stat metadata{};
    if (::fstat(source, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode))
    {
        return false;
    }

    const int statusFlags = ::fcntl(source, F_GETFL);
    if (statusFlags < 0 ||
        (statusFlags & O_ACCMODE) == O_RDONLY ||
        (statusFlags & O_APPEND) != 0)
    {
        return false;
    }

    int duplicate = -1;
    do
    {
        duplicate = ::fcntl(source, F_DUPFD_CLOEXEC, 0);
    } while (duplicate < 0 && errno == EINTR);
    if (duplicate < 0)
    {
        return false;
    }

    duplicateToken =
        static_cast<MacClipboardFileDescriptorToken>(duplicate);
    return true;
}

[[nodiscard]] bool macResizeFile(
    void *, const MacClipboardFileDescriptorToken token,
    const std::uint64_t size) noexcept
{
    if (size >
        static_cast<std::uint64_t>(
            std::numeric_limits<off_t>::max()))
    {
        return false;
    }

    const int descriptor = nativeDescriptor(token);
    if (descriptor < 0)
    {
        return false;
    }

    int result = -1;
    do
    {
        result = ::ftruncate(
            descriptor, static_cast<off_t>(size));
    } while (result != 0 && errno == EINTR);
    return result == 0;
}

[[nodiscard]] bool macWriteFileAt(
    void *, const MacClipboardFileDescriptorToken token,
    const std::uint64_t offset,
    const std::span<const std::byte> bytes) noexcept
{
    if (bytes.empty() ||
        offset >
            static_cast<std::uint64_t>(
                std::numeric_limits<off_t>::max()))
    {
        return false;
    }

    const int descriptor = nativeDescriptor(token);
    if (descriptor < 0)
    {
        return false;
    }

    std::size_t acceptedBytes = 0U;
    while (acceptedBytes < bytes.size())
    {
        const std::uint64_t writeOffset =
            offset + acceptedBytes;
        if (writeOffset >
            static_cast<std::uint64_t>(
                std::numeric_limits<off_t>::max()))
        {
            return false;
        }

        ssize_t written = -1;
        do
        {
            written = ::pwrite(
                descriptor,
                bytes.data() + acceptedBytes,
                bytes.size() - acceptedBytes,
                static_cast<off_t>(writeOffset));
        } while (written < 0 && errno == EINTR);
        if (written <= 0)
        {
            return false;
        }

        const auto nativeAccepted =
            static_cast<std::size_t>(written);
        if (nativeAccepted > bytes.size() - acceptedBytes)
        {
            return false;
        }
        acceptedBytes += nativeAccepted;
    }
    return true;
}

[[nodiscard]] bool macFlushFile(
    void *, const MacClipboardFileDescriptorToken token) noexcept
{
    const int descriptor = nativeDescriptor(token);
    if (descriptor < 0)
    {
        return false;
    }
    int result = -1;
    do
    {
        result = ::fsync(descriptor);
    } while (result != 0 && errno == EINTR);
    return result == 0;
}

void macCloseFile(
    void *, const MacClipboardFileDescriptorToken token) noexcept
{
    const int descriptor = nativeDescriptor(token);
    if (descriptor >= 0)
    {
        // POSIX close releases the descriptor even when it reports EINTR on
        // Darwin; never retry and risk closing a newly reused descriptor.
        (void)::close(descriptor);
    }
}

} // namespace

MacClipboardFileNativeOperations
makeMacClipboardFileNativeOperations() noexcept
{
    return {
        nullptr,
        &macDuplicateWritableRegularFile,
        &macResizeFile,
        &macWriteFileAt,
        &macFlushFile,
        &macCloseFile,
    };
}
#endif

} // namespace rdp::macos
