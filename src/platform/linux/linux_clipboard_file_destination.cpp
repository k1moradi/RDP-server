// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_clipboard_file_destination.h"

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace rdp::linux_platform
{
namespace
{

[[nodiscard]] bool nativeFileSizeRepresentable(
    const std::uint64_t bytes) noexcept
{
    return bytes <= static_cast<std::uint64_t>(
        std::numeric_limits<off_t>::max());
}

[[nodiscard]] int duplicateWritableRegularFile(
    const int descriptor) noexcept
{
    if (descriptor < 0)
    {
        return -1;
    }

    struct stat metadata{};
    if (::fstat(descriptor, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode))
    {
        return -1;
    }

    const int flags = ::fcntl(descriptor, F_GETFL);
    if (flags < 0 ||
        (flags & O_ACCMODE) == O_RDONLY ||
        (flags & O_APPEND) != 0)
    {
        return -1;
    }

    int duplicate = -1;
    do
    {
        duplicate = ::fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
    } while (duplicate < 0 && errno == EINTR);
    return duplicate;
}

[[nodiscard]] bool resizeNativeFile(
    const int descriptor, const std::uint64_t bytes) noexcept
{
    if (descriptor < 0 || !nativeFileSizeRepresentable(bytes))
    {
        return false;
    }

    int result = -1;
    do
    {
        result = ::ftruncate(
            descriptor, static_cast<off_t>(bytes));
    } while (result != 0 && errno == EINTR);
    return result == 0;
}

[[nodiscard]] bool writeNativeFileAt(
    const int descriptor, const std::uint64_t offset,
    const std::span<const std::byte> bytes) noexcept
{
    if (descriptor < 0 || bytes.empty())
    {
        return false;
    }

    const std::uint64_t maximumOffset = static_cast<std::uint64_t>(
        std::numeric_limits<off_t>::max());
    if (offset > maximumOffset ||
        bytes.size() >
            maximumOffset - offset + 1U)
    {
        return false;
    }

    std::size_t writtenBytes = 0;
    while (writtenBytes < bytes.size())
    {
        const std::uint64_t writeOffset =
            offset + writtenBytes;
        ssize_t result = -1;
        do
        {
            result = ::pwrite(
                descriptor,
                bytes.data() + writtenBytes,
                bytes.size() - writtenBytes,
                static_cast<off_t>(writeOffset));
        } while (result < 0 && errno == EINTR);

        if (result <= 0)
        {
            return false;
        }
        const auto accepted =
            static_cast<std::size_t>(result);
        if (accepted > bytes.size() - writtenBytes)
        {
            return false;
        }
        writtenBytes += accepted;
    }
    return true;
}

[[nodiscard]] bool flushNativeFile(const int descriptor) noexcept
{
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

[[nodiscard]] bool isHexDigit(const char character) noexcept
{
    return (character >= '0' && character <= '9') ||
           (character >= 'a' && character <= 'f') ||
           (character >= 'A' && character <= 'F');
}

[[nodiscard]] bool validLocalFileUri(
    const std::string_view uri) noexcept
{
    constexpr std::string_view kLocalFilePrefix{"file:///"};
    if (uri.empty())
    {
        return true;
    }
    if (uri.size() <= kLocalFilePrefix.size() ||
        uri.size() >
            LinuxClipboardFileDestination::kMaximumLocalFileUriBytes ||
        !uri.starts_with(kLocalFilePrefix))
    {
        return false;
    }

    for (std::size_t index = kLocalFilePrefix.size();
         index < uri.size(); ++index)
    {
        const unsigned char byte =
            static_cast<unsigned char>(uri[index]);
        if (byte <= 0x20U || byte >= 0x7fU ||
            uri[index] == '\\' || uri[index] == '?' ||
            uri[index] == '#')
        {
            return false;
        }
        if (uri[index] == '%')
        {
            if (index + 2U >= uri.size() ||
                !isHexDigit(uri[index + 1U]) ||
                !isHexDigit(uri[index + 2U]))
            {
                return false;
            }
            index += 2U;
        }
    }
    return true;
}

} // namespace

LinuxClipboardFileDestination::LinuxClipboardFileDestination(
    RemoteTransfer &remoteTransfer) noexcept
    : remoteTransfer_(remoteTransfer)
{
}

LinuxClipboardFileDestination::~LinuxClipboardFileDestination() noexcept
{
    if (active())
    {
        discardPartial(Status::Cancelled);
    }
    else
    {
        closeDestination();
    }
}

bool LinuxClipboardFileDestination::active() const noexcept
{
    return status_ == Status::NeedSizeRequest ||
           status_ == Status::NeedRangeRequest ||
           status_ == Status::RequestInFlight;
}

void LinuxClipboardFileDestination::closeDestination() noexcept
{
    if (destinationDescriptor_ < 0)
    {
        return;
    }
    // Linux releases the descriptor before reporting a close error; retrying
    // could close an unrelated descriptor if another thread reuses the number.
    (void)::close(destinationDescriptor_);
    destinationDescriptor_ = -1;
}

void LinuxClipboardFileDestination::discardPartial(
    const Status terminalStatus) noexcept
{
    bool discarded = true;
    if (destinationDescriptor_ >= 0)
    {
        discarded = resizeNativeFile(destinationDescriptor_, 0U);
        closeDestination();
    }
    activeRequest_ = {};
    localFileUri_.fill(0);
    localFileUriLength_ = 0;
    status_ = discarded ? terminalStatus : Status::NativeError;
}

bool LinuxClipboardFileDestination::ensureSourceCurrent() noexcept
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

bool LinuxClipboardFileDestination::finishComplete() noexcept
{
    if (destinationDescriptor_ < 0 || !expectedSizeKnown_ ||
        bytesWritten_ != expectedSize_)
    {
        discardPartial(Status::ProtocolError);
        return false;
    }
    if (!resizeNativeFile(destinationDescriptor_, expectedSize_) ||
        !flushNativeFile(destinationDescriptor_))
    {
        discardPartial(Status::NativeError);
        return false;
    }
    closeDestination();
    activeRequest_ = {};
    status_ = Status::Complete;
    return true;
}

bool LinuxClipboardFileDestination::begin(
    const std::size_t fileIndex,
    const int destinationDescriptor) noexcept
{
    return beginInternal(fileIndex, destinationDescriptor, {});
}

bool LinuxClipboardFileDestination::begin(
    const std::size_t fileIndex,
    const int destinationDescriptor,
    const std::string_view localFileUri) noexcept
{
    if (localFileUri.empty())
    {
        return false;
    }
    return beginInternal(
        fileIndex, destinationDescriptor, localFileUri);
}

std::optional<std::string_view>
LinuxClipboardFileDestination::completedFileUri() const noexcept
{
    if (status_ != Status::Complete || localFileUriLength_ == 0 ||
        !remoteTransfer_.synchronized() ||
        remoteTransfer_.generation() != sourceGeneration_ ||
        remoteTransfer_.sourceEpoch() != sourceEpoch_)
    {
        return std::nullopt;
    }
    return std::string_view{
        localFileUri_.data(), localFileUriLength_};
}

bool LinuxClipboardFileDestination::beginInternal(
    const std::size_t fileIndex,
    const int destinationDescriptor,
    const std::string_view localFileUri) noexcept
{
    if (status_ != Status::Idle || destinationDescriptor < 0 ||
        !validLocalFileUri(localFileUri) ||
        !remoteTransfer_.synchronized() ||
        !remoteTransfer_.fileStreamingAvailable())
    {
        return false;
    }

    const auto file = remoteTransfer_.remoteFile(fileIndex);
    if (!file || file->directory ||
        file->name.empty() ||
        file->name.size() >= sourceName_.size())
    {
        return false;
    }
    if (file->sizeKnown &&
        !nativeFileSizeRepresentable(file->size))
    {
        status_ = Status::UnsupportedFileSize;
        return false;
    }

    const int duplicate =
        duplicateWritableRegularFile(destinationDescriptor);
    if (duplicate < 0)
    {
        status_ = Status::NativeError;
        return false;
    }
    destinationDescriptor_ = duplicate;
    if (!resizeNativeFile(destinationDescriptor_, 0U))
    {
        discardPartial(Status::NativeError);
        return false;
    }

    std::copy(
        file->name.begin(), file->name.end(),
        sourceName_.begin());
    sourceNameLength_ = file->name.size();
    localFileUri_.fill(0);
    localFileUriLength_ = localFileUri.size();
    std::copy(
        localFileUri.begin(), localFileUri.end(),
        localFileUri_.begin());
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

std::optional<LinuxClipboardFileDestination::RequestIntent>
LinuxClipboardFileDestination::nextRequestIntent() noexcept
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

    if (!expectedSizeKnown_ ||
        bytesWritten_ >= expectedSize_)
    {
        discardPartial(Status::ProtocolError);
        return std::nullopt;
    }

    const std::uint64_t remaining =
        expectedSize_ - bytesWritten_;
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

bool LinuxClipboardFileDestination::bindRequest(
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

bool LinuxClipboardFileDestination::acceptResult(
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
    case RemoteTransfer::FileContentsStatus::ProtocolError:
    case RemoteTransfer::FileContentsStatus::Invalid:
        discardPartial(Status::ProtocolError);
        return false;
    case RemoteTransfer::FileContentsStatus::ReceivedSize:
        if (activeRequest_.kind !=
                RemoteTransfer::FileContentsKind::Size ||
            !nativeFileSizeRepresentable(result.fileSize))
        {
            discardPartial(
                nativeFileSizeRepresentable(result.fileSize) ?
                    Status::ProtocolError :
                    Status::UnsupportedFileSize);
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
        !expectedSizeKnown_ ||
        result.bytes.empty() ||
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
    if (!writeNativeFileAt(
            destinationDescriptor_,
            bytesWritten_,
            std::as_bytes(result.bytes)))
    {
        discardPartial(Status::NativeError);
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

void LinuxClipboardFileDestination::onRemoteGenerationChanged() noexcept
{
    if (!active())
    {
        return;
    }
    (void)ensureSourceCurrent();
}

void LinuxClipboardFileDestination::cancel() noexcept
{
    if (active())
    {
        discardPartial(Status::Cancelled);
    }
}

} // namespace rdp::linux_platform
