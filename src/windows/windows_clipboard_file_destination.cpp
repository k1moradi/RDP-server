// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_clipboard_file_destination.h"

#include <algorithm>
#include <limits>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace rdp_server::windows
{
namespace
{

[[nodiscard]] bool asciiDriveLetter(const char16_t character) noexcept
{
    return (character >= u'A' && character <= u'Z') ||
           (character >= u'a' && character <= u'z');
}

[[nodiscard]] bool validLocalAbsolutePath(
    const std::u16string_view path) noexcept
{
    if (path.empty())
    {
        return true;
    }
    if (path.size() >
        WindowsClipboardFileDestination::kMaximumLocalPathCodeUnits)
    {
        return false;
    }
    for (const char16_t character : path)
    {
        if (character == u'\0' || character == u'\r' ||
            character == u'\n')
        {
            return false;
        }
    }
    if (path.size() >= 3U && asciiDriveLetter(path[0]) &&
        path[1] == u':' && path[2] == u'\\')
    {
        return true;
    }
    if (path.size() < 5U || path[0] != u'\\' || path[1] != u'\\' ||
        path[2] == u'?' || path[2] == u'.')
    {
        return false;
    }
    const std::size_t serverEnd = path.find(u'\\', 2U);
    if (serverEnd == std::u16string_view::npos || serverEnd == 2U ||
        serverEnd + 1U >= path.size())
    {
        return false;
    }
    const std::size_t shareEnd = path.find(u'\\', serverEnd + 1U);
    return shareEnd == std::u16string_view::npos ?
               serverEnd + 1U < path.size() :
               shareEnd > serverEnd + 1U;
}

} // namespace

WindowsClipboardFileDestination::WindowsClipboardFileDestination(
    RemoteTransfer &remoteTransfer,
    WindowsClipboardFileNativeOperations nativeOperations) noexcept
    : remoteTransfer_(remoteTransfer),
      nativeOperations_(nativeOperations),
      closed_(!nativeOperationsValid())
{
}

WindowsClipboardFileDestination::~WindowsClipboardFileDestination() noexcept
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

bool WindowsClipboardFileDestination::nativeOperationsValid() const noexcept
{
    return nativeOperations_.duplicateWritableRegularFile != nullptr &&
           nativeOperations_.resizeFile != nullptr &&
           nativeOperations_.writeFileAt != nullptr &&
           nativeOperations_.flushFile != nullptr &&
           nativeOperations_.closeFile != nullptr;
}

bool WindowsClipboardFileDestination::valid() const noexcept
{
    return !closed_;
}

bool WindowsClipboardFileDestination::active() const noexcept
{
    return !closed_ &&
           (status_ == Status::NeedSizeRequest ||
            status_ == Status::NeedRangeRequest ||
            status_ == Status::RequestInFlight);
}

void WindowsClipboardFileDestination::closeDestination() noexcept
{
    if (destinationHandle_ == 0U)
    {
        return;
    }
    nativeOperations_.closeFile(
        nativeOperations_.context, destinationHandle_);
    destinationHandle_ = 0U;
}

void WindowsClipboardFileDestination::discardPartial(
    const Status terminalStatus) noexcept
{
    bool discarded = true;
    if (destinationHandle_ != 0U)
    {
        discarded = nativeOperations_.resizeFile(
            nativeOperations_.context, destinationHandle_, 0U);
        closeDestination();
    }
    activeRequest_ = {};
    localAbsolutePath_.clear();
    status_ = discarded ? terminalStatus : Status::NativeError;
}

bool WindowsClipboardFileDestination::ensureSourceCurrent() noexcept
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

bool WindowsClipboardFileDestination::finishComplete() noexcept
{
    if (destinationHandle_ == 0U || !expectedSizeKnown_ ||
        bytesWritten_ != expectedSize_)
    {
        discardPartial(Status::ProtocolError);
        return false;
    }
    if (!nativeOperations_.resizeFile(
            nativeOperations_.context,
            destinationHandle_, expectedSize_) ||
        !nativeOperations_.flushFile(
            nativeOperations_.context, destinationHandle_))
    {
        discardPartial(Status::NativeError);
        return false;
    }

    closeDestination();
    activeRequest_ = {};
    status_ = Status::Complete;
    return true;
}

bool WindowsClipboardFileDestination::begin(
    const std::size_t fileIndex,
    const WindowsClipboardFileHandleToken destinationHandle) noexcept
{
    return beginInternal(fileIndex, destinationHandle, {});
}

bool WindowsClipboardFileDestination::begin(
    const std::size_t fileIndex,
    const WindowsClipboardFileHandleToken destinationHandle,
    const std::u16string_view localAbsolutePath) noexcept
{
    if (localAbsolutePath.empty())
    {
        return false;
    }
    return beginInternal(
        fileIndex, destinationHandle, localAbsolutePath);
}

std::optional<std::u16string_view>
WindowsClipboardFileDestination::completedFilePath() const noexcept
{
    if (status_ != Status::Complete || localAbsolutePath_.empty() ||
        !remoteTransfer_.synchronized() ||
        remoteTransfer_.generation() != sourceGeneration_ ||
        remoteTransfer_.sourceEpoch() != sourceEpoch_)
    {
        return std::nullopt;
    }
    return std::u16string_view{localAbsolutePath_};
}

bool WindowsClipboardFileDestination::beginInternal(
    const std::size_t fileIndex,
    const WindowsClipboardFileHandleToken destinationHandle,
    const std::u16string_view localAbsolutePath) noexcept
{
    if (closed_ || status_ != Status::Idle ||
        destinationHandle == 0U ||
        !validLocalAbsolutePath(localAbsolutePath) ||
        !remoteTransfer_.synchronized() ||
        !remoteTransfer_.fileStreamingAvailable())
    {
        return false;
    }

    std::u16string pathCopy;
    try
    {
        pathCopy.assign(localAbsolutePath);
    }
    catch (...)
    {
        return false;
    }

    const auto file = remoteTransfer_.remoteFile(fileIndex);
    if (!file || file->directory || file->name.empty() ||
        file->name.size() >= sourceName_.size())
    {
        return false;
    }

    WindowsClipboardFileHandleToken duplicate{};
    if (!nativeOperations_.duplicateWritableRegularFile(
            nativeOperations_.context,
            destinationHandle, duplicate) ||
        duplicate == 0U)
    {
        status_ = Status::NativeError;
        return false;
    }

    destinationHandle_ = duplicate;
    if (!nativeOperations_.resizeFile(
            nativeOperations_.context,
            destinationHandle_, 0U))
    {
        discardPartial(Status::NativeError);
        return false;
    }

    std::copy(
        file->name.begin(), file->name.end(),
        sourceName_.begin());
    sourceNameLength_ = file->name.size();
    localAbsolutePath_ = std::move(pathCopy);
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

std::optional<WindowsClipboardFileDestination::RequestIntent>
WindowsClipboardFileDestination::nextRequestIntent() noexcept
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

bool WindowsClipboardFileDestination::bindRequest(
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

bool WindowsClipboardFileDestination::acceptResult(
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
            destinationHandle_, bytesWritten_,
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

void WindowsClipboardFileDestination::onRemoteGenerationChanged() noexcept
{
    if (active())
    {
        (void)ensureSourceCurrent();
    }
}

void WindowsClipboardFileDestination::cancel() noexcept
{
    if (active())
    {
        discardPartial(Status::Cancelled);
    }
}

#ifdef _WIN32
namespace
{

[[nodiscard]] HANDLE nativeHandle(
    const WindowsClipboardFileHandleToken token) noexcept
{
    return reinterpret_cast<HANDLE>(token);
}

[[nodiscard]] bool win32DuplicateWritableRegularFile(
    void *, const WindowsClipboardFileHandleToken sourceToken,
    WindowsClipboardFileHandleToken &duplicateToken) noexcept
{
    duplicateToken = 0U;
    HANDLE source = nativeHandle(sourceToken);
    if (source == nullptr || source == INVALID_HANDLE_VALUE ||
        ::GetFileType(source) != FILE_TYPE_DISK)
    {
        return false;
    }

    FILE_STANDARD_INFO information{};
    if (!::GetFileInformationByHandleEx(
            source, FileStandardInfo,
            &information, sizeof(information)) ||
        information.Directory)
    {
        return false;
    }

    HANDLE duplicate = nullptr;
    if (!::DuplicateHandle(
            ::GetCurrentProcess(), source,
            ::GetCurrentProcess(), &duplicate,
            0, FALSE, DUPLICATE_SAME_ACCESS) ||
        duplicate == nullptr ||
        duplicate == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    duplicateToken =
        reinterpret_cast<WindowsClipboardFileHandleToken>(duplicate);
    return true;
}

[[nodiscard]] bool win32ResizeFile(
    void *, const WindowsClipboardFileHandleToken token,
    const std::uint64_t size) noexcept
{
    if (size >
        static_cast<std::uint64_t>(
            std::numeric_limits<LONGLONG>::max()))
    {
        return false;
    }

    FILE_END_OF_FILE_INFO information{};
    information.EndOfFile.QuadPart =
        static_cast<LONGLONG>(size);
    return ::SetFileInformationByHandle(
               nativeHandle(token), FileEndOfFileInfo,
               &information, sizeof(information)) != FALSE;
}

[[nodiscard]] bool win32WriteFileAt(
    void *, const WindowsClipboardFileHandleToken token,
    const std::uint64_t offset,
    const std::span<const std::byte> bytes) noexcept
{
    if (bytes.empty() ||
        offset >
            static_cast<std::uint64_t>(
                std::numeric_limits<LONGLONG>::max()))
    {
        return false;
    }

    HANDLE handle = nativeHandle(token);
    std::size_t acceptedBytes = 0U;
    while (acceptedBytes < bytes.size())
    {
        const std::size_t remaining =
            bytes.size() - acceptedBytes;
        const DWORD requested =
            static_cast<DWORD>(std::min<std::size_t>(
                remaining,
                std::numeric_limits<DWORD>::max()));
        const std::uint64_t writeOffset =
            offset + acceptedBytes;
        if (writeOffset >
            static_cast<std::uint64_t>(
                std::numeric_limits<LONGLONG>::max()))
        {
            return false;
        }

        LARGE_INTEGER position{};
        position.QuadPart =
            static_cast<LONGLONG>(writeOffset);
        if (!::SetFilePointerEx(
                handle, position, nullptr, FILE_BEGIN))
        {
            return false;
        }

        DWORD written{};
        if (!::WriteFile(
                handle, bytes.data() + acceptedBytes,
                requested, &written, nullptr) ||
            written == 0U || written > requested)
        {
            return false;
        }
        acceptedBytes += written;
    }
    return true;
}

[[nodiscard]] bool win32FlushFile(
    void *, const WindowsClipboardFileHandleToken token) noexcept
{
    return ::FlushFileBuffers(nativeHandle(token)) != FALSE;
}

void win32CloseFile(
    void *, const WindowsClipboardFileHandleToken token) noexcept
{
    HANDLE handle = nativeHandle(token);
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
    {
        (void)::CloseHandle(handle);
    }
}

} // namespace

WindowsClipboardFileNativeOperations
makeWindowsClipboardFileNativeOperations() noexcept
{
    return {
        nullptr,
        &win32DuplicateWritableRegularFile,
        &win32ResizeFile,
        &win32WriteFileAt,
        &win32FlushFile,
        &win32CloseFile,
    };
}
#endif

} // namespace rdp_server::windows
