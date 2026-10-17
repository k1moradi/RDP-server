// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_clipboard_adapter.h"

#include "clipboard/clipboard_protocol.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>

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

WindowsClipboardAdapter::WindowsClipboardAdapter(
    RemoteTransfer &remoteTransfer,
    WindowsClipboardNativeOperations nativeOperations,
    WindowsClipboardWindowToken ownerWindow) noexcept
    : remoteTransfer_(remoteTransfer),
      nativeOperations_(nativeOperations),
      ownerWindow_(ownerWindow),
      closed_(ownerWindow_ == 0 || !nativeOperationsValid())
{
    if (!closed_)
    {
        pngFormat_ = nativeOperations_.registerFormat(
            nativeOperations_.context, "PNG");
    }
}

WindowsClipboardAdapter::~WindowsClipboardAdapter() noexcept
{
    disconnect();
}

bool WindowsClipboardAdapter::nativeOperationsValid() const noexcept
{
    return nativeOperations_.context != nullptr &&
           nativeOperations_.registerFormat != nullptr &&
           nativeOperations_.openClipboard != nullptr &&
           nativeOperations_.emptyClipboard != nullptr &&
           nativeOperations_.setDelayedFormat != nullptr &&
           nativeOperations_.setFormatBytes != nullptr &&
           nativeOperations_.closeClipboard != nullptr &&
           nativeOperations_.clipboardOwner != nullptr;
}

bool WindowsClipboardAdapter::valid() const noexcept
{
    return !closed_;
}

bool WindowsClipboardAdapter::ownsClipboard() const noexcept
{
    return !closed_ && ownsClipboard_;
}

std::uint64_t WindowsClipboardAdapter::publicationGeneration() const noexcept
{
    return ownsClipboard() ? publicationGeneration_ : 0U;
}

WindowsClipboardFormat WindowsClipboardAdapter::pngFormat() const noexcept
{
    return closed_ ? 0U : pngFormat_;
}

WindowsClipboardFormat
WindowsClipboardAdapter::publishedImageNativeFormat() const noexcept
{
    if (!imagePublished_)
    {
        return 0U;
    }
    switch (publishedImageFormat_)
    {
    case RemoteTransfer::VerifiedImageFormat::Png:
        return pngFormat_;
    case RemoteTransfer::VerifiedImageFormat::DibV5:
        return kDibV5Format;
    case RemoteTransfer::VerifiedImageFormat::Dib:
        return kDibFormat;
    }
    return 0U;
}

bool WindowsClipboardAdapter::currentPublicationValid() const noexcept
{
    return !closed_ && ownsClipboard_ && publicationGeneration_ != 0 &&
           remoteTransfer_.synchronized() &&
           remoteTransfer_.generation() == publicationGeneration_;
}

void WindowsClipboardAdapter::clearPublicationState() noexcept
{
    publicationGeneration_ = 0;
    textPublished_ = false;
    imagePublished_ = false;
    textRendered_ = false;
    imageRendered_ = false;
    fileDropPublished_ = false;
    ownsClipboard_ = false;
}

bool WindowsClipboardAdapter::publishReadyRemoteGeneration() noexcept
{
    if (closed_ || operationInProgress_ || !remoteTransfer_.synchronized())
    {
        return false;
    }

    const std::uint64_t generation = remoteTransfer_.generation();
    if (generation == 0 || generation == yieldedGeneration_)
    {
        return false;
    }

    const bool textReady = remoteTransfer_.verifiedUnicodeText().has_value();
    const auto image = remoteTransfer_.verifiedImage();
    WindowsClipboardFormat imageFormat = 0;
    if (image)
    {
        switch (image->format)
        {
        case RemoteTransfer::VerifiedImageFormat::Png:
            imageFormat = pngFormat_;
            break;
        case RemoteTransfer::VerifiedImageFormat::DibV5:
            imageFormat = kDibV5Format;
            break;
        case RemoteTransfer::VerifiedImageFormat::Dib:
            imageFormat = kDibFormat;
            break;
        }
    }
    const bool imageReady = imageFormat != 0;
    if (!textReady && !imageReady)
    {
        return false;
    }

    if (ownsClipboard_ && publicationGeneration_ == generation &&
        !fileDropPublished_ &&
        textPublished_ == textReady && imagePublished_ == imageReady &&
        (!imageReady || publishedImageFormat_ == image->format))
    {
        return true;
    }

    operationInProgress_ = true;
    const bool wasOwner = ownsClipboard_;
    selfReplacingPublication_ = wasOwner;
    const bool opened = nativeOperations_.openClipboard(
        nativeOperations_.context, ownerWindow_);
    bool success = opened;
    if (success)
    {
        success = nativeOperations_.emptyClipboard(nativeOperations_.context);
    }
    if (success && imageReady)
    {
        success = nativeOperations_.setDelayedFormat(
            nativeOperations_.context, imageFormat);
    }
    if (success && textReady)
    {
        success = nativeOperations_.setDelayedFormat(
            nativeOperations_.context, kUnicodeTextFormat);
    }
    if (!success && opened)
    {
        // If publication failed after EmptyClipboard, remove any partial
        // delayed-format set before releasing the clipboard.
        (void)nativeOperations_.emptyClipboard(nativeOperations_.context);
    }
    const bool closedClipboard =
        !opened || nativeOperations_.closeClipboard(nativeOperations_.context);
    selfReplacingPublication_ = false;

    if (opened && !closedClipboard)
    {
        // A failed CloseClipboard leaves native ownership uncertain.
        closed_ = true;
    }

    if (success && closedClipboard && !closed_)
    {
        publicationGeneration_ = generation;
        textPublished_ = textReady;
        imagePublished_ = imageReady;
        if (imageReady)
        {
            publishedImageFormat_ = image->format;
        }
        textRendered_ = false;
        imageRendered_ = false;
        fileDropPublished_ = false;
        ownsClipboard_ = true;
    }
    else
    {
        clearPublicationState();
    }

    operationInProgress_ = false;
    finishDeferredDisconnect();
    return success && closedClipboard && !closed_;
}

bool WindowsClipboardAdapter::encodeNativeUnicodeText(
    std::string_view text, std::vector<std::uint8_t> &bytes) const noexcept
{
    bytes.clear();
    try
    {
        const std::vector<std::uint8_t> normalized =
            rdp_server::clipboard::encodeUtf16Le(text);
        if (normalized.size() < 2U || normalized.size() % 2U != 0 ||
            normalized.size() > kMaximumNativeTextBytes)
        {
            return false;
        }

        std::size_t newlineCount = 0;
        for (std::size_t offset = 0; offset + 2U < normalized.size();
             offset += 2U)
        {
            if (normalized[offset] == 0x0aU &&
                normalized[offset + 1U] == 0U)
            {
                ++newlineCount;
            }
        }
        if (newlineCount >
            (kMaximumNativeTextBytes - normalized.size()) / 2U)
        {
            return false;
        }

        std::vector<std::uint8_t> candidate;
        candidate.reserve(normalized.size() + newlineCount * 2U);
        for (std::size_t offset = 0; offset + 2U < normalized.size();
             offset += 2U)
        {
            if (normalized[offset] == 0x0aU &&
                normalized[offset + 1U] == 0U)
            {
                candidate.push_back(0x0dU);
                candidate.push_back(0U);
            }
            candidate.push_back(normalized[offset]);
            candidate.push_back(normalized[offset + 1U]);
        }
        candidate.push_back(0U);
        candidate.push_back(0U);
        bytes.swap(candidate);
        return true;
    }
    catch (...)
    {
        bytes.clear();
        return false;
    }
}

bool WindowsClipboardAdapter::encodeFileDrop(
    const std::span<const std::u16string_view> absolutePaths,
    std::vector<std::uint8_t> &bytes) const noexcept
{
    constexpr std::size_t kDropFilesHeaderBytes = 20U;
    bytes.clear();
    if (absolutePaths.empty() ||
        absolutePaths.size() > RemoteTransfer::kMaximumRemoteFiles)
    {
        return false;
    }

    std::size_t listCodeUnits = 1U; // Final list NUL.
    for (std::size_t index = 0; index < absolutePaths.size(); ++index)
    {
        const std::u16string_view path = absolutePaths[index];
        if (path.empty() ||
            path.size() >
                WindowsClipboardFileDestination::kMaximumLocalPathCodeUnits ||
            path.size() >
                std::numeric_limits<std::size_t>::max() - listCodeUnits - 1U)
        {
            return false;
        }
        for (std::size_t previous = 0; previous < index; ++previous)
        {
            if (absolutePaths[previous] == path)
            {
                return false;
            }
        }
        listCodeUnits += path.size() + 1U;
    }

    if (listCodeUnits >
        (std::numeric_limits<std::size_t>::max() -
         kDropFilesHeaderBytes) / 2U)
    {
        return false;
    }

    try
    {
        bytes.assign(
            kDropFilesHeaderBytes + listCodeUnits * 2U,
            0U);
    }
    catch (...)
    {
        bytes.clear();
        return false;
    }

    const auto write32 = [&bytes](
        const std::size_t offset, const std::uint32_t value)
    {
        bytes[offset] = static_cast<std::uint8_t>(value);
        bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
        bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
        bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
    };
    // DROPFILES: pFiles=20, pt={0,0}, fNC=FALSE, fWide=TRUE.
    write32(0U, static_cast<std::uint32_t>(kDropFilesHeaderBytes));
    write32(16U, 1U);

    std::size_t outputOffset = kDropFilesHeaderBytes;
    for (const std::u16string_view path : absolutePaths)
    {
        for (const char16_t codeUnit : path)
        {
            const auto value = static_cast<std::uint16_t>(codeUnit);
            bytes[outputOffset++] = static_cast<std::uint8_t>(value);
            bytes[outputOffset++] =
                static_cast<std::uint8_t>(value >> 8U);
        }
        outputOffset += 2U; // Per-path NUL from zero-filled storage.
    }
    // The remaining zero-filled code unit is the final list NUL.
    return outputOffset + 2U == bytes.size();
}

bool WindowsClipboardAdapter::collectCompletedFilePaths(
    const RemoteFileDestinationPlan *const plan,
    const std::span<const WindowsClipboardFileDestination *const>
        destinations,
    const std::uint64_t generation,
    std::array<std::u16string_view,
               RemoteTransfer::kMaximumRemoteFiles> &paths) const noexcept
{
    paths.fill({});
    if (generation == 0U || destinations.empty() ||
        destinations.size() > RemoteTransfer::kMaximumRemoteFiles)
    {
        return false;
    }
    if (plan == nullptr)
    {
        if (destinations.size() != 1U)
        {
            return false;
        }
    }
    else if (!plan->current(remoteTransfer_) ||
             plan->generation() != generation ||
             plan->size() != destinations.size())
    {
        return false;
    }

    std::array<bool, RemoteTransfer::kMaximumRemoteFiles> seen{};
    for (std::size_t inputIndex = 0;
         inputIndex < destinations.size(); ++inputIndex)
    {
        const WindowsClipboardFileDestination *const destination =
            destinations[inputIndex];
        if (destination == nullptr ||
            destination->status() !=
                WindowsClipboardFileDestination::Status::Complete ||
            destination->generation() != generation)
        {
            return false;
        }

        const std::size_t outputIndex =
            plan == nullptr ? 0U : destination->fileIndex();
        if (outputIndex >= destinations.size() || seen[outputIndex])
        {
            return false;
        }
        if (plan != nullptr &&
            plan->associationStatus(remoteTransfer_, outputIndex) !=
                RemoteFileDestinationPlan::AssociationStatus::CurrentFile)
        {
            return false;
        }

        const auto completedPath = destination->completedFilePath();
        if (!completedPath || completedPath->empty())
        {
            return false;
        }
        for (std::size_t previous = 0;
             previous < destinations.size(); ++previous)
        {
            if (seen[previous] && paths[previous] == *completedPath)
            {
                return false;
            }
        }

        paths[outputIndex] = *completedPath;
        seen[outputIndex] = true;
    }

    return std::all_of(
        seen.begin(), seen.begin() + destinations.size(),
        [](const bool present) { return present; });
}

bool WindowsClipboardAdapter::publishCompletedFileDestination(
    const WindowsClipboardFileDestination &destination) noexcept
{
    const std::array<const WindowsClipboardFileDestination *, 1> destinations{
        &destination};
    return publishCompletedFileDestinationsInternal(
        nullptr, destinations);
}

bool WindowsClipboardAdapter::publishCompletedFileDestinations(
    const RemoteFileDestinationPlan &plan,
    const std::span<const WindowsClipboardFileDestination *const>
        destinations) noexcept
{
    return publishCompletedFileDestinationsInternal(
        &plan, destinations);
}

bool WindowsClipboardAdapter::publishCompletedFileDestinationsInternal(
    const RemoteFileDestinationPlan *const plan,
    const std::span<const WindowsClipboardFileDestination *const>
        destinations) noexcept
{
    if (closed_ || operationInProgress_ ||
        !remoteTransfer_.synchronized())
    {
        return false;
    }

    const std::uint64_t generation = remoteTransfer_.generation();
    if (generation == 0U || generation == yieldedGeneration_)
    {
        return false;
    }

    std::array<std::u16string_view,
               RemoteTransfer::kMaximumRemoteFiles> completedPaths{};
    if (!collectCompletedFilePaths(
            plan, destinations, generation, completedPaths))
    {
        return false;
    }

    std::vector<std::uint8_t> dropBytes;
    if (!encodeFileDrop(
            {completedPaths.data(), destinations.size()}, dropBytes))
    {
        return false;
    }

    operationInProgress_ = true;
    bool success = true;
    if (ownsClipboard_ &&
        nativeOperations_.clipboardOwner(nativeOperations_.context) !=
            ownerWindow_)
    {
        yieldedGeneration_ = publicationGeneration_;
        clearPublicationState();
        success = false;
    }

    bool opened = false;
    if (success)
    {
        opened = nativeOperations_.openClipboard(
            nativeOperations_.context, ownerWindow_);
        success = opened;
    }

    const bool wasOwner = ownsClipboard_;
    selfReplacingPublication_ = wasOwner;
    if (success)
    {
        success = nativeOperations_.emptyClipboard(
            nativeOperations_.context);
    }
    if (success)
    {
        success = nativeOperations_.setFormatBytes(
            nativeOperations_.context, kFileDropFormat,
            std::as_bytes(std::span<const std::uint8_t>{dropBytes}));
    }
    if (success)
    {
        std::array<std::u16string_view,
                   RemoteTransfer::kMaximumRemoteFiles> currentPaths{};
        std::vector<std::uint8_t> currentDropBytes;
        const bool sourceStillCurrent =
            remoteTransfer_.synchronized() &&
            remoteTransfer_.generation() == generation &&
            collectCompletedFilePaths(
                plan, destinations, generation, currentPaths) &&
            encodeFileDrop(
                {currentPaths.data(), destinations.size()},
                currentDropBytes) &&
            currentDropBytes == dropBytes;
        if (!sourceStillCurrent)
        {
            (void)nativeOperations_.emptyClipboard(
                nativeOperations_.context);
            success = false;
        }
    }
    if (!success && opened)
    {
        (void)nativeOperations_.emptyClipboard(
            nativeOperations_.context);
    }
    selfReplacingPublication_ = false;

    const bool closedClipboard =
        !opened || nativeOperations_.closeClipboard(
            nativeOperations_.context);
    if (opened && !closedClipboard)
    {
        closed_ = true;
    }

    if (success && closedClipboard && !closed_)
    {
        publicationGeneration_ = generation;
        textPublished_ = false;
        imagePublished_ = false;
        textRendered_ = false;
        imageRendered_ = false;
        fileDropPublished_ = true;
        ownsClipboard_ = true;
    }
    else
    {
        clearPublicationState();
    }

    operationInProgress_ = false;
    finishDeferredDisconnect();
    return success && closedClipboard && !closed_;
}

bool WindowsClipboardAdapter::renderFormat(
    WindowsClipboardFormat format) noexcept
{
    // MS Win32 WM_RENDERFORMAT: the clipboard is already open by the consumer;
    // opening it again here would fail and could deadlock native progression.
    if (closed_ || operationInProgress_)
    {
        return false;
    }
    operationInProgress_ = true;
    const bool rendered = renderFormatInternal(format);
    operationInProgress_ = false;
    finishDeferredDisconnect();
    return rendered && !closed_;
}

bool WindowsClipboardAdapter::renderAllBeforeOwnerDestroy() noexcept
{
    if (closed_ || operationInProgress_ || !currentPublicationValid())
    {
        return false;
    }

    operationInProgress_ = true;
    const bool opened = nativeOperations_.openClipboard(
        nativeOperations_.context, ownerWindow_);
    bool success = opened;
    if (success &&
        nativeOperations_.clipboardOwner(nativeOperations_.context) !=
            ownerWindow_)
    {
        yieldedGeneration_ = publicationGeneration_;
        clearPublicationState();
        success = false;
    }
    if (success && imagePublished_)
    {
        success = renderFormatInternal(publishedImageNativeFormat());
    }
    if (success && textPublished_)
    {
        success = renderFormatInternal(kUnicodeTextFormat);
    }
    const bool closedClipboard =
        !opened || nativeOperations_.closeClipboard(nativeOperations_.context);

    operationInProgress_ = false;
    finishDeferredDisconnect();
    if (opened && !closedClipboard)
    {
        closed_ = true;
    }
    return success && closedClipboard && !closed_;
}

void WindowsClipboardAdapter::onDestroyClipboard() noexcept
{
    if (closed_)
    {
        return;
    }
    if (selfReplacingPublication_)
    {
        clearPublicationState();
        return;
    }
    if (ownsClipboard_ && publicationGeneration_ != 0)
    {
        yieldedGeneration_ = publicationGeneration_;
    }
    clearPublicationState();
}

void WindowsClipboardAdapter::finishDeferredDisconnect() noexcept
{
    if (disconnectRequested_ && !operationInProgress_ && !closed_)
    {
        disconnectRequested_ = false;
        disconnect();
    }
}

void WindowsClipboardAdapter::disconnect() noexcept
{
    if (closed_)
    {
        return;
    }
    if (operationInProgress_)
    {
        disconnectRequested_ = true;
        return;
    }

    operationInProgress_ = true;
    disconnectRequested_ = false;
    if (ownsClipboard_)
    {
        const bool opened = nativeOperations_.openClipboard(
            nativeOperations_.context, ownerWindow_);
        if (opened)
        {
            if (nativeOperations_.clipboardOwner(nativeOperations_.context) ==
                ownerWindow_)
            {
                selfReplacingPublication_ = true;
                (void)nativeOperations_.emptyClipboard(
                    nativeOperations_.context);
                selfReplacingPublication_ = false;
            }
            (void)nativeOperations_.closeClipboard(
                nativeOperations_.context);
        }
    }
    clearPublicationState();
    operationInProgress_ = false;
    closed_ = true;
}

#ifdef _WIN32
namespace
{

[[nodiscard]] bool nativeOpenClipboard(
    void *, WindowsClipboardWindowToken ownerWindow) noexcept
{
    return ::OpenClipboard(
               reinterpret_cast<HWND>(ownerWindow)) != FALSE;
}

[[nodiscard]] bool nativeEmptyClipboard(void *) noexcept
{
    return ::EmptyClipboard() != FALSE;
}

[[nodiscard]] WindowsClipboardFormat nativeRegisterFormat(
    void *, std::string_view name) noexcept
{
    if (name.empty() || name.size() >= 64U)
    {
        return 0U;
    }
    std::array<char, 64> terminated{};
    std::copy(name.begin(), name.end(), terminated.begin());
    return static_cast<WindowsClipboardFormat>(
        ::RegisterClipboardFormatA(terminated.data()));
}

[[nodiscard]] bool nativeSetDelayedFormat(
    void *, WindowsClipboardFormat format) noexcept
{
    if (format == 0U)
    {
        return false;
    }
    ::SetLastError(ERROR_SUCCESS);
    const HANDLE result =
        ::SetClipboardData(static_cast<UINT>(format), nullptr);
    return result != nullptr || ::GetLastError() == ERROR_SUCCESS;
}

[[nodiscard]] bool nativeSetFormatBytes(
    void *, WindowsClipboardFormat format,
    std::span<const std::byte> bytes) noexcept
{
    if (format == 0U || bytes.empty())
    {
        return false;
    }
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, bytes.size());
    if (memory == nullptr)
    {
        return false;
    }
    void *destination = ::GlobalLock(memory);
    if (destination == nullptr)
    {
        ::GlobalFree(memory);
        return false;
    }
    std::memcpy(destination, bytes.data(), bytes.size());
    ::SetLastError(NO_ERROR);
    const BOOL unlocked = ::GlobalUnlock(memory);
    if (unlocked == FALSE && ::GetLastError() != NO_ERROR)
    {
        ::GlobalFree(memory);
        return false;
    }

    if (::SetClipboardData(static_cast<UINT>(format), memory) == nullptr)
    {
        ::GlobalFree(memory);
        return false;
    }
    // The system owns memory after successful SetClipboardData.
    return true;
}

[[nodiscard]] bool nativeCloseClipboard(void *) noexcept
{
    return ::CloseClipboard() != FALSE;
}

[[nodiscard]] WindowsClipboardWindowToken nativeClipboardOwner(
    void *) noexcept
{
    return reinterpret_cast<WindowsClipboardWindowToken>(
        ::GetClipboardOwner());
}

} // namespace

WindowsClipboardNativeOperations
makeWindowsClipboardNativeOperations() noexcept
{
    static int nativeContext{};
    return WindowsClipboardNativeOperations{
        &nativeContext,
        &nativeRegisterFormat,
        &nativeOpenClipboard,
        &nativeEmptyClipboard,
        &nativeSetDelayedFormat,
        &nativeSetFormatBytes,
        &nativeCloseClipboard,
        &nativeClipboardOwner,
    };
}
#endif

} // namespace rdp_server::windows
