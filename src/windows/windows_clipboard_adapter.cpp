// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_clipboard_adapter.h"

#include "clipboard/clipboard_protocol.h"

#include <algorithm>
#include <array>
#include <cstring>
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

bool WindowsClipboardAdapter::renderFormatInternal(
    WindowsClipboardFormat format) noexcept
{
    if (!currentPublicationValid())
    {
        return false;
    }

    if (format == kUnicodeTextFormat && textPublished_)
    {
        if (textRendered_)
        {
            return true;
        }
        const auto text = remoteTransfer_.verifiedUnicodeText();
        if (!text)
        {
            return false;
        }
        std::vector<std::uint8_t> bytes;
        if (!encodeNativeUnicodeText(*text, bytes) ||
            !nativeOperations_.setFormatBytes(
                nativeOperations_.context, format,
                std::as_bytes(std::span<const std::uint8_t>{bytes})))
        {
            return false;
        }
        textRendered_ = true;
        return true;
    }

    if (format == publishedImageNativeFormat() && imagePublished_)
    {
        if (imageRendered_)
        {
            return true;
        }
        const auto image = remoteTransfer_.verifiedImage();
        if (!image || image->generation != publicationGeneration_ ||
            image->format != publishedImageFormat_)
        {
            return false;
        }
        if (!nativeOperations_.setFormatBytes(
                nativeOperations_.context, format,
                std::as_bytes(image->bytes)))
        {
            return false;
        }
        imageRendered_ = true;
        return true;
    }

    return false;
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
