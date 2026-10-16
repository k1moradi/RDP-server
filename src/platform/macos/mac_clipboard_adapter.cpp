// SPDX-License-Identifier: GPL-3.0-or-later
#include "mac_clipboard_adapter.h"

#include <optional>

namespace rdp::macos
{

MacClipboardAdapter::MacClipboardAdapter(
    RemoteTransfer &remoteTransfer,
    MacClipboardNativeOperations nativeOperations) noexcept
    : remoteTransfer_(remoteTransfer),
      nativeOperations_(nativeOperations),
      closed_(!nativeOperationsValid())
{
}

MacClipboardAdapter::~MacClipboardAdapter() noexcept
{
    disconnect();
}

bool MacClipboardAdapter::nativeOperationsValid() const noexcept
{
    return nativeOperations_.context != nullptr &&
           nativeOperations_.readChangeCount != nullptr &&
           nativeOperations_.replaceContents != nullptr &&
           nativeOperations_.clearContents != nullptr;
}

bool MacClipboardAdapter::valid() const noexcept
{
    return !closed_;
}

bool MacClipboardAdapter::ownsPasteboard() const noexcept
{
    return !closed_ && ownsPasteboard_;
}

std::uint64_t MacClipboardAdapter::publicationGeneration() const noexcept
{
    return ownsPasteboard() ? publicationGeneration_ : 0U;
}

std::uint64_t MacClipboardAdapter::publicationChangeCount() const noexcept
{
    return ownsPasteboard() ? publicationChangeCount_ : 0U;
}

void MacClipboardAdapter::clearPublicationState() noexcept
{
    publicationGeneration_ = 0;
    publicationChangeCount_ = 0;
    textPublished_ = false;
    pngPublished_ = false;
    fileUrlPublished_ = false;
    ownsPasteboard_ = false;
}

bool MacClipboardAdapter::refreshNativeOwnership() noexcept
{
    if (!ownsPasteboard_)
    {
        return false;
    }

    std::uint64_t currentChangeCount{};
    if (!nativeOperations_.readChangeCount(
            nativeOperations_.context, currentChangeCount))
    {
        // If native ownership cannot be observed, mutating the pasteboard could
        // erase another application's data. Terminate this adapter instead.
        clearPublicationState();
        closed_ = true;
        return false;
    }

    if (currentChangeCount != publicationChangeCount_)
    {
        yieldedGeneration_ = publicationGeneration_;
        clearPublicationState();
        return false;
    }
    return true;
}

bool MacClipboardAdapter::clearOwnedPublication() noexcept
{
    if (!ownsPasteboard_)
    {
        return true;
    }
    if (!refreshNativeOwnership())
    {
        return !closed_;
    }
    if (!nativeOperations_.clearContents(nativeOperations_.context))
    {
        clearPublicationState();
        closed_ = true;
        return false;
    }
    clearPublicationState();
    return true;
}

bool MacClipboardAdapter::publishReadyRemoteGeneration() noexcept
{
    if (closed_ || operationInProgress_ || !remoteTransfer_.synchronized())
    {
        return false;
    }

    operationInProgress_ = true;
    bool success = true;

    if (ownsPasteboard_)
    {
        const bool stillOwner = refreshNativeOwnership();
        if (closed_)
        {
            success = false;
        }
        else if (stillOwner &&
                 publicationGeneration_ != remoteTransfer_.generation())
        {
            success = clearOwnedPublication();
        }
    }

    const std::uint64_t generation = remoteTransfer_.generation();
    const auto text = success ? remoteTransfer_.verifiedUnicodeText()
                              : std::nullopt;
    const auto image = success ? remoteTransfer_.verifiedImage()
                               : std::nullopt;
    const bool textReady = text.has_value();
    const bool pngReady =
        image.has_value() &&
        image->generation == generation &&
        image->format == RemoteTransfer::VerifiedImageFormat::Png;

    if (success &&
        (generation == 0 || generation == yieldedGeneration_ ||
         (!textReady && !pngReady)))
    {
        success = false;
    }

    if (success && ownsPasteboard_ &&
        publicationGeneration_ == generation &&
        !fileUrlPublished_ &&
        textPublished_ == textReady && pngPublished_ == pngReady)
    {
        operationInProgress_ = false;
        finishDeferredActions();
        return !closed_;
    }

    if (success)
    {
        MacClipboardNativeContent content{};
        if (textReady)
        {
            content.utf8Text = *text;
            content.hasText = true;
        }
        if (pngReady)
        {
            content.pngBytes = std::as_bytes(image->bytes);
            content.hasPng = true;
        }

        success = nativeOperations_.replaceContents(
            nativeOperations_.context, content);
        if (success)
        {
            std::uint64_t changeCount{};
            success = nativeOperations_.readChangeCount(
                nativeOperations_.context, changeCount);
            if (!success)
            {
                // Replacement may have succeeded, but ownership is now
                // ambiguous and must never be cleared speculatively.
                clearPublicationState();
                closed_ = true;
            }
            else
            {
                const auto currentText =
                    remoteTransfer_.verifiedUnicodeText();
                const auto currentImage =
                    remoteTransfer_.verifiedImage();
                const bool sourceStillCurrent =
                    remoteTransfer_.synchronized() &&
                    remoteTransfer_.generation() == generation &&
                    currentText.has_value() == textReady &&
                    currentImage.has_value() == image.has_value() &&
                    (!pngReady ||
                     (currentImage &&
                      currentImage->generation == generation &&
                      currentImage->format ==
                          RemoteTransfer::VerifiedImageFormat::Png));
                if (!sourceStillCurrent)
                {
                    // We just replaced the pasteboard, so the native callback's
                    // completed write is ours to revoke before returning.
                    if (!nativeOperations_.clearContents(
                            nativeOperations_.context))
                    {
                        closed_ = true;
                    }
                    clearPublicationState();
                    success = false;
                }
                else
                {
                    publicationGeneration_ = generation;
                    publicationChangeCount_ = changeCount;
                    textPublished_ = textReady;
                    pngPublished_ = pngReady;
                    fileUrlPublished_ = false;
                    ownsPasteboard_ = true;
                }
            }
        }
    }

    operationInProgress_ = false;
    finishDeferredActions();
    return success && !closed_;
}

bool MacClipboardAdapter::publishCompletedFileDestination(
    const MacClipboardFileDestination &destination) noexcept
{
    const auto completedFileUrl = destination.completedFileUrl();
    if (closed_ || operationInProgress_ ||
        !remoteTransfer_.synchronized() ||
        destination.status() !=
            MacClipboardFileDestination::Status::Complete ||
        !completedFileUrl)
    {
        return false;
    }

    const std::uint64_t generation = remoteTransfer_.generation();
    if (generation == 0U ||
        destination.generation() != generation ||
        generation == yieldedGeneration_)
    {
        return false;
    }

    operationInProgress_ = true;
    bool success = true;
    if (ownsPasteboard_)
    {
        const bool stillOwner = refreshNativeOwnership();
        if (closed_)
        {
            success = false;
        }
        else if (!stillOwner)
        {
            // refreshNativeOwnership records this generation as yielded after
            // a local takeover; never immediately steal the pasteboard back.
            success = false;
        }
        else if (publicationGeneration_ != generation)
        {
            success = clearOwnedPublication();
        }
    }

    if (success)
    {
        MacClipboardNativeContent content{};
        content.fileUrl = *completedFileUrl;
        content.hasFileUrl = true;
        success = nativeOperations_.replaceContents(
            nativeOperations_.context, content);
        if (success)
        {
            std::uint64_t changeCount{};
            success = nativeOperations_.readChangeCount(
                nativeOperations_.context, changeCount);
            if (!success)
            {
                // Replacement may have succeeded, but ownership is ambiguous.
                clearPublicationState();
                closed_ = true;
            }
            else
            {
                const auto currentFileUrl =
                    destination.completedFileUrl();
                const bool sourceStillCurrent =
                    remoteTransfer_.synchronized() &&
                    remoteTransfer_.generation() == generation &&
                    destination.generation() == generation &&
                    destination.status() ==
                        MacClipboardFileDestination::Status::Complete &&
                    currentFileUrl.has_value();
                if (!sourceStillCurrent)
                {
                    if (!nativeOperations_.clearContents(
                            nativeOperations_.context))
                    {
                        closed_ = true;
                    }
                    clearPublicationState();
                    success = false;
                }
                else
                {
                    publicationGeneration_ = generation;
                    publicationChangeCount_ = changeCount;
                    textPublished_ = false;
                    pngPublished_ = false;
                    fileUrlPublished_ = true;
                    ownsPasteboard_ = true;
                }
            }
        }
    }

    operationInProgress_ = false;
    finishDeferredActions();
    return success && !closed_;
}

bool MacClipboardAdapter::observePasteboardChange() noexcept
{
    if (closed_ || operationInProgress_ || !ownsPasteboard_)
    {
        return false;
    }
    operationInProgress_ = true;
    const bool stillOwner = refreshNativeOwnership();
    operationInProgress_ = false;
    finishDeferredActions();
    return stillOwner && !closed_;
}

void MacClipboardAdapter::onRemoteGenerationChanged() noexcept
{
    if (closed_)
    {
        return;
    }
    if (operationInProgress_)
    {
        generationChangeRequested_ = true;
        return;
    }

    operationInProgress_ = true;
    generationChangeRequested_ = false;
    if (ownsPasteboard_ &&
        (!remoteTransfer_.synchronized() ||
         publicationGeneration_ != remoteTransfer_.generation()))
    {
        (void)clearOwnedPublication();
    }
    operationInProgress_ = false;
    finishDeferredActions();
}

void MacClipboardAdapter::finishDeferredActions() noexcept
{
    if (operationInProgress_ || closed_)
    {
        return;
    }
    if (disconnectRequested_)
    {
        disconnectRequested_ = false;
        disconnect();
        return;
    }
    if (generationChangeRequested_)
    {
        generationChangeRequested_ = false;
        onRemoteGenerationChanged();
    }
}

void MacClipboardAdapter::disconnect() noexcept
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
    generationChangeRequested_ = false;
    (void)clearOwnedPublication();
    clearPublicationState();
    operationInProgress_ = false;
    closed_ = true;
}

} // namespace rdp::macos
