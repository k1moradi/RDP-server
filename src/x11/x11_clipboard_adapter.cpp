// SPDX-License-Identifier: GPL-3.0-or-later

#include "x11_clipboard_adapter.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <limits>

#include "clipboard/clipboard_protocol.h"
#include "platform/linux/linux_clipboard_file_destination.h"

namespace
{

[[nodiscard]] xcb_connection_t *
asConnection(void *context) noexcept
{
    return static_cast<xcb_connection_t *>(context);
}

[[nodiscard]] bool
connectionUsable(xcb_connection_t *connection) noexcept
{
    return connection != nullptr && xcb_connection_has_error(connection) == 0;
}

xcb_atom_t
xcbInternAtom(void *context, std::string_view name) noexcept
{
    xcb_connection_t *connection = asConnection(context);
    if (!connectionUsable(connection) || name.empty() ||
        name.size() > std::numeric_limits<std::uint16_t>::max())
    {
        return XCB_ATOM_NONE;
    }

    const auto cookie = xcb_intern_atom(
        connection, 0, static_cast<std::uint16_t>(name.size()), name.data());
    xcb_generic_error_t *error = nullptr;
    xcb_intern_atom_reply_t *reply =
        xcb_intern_atom_reply(connection, cookie, &error);
    const xcb_atom_t atom =
        error == nullptr && reply != nullptr ? reply->atom : xcb_atom_t{};
    std::free(error);
    std::free(reply);
    return atom;
}

xcb_window_t
xcbCreateOwnerWindow(void *context, xcb_window_t rootWindow) noexcept
{
    xcb_connection_t *connection = asConnection(context);
    if (!connectionUsable(connection) || rootWindow == XCB_WINDOW_NONE)
    {
        return XCB_WINDOW_NONE;
    }

    const xcb_window_t window = xcb_generate_id(connection);
    if (window == XCB_WINDOW_NONE)
    {
        return XCB_WINDOW_NONE;
    }
    const xcb_void_cookie_t cookie = xcb_create_window_checked(
        connection, XCB_COPY_FROM_PARENT, window, rootWindow,
        0, 0, 1, 1, 0, XCB_WINDOW_CLASS_INPUT_ONLY,
        XCB_COPY_FROM_PARENT, 0, nullptr);
    xcb_generic_error_t *error = xcb_request_check(connection, cookie);
    const bool success = error == nullptr;
    std::free(error);
    return success ? window : xcb_window_t{};
}

bool
xcbDestroyWindow(void *context, xcb_window_t window) noexcept
{
    xcb_connection_t *connection = asConnection(context);
    if (!connectionUsable(connection) || window == XCB_WINDOW_NONE)
    {
        return false;
    }
    const xcb_void_cookie_t cookie =
        xcb_destroy_window_checked(connection, window);
    xcb_generic_error_t *error = xcb_request_check(connection, cookie);
    const bool success = error == nullptr;
    std::free(error);
    return success;
}

xcb_window_t
xcbSelectionOwner(void *context, xcb_atom_t selection) noexcept
{
    xcb_connection_t *connection = asConnection(context);
    if (!connectionUsable(connection) || selection == XCB_ATOM_NONE)
    {
        return XCB_WINDOW_NONE;
    }
    const auto cookie = xcb_get_selection_owner(connection, selection);
    xcb_generic_error_t *error = nullptr;
    xcb_get_selection_owner_reply_t *reply =
        xcb_get_selection_owner_reply(connection, cookie, &error);
    const xcb_window_t owner =
        error == nullptr && reply != nullptr ? reply->owner : xcb_window_t{};
    std::free(error);
    std::free(reply);
    return owner;
}

bool
xcbSetSelectionOwner(void *context, xcb_window_t owner,
                     xcb_atom_t selection) noexcept
{
    xcb_connection_t *connection = asConnection(context);
    if (!connectionUsable(connection) || selection == XCB_ATOM_NONE)
    {
        return false;
    }
    const xcb_void_cookie_t cookie = xcb_set_selection_owner_checked(
        connection, owner, selection, XCB_CURRENT_TIME);
    xcb_generic_error_t *error = xcb_request_check(connection, cookie);
    if (error != nullptr)
    {
        std::free(error);
        return false;
    }
    return xcbSelectionOwner(context, selection) == owner;
}

bool
xcbChangeProperty(void *context, xcb_window_t window, xcb_atom_t property,
                  xcb_atom_t propertyType, std::uint8_t format,
                  std::span<const std::byte> bytes) noexcept
{
    xcb_connection_t *connection = asConnection(context);
    if (!connectionUsable(connection) || window == XCB_WINDOW_NONE ||
        property == XCB_ATOM_NONE || propertyType == XCB_ATOM_NONE ||
        (format != 8U && format != 16U && format != 32U))
    {
        return false;
    }

    const std::size_t unitBytes = format / 8U;
    if (unitBytes == 0 || bytes.size() % unitBytes != 0 ||
        bytes.size() / unitBytes > std::numeric_limits<std::uint32_t>::max())
    {
        return false;
    }

    const auto elementCount =
        static_cast<std::uint32_t>(bytes.size() / unitBytes);
    const xcb_void_cookie_t cookie = xcb_change_property_checked(
        connection, XCB_PROP_MODE_REPLACE, window, property, propertyType,
        format, elementCount, bytes.data());
    xcb_generic_error_t *error = xcb_request_check(connection, cookie);
    const bool success = error == nullptr;
    std::free(error);
    return success;
}

bool
xcbSelectTransferEvents(void *context, xcb_window_t window,
                        std::uint32_t &previousEventMask) noexcept
{
    xcb_connection_t *connection = asConnection(context);
    if (!connectionUsable(connection) || window == XCB_WINDOW_NONE)
    {
        return false;
    }

    const auto attributesCookie = xcb_get_window_attributes(connection, window);
    xcb_generic_error_t *attributesError = nullptr;
    xcb_get_window_attributes_reply_t *attributes =
        xcb_get_window_attributes_reply(
            connection, attributesCookie, &attributesError);
    if (attributesError != nullptr || attributes == nullptr)
    {
        std::free(attributesError);
        std::free(attributes);
        return false;
    }

    previousEventMask = attributes->your_event_mask;
    std::free(attributes);
    constexpr std::uint32_t transferEventMask =
        static_cast<std::uint32_t>(XCB_EVENT_MASK_PROPERTY_CHANGE) |
        static_cast<std::uint32_t>(XCB_EVENT_MASK_STRUCTURE_NOTIFY);
    const std::uint32_t requestedEventMask =
        previousEventMask | transferEventMask;
    if (requestedEventMask == previousEventMask)
    {
        return true;
    }

    const xcb_void_cookie_t cookie = xcb_change_window_attributes_checked(
        connection, window, XCB_CW_EVENT_MASK, &requestedEventMask);
    xcb_generic_error_t *error = xcb_request_check(connection, cookie);
    const bool success = error == nullptr;
    std::free(error);
    return success;
}

bool
xcbRestoreEventMask(void *context, xcb_window_t window,
                    std::uint32_t eventMask) noexcept
{
    xcb_connection_t *connection = asConnection(context);
    if (!connectionUsable(connection) || window == XCB_WINDOW_NONE)
    {
        return false;
    }

    const xcb_void_cookie_t cookie = xcb_change_window_attributes_checked(
        connection, window, XCB_CW_EVENT_MASK, &eventMask);
    xcb_generic_error_t *error = xcb_request_check(connection, cookie);
    const bool success = error == nullptr;
    std::free(error);
    return success;
}

bool
xcbDeleteProperty(void *context, xcb_window_t window,
                  xcb_atom_t property) noexcept
{
    xcb_connection_t *connection = asConnection(context);
    if (!connectionUsable(connection) || window == XCB_WINDOW_NONE ||
        property == XCB_ATOM_NONE)
    {
        return false;
    }

    const xcb_void_cookie_t cookie =
        xcb_delete_property_checked(connection, window, property);
    xcb_generic_error_t *error = xcb_request_check(connection, cookie);
    const bool success = error == nullptr;
    std::free(error);
    return success;
}

bool
xcbSendSelectionNotify(void *context,
                       const xcb_selection_notify_event_t &event) noexcept
{
    xcb_connection_t *connection = asConnection(context);
    if (!connectionUsable(connection) || event.requestor == XCB_WINDOW_NONE)
    {
        return false;
    }
    const xcb_void_cookie_t cookie = xcb_send_event_checked(
        connection, 0, event.requestor, XCB_EVENT_MASK_NO_EVENT,
        reinterpret_cast<const char *>(&event));
    xcb_generic_error_t *error = xcb_request_check(connection, cookie);
    const bool success = error == nullptr;
    std::free(error);
    return success;
}

} // namespace

X11ClipboardNativeOperations
X11ClipboardAdapter::makeXcbOperations(xcb_connection_t &connection) noexcept
{
    return X11ClipboardNativeOperations{
        &connection,
        xcbInternAtom,
        xcbCreateOwnerWindow,
        xcbDestroyWindow,
        xcbSetSelectionOwner,
        xcbSelectionOwner,
        xcbChangeProperty,
        xcbSelectTransferEvents,
        xcbRestoreEventMask,
        xcbDeleteProperty,
        xcbSendSelectionNotify,
    };
}

X11ClipboardAdapter::X11ClipboardAdapter(RemoteTransfer &remoteTransfer,
                                         xcb_connection_t &connection,
                                         xcb_window_t rootWindow) noexcept
    : X11ClipboardAdapter(remoteTransfer, makeXcbOperations(connection),
                          rootWindow)
{
}

X11ClipboardAdapter::X11ClipboardAdapter(
    RemoteTransfer &remoteTransfer,
    X11ClipboardNativeOperations nativeOperations,
    xcb_window_t rootWindow) noexcept
    : remoteTransfer_(remoteTransfer),
      nativeOperations_(nativeOperations),
      rootWindow_(rootWindow)
{
    if (!nativeOperationsValid() || rootWindow_ == XCB_WINDOW_NONE)
    {
        return;
    }

    // Fixed native names only: never intern remote-provided atom names.
    atoms_.clipboard =
        nativeOperations_.internAtom(nativeOperations_.context, "CLIPBOARD");
    atoms_.targets =
        nativeOperations_.internAtom(nativeOperations_.context, "TARGETS");
    atoms_.utf8String =
        nativeOperations_.internAtom(nativeOperations_.context, "UTF8_STRING");
    atoms_.png =
        nativeOperations_.internAtom(nativeOperations_.context, "image/png");
    atoms_.uriList =
        nativeOperations_.internAtom(nativeOperations_.context, "text/uri-list");
    atoms_.gnomeCopiedFiles = nativeOperations_.internAtom(
        nativeOperations_.context, "x-special/gnome-copied-files");
    atoms_.kdeCutSelection = nativeOperations_.internAtom(
        nativeOperations_.context, "application/x-kde-cutselection");
    atoms_.incr =
        nativeOperations_.internAtom(nativeOperations_.context, "INCR");
    if (atoms_.clipboard == XCB_ATOM_NONE ||
        atoms_.targets == XCB_ATOM_NONE ||
        atoms_.utf8String == XCB_ATOM_NONE ||
        atoms_.png == XCB_ATOM_NONE ||
        atoms_.uriList == XCB_ATOM_NONE ||
        atoms_.gnomeCopiedFiles == XCB_ATOM_NONE ||
        atoms_.kdeCutSelection == XCB_ATOM_NONE ||
        atoms_.incr == XCB_ATOM_NONE)
    {
        return;
    }

    ownerWindow_ = nativeOperations_.createOwnerWindow(
        nativeOperations_.context, rootWindow_);
    valid_ = ownerWindow_ != XCB_WINDOW_NONE;
}

X11ClipboardAdapter::~X11ClipboardAdapter() noexcept
{
    disconnect();
}

bool
X11ClipboardAdapter::nativeOperationsValid() const noexcept
{
    return nativeOperations_.context != nullptr &&
           nativeOperations_.internAtom != nullptr &&
           nativeOperations_.createOwnerWindow != nullptr &&
           nativeOperations_.destroyWindow != nullptr &&
           nativeOperations_.setSelectionOwner != nullptr &&
           nativeOperations_.selectionOwner != nullptr &&
           nativeOperations_.changeProperty != nullptr &&
           nativeOperations_.selectTransferEvents != nullptr &&
           nativeOperations_.restoreEventMask != nullptr &&
           nativeOperations_.deleteProperty != nullptr &&
           nativeOperations_.sendSelectionNotify != nullptr;
}

bool
X11ClipboardAdapter::valid() const noexcept
{
    return valid_ && ownerWindow_ != XCB_WINDOW_NONE &&
           atoms_.clipboard != XCB_ATOM_NONE;
}

xcb_window_t
X11ClipboardAdapter::ownerWindow() const noexcept
{
    return valid() ? ownerWindow_ : xcb_window_t{};
}

xcb_atom_t
X11ClipboardAdapter::clipboardAtom() const noexcept
{
    return valid() ? atoms_.clipboard : xcb_atom_t{};
}

xcb_atom_t
X11ClipboardAdapter::targetsAtom() const noexcept
{
    return valid() ? atoms_.targets : xcb_atom_t{};
}

xcb_atom_t
X11ClipboardAdapter::utf8StringAtom() const noexcept
{
    return valid() ? atoms_.utf8String : xcb_atom_t{};
}

xcb_atom_t
X11ClipboardAdapter::pngAtom() const noexcept
{
    return valid() ? atoms_.png : xcb_atom_t{};
}

xcb_atom_t
X11ClipboardAdapter::uriListAtom() const noexcept
{
    return valid() ? atoms_.uriList : xcb_atom_t{};
}

xcb_atom_t
X11ClipboardAdapter::gnomeCopiedFilesAtom() const noexcept
{
    return valid() ? atoms_.gnomeCopiedFiles : xcb_atom_t{};
}

xcb_atom_t
X11ClipboardAdapter::kdeCutSelectionAtom() const noexcept
{
    return valid() ? atoms_.kdeCutSelection : xcb_atom_t{};
}

xcb_atom_t
X11ClipboardAdapter::incrAtom() const noexcept
{
    return valid() ? atoms_.incr : xcb_atom_t{};
}

bool
X11ClipboardAdapter::incrTransferActive() const noexcept
{
    return valid() && incr_.active;
}

std::size_t
X11ClipboardAdapter::incrBytesSent() const noexcept
{
    return incr_.active ? incr_.offset : 0;
}

std::uint64_t
X11ClipboardAdapter::publicationGeneration() const noexcept
{
    return publicationGeneration_;
}

std::uint64_t
X11ClipboardAdapter::ownershipEpoch() const noexcept
{
    return ownershipEpoch_;
}

bool
X11ClipboardAdapter::ownsClipboard() const noexcept
{
    return valid() && ownsClipboard_;
}

X11ClipboardAdapter::Source
X11ClipboardAdapter::contentSource() const noexcept
{
    return contentSource_;
}

X11ClipboardAdapter::Source
X11ClipboardAdapter::lastOwnershipTransitionSource() const noexcept
{
    return lastOwnershipTransitionSource_;
}

bool
X11ClipboardAdapter::fileHandoffAvailable() const noexcept
{
    return fileUriListLength_ != 0U &&
           fileHandoffFileCount_ != 0U &&
           fileHandoffGeneration_ != 0U &&
           fileHandoffGeneration_ == remoteTransfer_.generation();
}

bool
X11ClipboardAdapter::remoteTextOffered() const noexcept
{
    return remoteTransfer_.advertises(
        rdp_server::clipboard::kFormatUnicodeText);
}

std::uint32_t
X11ClipboardAdapter::remotePngFormatId() const noexcept
{
    const std::uint32_t formatId = remoteTransfer_.namedFormatId("PNG");
    return formatId != 0 && remoteTransfer_.advertises(formatId) ? formatId : 0;
}

bool
X11ClipboardAdapter::currentPublicationValid() const noexcept
{
    return valid() && ownsClipboard_ &&
           contentSource_ == Source::RemoteRdp &&
           remoteTransfer_.synchronized() && publicationGeneration_ != 0 &&
           publicationGeneration_ == remoteTransfer_.generation();
}

bool
X11ClipboardAdapter::publishCompletedFile(
    const rdp::linux_platform::LinuxClipboardFileDestination &destination,
    PasteClock::time_point now) noexcept
{
    const std::array<
        const rdp::linux_platform::LinuxClipboardFileDestination *, 1>
        destinations{&destination};
    return publishCompletedFiles(destinations, now);
}

bool
X11ClipboardAdapter::publishCompletedFiles(
    std::span<const rdp::linux_platform::
                  LinuxClipboardFileDestination *const> destinations,
    PasteClock::time_point now) noexcept
{
    static_assert(
        kMaximumFileUriBytes ==
        rdp::linux_platform::LinuxClipboardFileDestination::
            kMaximumLocalFileUriBytes);

    if (!valid() || destinations.empty() ||
        destinations.size() > kMaximumCompletedFiles ||
        !remoteTransfer_.synchronized())
    {
        return false;
    }

    const std::uint64_t generation = remoteTransfer_.generation();
    if (generation == 0U ||
        (yieldedGeneration_ == generation && !ownsClipboard_))
    {
        return false;
    }

    std::array<char, kMaximumFileHandoffBytes> candidate{};
    std::size_t candidateBytes = 0U;
    for (std::size_t index = 0; index < destinations.size(); ++index)
    {
        const auto *destination = destinations[index];
        if (destination == nullptr ||
            destination->status() !=
                rdp::linux_platform::LinuxClipboardFileDestination::
                    Status::Complete ||
            destination->generation() != generation)
        {
            return false;
        }

        const auto uri = destination->completedFileUri();
        if (!uri || uri->empty() ||
            uri->size() > kMaximumFileUriBytes)
        {
            return false;
        }

        for (std::size_t previous = 0; previous < index; ++previous)
        {
            const auto previousUri =
                destinations[previous]->completedFileUri();
            if (previousUri && *previousUri == *uri)
            {
                return false;
            }
        }

        const std::size_t separatorBytes = index == 0U ? 0U : 1U;
        const std::size_t remainingBytes =
            candidate.size() - candidateBytes;
        if (separatorBytes > remainingBytes ||
            uri->size() > remainingBytes - separatorBytes)
        {
            return false;
        }
        if (separatorBytes != 0U)
        {
            candidate[candidateBytes++] = '\n';
        }
        std::copy(
            uri->begin(), uri->end(),
            candidate.begin() +
                static_cast<std::ptrdiff_t>(candidateBytes));
        candidateBytes += uri->size();
    }

    if (fileHandoffGeneration_ == generation &&
        fileUriListLength_ != 0U)
    {
        if (fileHandoffFileCount_ != destinations.size() ||
            fileUriListLength_ != candidateBytes ||
            !std::equal(
                candidate.begin(),
                candidate.begin() +
                    static_cast<std::ptrdiff_t>(candidateBytes),
                fileUriList_.begin()))
        {
            // Do not silently mutate file-manager payload behind one X11
            // ownership transition. A later generation can publish a new set.
            return false;
        }
        return publishCurrentRemoteOffer(now);
    }

    fileUriList_.fill(0);
    std::copy_n(
        candidate.begin(), candidateBytes, fileUriList_.begin());
    fileUriListLength_ = candidateBytes;
    fileHandoffFileCount_ = destinations.size();
    fileHandoffGeneration_ = generation;

    if (!publishCurrentRemoteOffer(now))
    {
        clearFileHandoff();
        return false;
    }
    return true;
}

bool
X11ClipboardAdapter::publishCurrentRemoteOffer(
    PasteClock::time_point now) noexcept
{
    if (!valid())
    {
        return false;
    }

    (void)serviceIncrTransfer(now);
    if (pending_.active)
    {
        (void)servicePendingPaste(now);
        if (pending_.active &&
            pending_.publicationGeneration != remoteTransfer_.generation())
        {
            failPendingSelection();
        }
    }

    const std::uint64_t generation = remoteTransfer_.generation();
    if (!remoteTransfer_.synchronized() || generation == 0)
    {
        releaseNativeOwnership();
        return false;
    }
    if (yieldedGeneration_ == generation && !ownsClipboard_)
    {
        // No timer or same-generation retry may fight a local desktop owner.
        return false;
    }

    if (fileHandoffGeneration_ != 0U &&
        fileHandoffGeneration_ != generation)
    {
        clearFileHandoff();
    }

    const bool textOffered = remoteTextOffered();
    const bool pngOffered = remotePngFormatId() != 0;
    const bool fileOffered = fileHandoffAvailable();
    if (!textOffered && !pngOffered && !fileOffered)
    {
        releaseNativeOwnership();
        return false;
    }
    if (ownsClipboard_ && publicationGeneration_ == generation &&
        textOffered_ == textOffered && pngOffered_ == pngOffered &&
        fileOffered_ == fileOffered)
    {
        return true;
    }
    if (ownershipEpoch_ == std::numeric_limits<std::uint64_t>::max())
    {
        releaseNativeOwnership();
        valid_ = false;
        return false;
    }

    lastOwnershipTransitionSource_ = Source::SelfGeneratedNativeTransition;
    if (!nativeOperations_.setSelectionOwner(
            nativeOperations_.context, ownerWindow_, atoms_.clipboard) ||
        nativeOperations_.selectionOwner(
            nativeOperations_.context, atoms_.clipboard) != ownerWindow_)
    {
        ownsClipboard_ = false;
        clearPublicationState();
        return false;
    }

    ++ownershipEpoch_;
    publicationGeneration_ = generation;
    textOffered_ = textOffered;
    pngOffered_ = pngOffered;
    fileOffered_ = fileOffered;
    ownsClipboard_ = true;
    yieldedGeneration_ = 0;
    contentSource_ = Source::RemoteRdp;
    return true;
}

xcb_atom_t
X11ClipboardAdapter::requestProperty(
    const xcb_selection_request_event_t &request) const noexcept
{
    // ICCCM compatibility for obsolete requestors using property=None.
    return request.property == XCB_ATOM_NONE ? request.target : request.property;
}

void
X11ClipboardAdapter::handle(const xcb_generic_event_t &event) noexcept
{
    handleAt(event, PasteClock::now());
}

void
X11ClipboardAdapter::handleAt(const xcb_generic_event_t &event,
                              PasteClock::time_point now) noexcept
{
    if (!valid())
    {
        return;
    }

    switch (event.response_type & 0x7fU)
    {
        case XCB_SELECTION_REQUEST:
            handleSelectionRequest(
                reinterpret_cast<const xcb_selection_request_event_t &>(event),
                now);
            break;
        case XCB_SELECTION_CLEAR:
            handleSelectionClear(
                reinterpret_cast<const xcb_selection_clear_event_t &>(event));
            break;
        case XCB_PROPERTY_NOTIFY:
            handlePropertyNotify(
                reinterpret_cast<const xcb_property_notify_event_t &>(event),
                now);
            break;
        case XCB_DESTROY_NOTIFY:
            handleDestroyNotify(
                reinterpret_cast<const xcb_destroy_notify_event_t &>(event));
            break;
        default:
            break;
    }
}

void
X11ClipboardAdapter::handleSelectionRequest(
    const xcb_selection_request_event_t &request,
    PasteClock::time_point now) noexcept
{
    if (!currentPublicationValid() || request.owner != ownerWindow_ ||
        request.selection != atoms_.clipboard || incr_.active)
    {
        (void)sendFailureNotify(request);
        return;
    }

    const xcb_atom_t property = requestProperty(request);
    if (property == XCB_ATOM_NONE)
    {
        (void)sendFailureNotify(request);
        return;
    }
    if (request.target == atoms_.targets)
    {
        (void)publishTargets(request, property);
        return;
    }
    if (request.target == atoms_.utf8String && textOffered_)
    {
        const auto text = remoteTransfer_.verifiedUnicodeText();
        if (text)
        {
            (void)publishText(request, property, *text, now);
            return;
        }
        beginDelayedRequest(request, property,
                            RemoteTransfer::PasteKind::UnicodeText,
                            rdp_server::clipboard::kFormatUnicodeText, now);
        return;
    }
    if (request.target == atoms_.png && pngOffered_)
    {
        const auto image = remoteTransfer_.verifiedImage();
        const std::uint32_t pngFormatId = remotePngFormatId();
        if (image &&
            image->format == RemoteTransfer::VerifiedImageFormat::Png &&
            image->generation == publicationGeneration_ &&
            image->sourceFormatId == pngFormatId)
        {
            (void)publishPng(request, property, *image, now);
            return;
        }
        beginDelayedRequest(request, property, RemoteTransfer::PasteKind::Png,
                            pngFormatId, now);
        return;
    }
    if (request.target == atoms_.uriList && fileOffered_)
    {
        (void)publishUriList(request, property);
        return;
    }
    if (request.target == atoms_.gnomeCopiedFiles && fileOffered_)
    {
        (void)publishGnomeCopiedFiles(request, property);
        return;
    }
    if (request.target == atoms_.kdeCutSelection && fileOffered_)
    {
        (void)publishKdeCopyMarker(request, property);
        return;
    }

    (void)sendFailureNotify(request);
}

void
X11ClipboardAdapter::beginDelayedRequest(
    const xcb_selection_request_event_t &request, xcb_atom_t property,
    RemoteTransfer::PasteKind kind, std::uint32_t remoteFormatId,
    PasteClock::time_point now) noexcept
{
    if (pending_.active || remoteFormatId == 0)
    {
        (void)sendFailureNotify(request);
        return;
    }

    const auto receipt = remoteTransfer_.beginPasteRequest(
        kind, now, now + kPasteTimeout);
    if (!receipt || receipt->generation != publicationGeneration_)
    {
        (void)sendFailureNotify(request);
        return;
    }

    pending_.request = request;
    pending_.property = property;
    pending_.publicationGeneration = publicationGeneration_;
    pending_.ownershipEpoch = ownershipEpoch_;
    pending_.pasteSequence = receipt->sequence;
    pending_.remoteFormatId = remoteFormatId;
    pending_.kind = kind;
    pending_.remoteFetchStarted = false;
    pending_.active = true;
}

std::optional<X11ClipboardAdapter::RemoteFetchRequest>
X11ClipboardAdapter::pendingRemoteFetch() const noexcept
{
    if (!pending_.active || pending_.remoteFetchStarted ||
        !currentPublicationValid() ||
        pending_.publicationGeneration != publicationGeneration_ ||
        pending_.ownershipEpoch != ownershipEpoch_)
    {
        return std::nullopt;
    }
    return RemoteFetchRequest{
        pending_.pasteSequence,
        pending_.publicationGeneration,
        pending_.remoteFormatId,
        pending_.kind,
    };
}

bool
X11ClipboardAdapter::markRemoteFetchStarted(
    std::uint64_t pasteSequence) noexcept
{
    if (!pending_.active || pending_.remoteFetchStarted || pasteSequence == 0 ||
        pasteSequence != pending_.pasteSequence)
    {
        return false;
    }
    pending_.remoteFetchStarted = true;
    return true;
}

bool
X11ClipboardAdapter::publishTargets(
    const xcb_selection_request_event_t &request,
    xcb_atom_t property) noexcept
{
    std::array<xcb_atom_t, 6> targets{};
    std::size_t count = 0;
    targets[count++] = atoms_.targets;
    if (textOffered_)
    {
        targets[count++] = atoms_.utf8String;
    }
    if (pngOffered_)
    {
        targets[count++] = atoms_.png;
    }
    if (fileOffered_)
    {
        targets[count++] = atoms_.uriList;
        targets[count++] = atoms_.gnomeCopiedFiles;
        targets[count++] = atoms_.kdeCutSelection;
    }
    const auto bytes =
        std::as_bytes(std::span<const xcb_atom_t>{targets.data(), count});
    return publishPropertyAndNotify(
        request, property, XCB_ATOM_ATOM, 32, bytes);
}

bool
X11ClipboardAdapter::publishText(
    const xcb_selection_request_event_t &request, xcb_atom_t property,
    std::string_view text, PasteClock::time_point now) noexcept
{
    const auto bytes =
        std::as_bytes(std::span<const char>{text.data(), text.size()});
    if (bytes.size() > kMaximumDirectPropertyBytes)
    {
        return beginIncrTransfer(
            request, property, atoms_.utf8String, bytes, now);
    }
    return publishPropertyAndNotify(
        request, property, atoms_.utf8String, 8, bytes);
}

bool
X11ClipboardAdapter::publishPng(
    const xcb_selection_request_event_t &request, xcb_atom_t property,
    const RemoteTransfer::VerifiedImage &image,
    PasteClock::time_point now) noexcept
{
    if (image.format != RemoteTransfer::VerifiedImageFormat::Png ||
        image.generation != publicationGeneration_ ||
        image.sourceFormatId != remotePngFormatId())
    {
        return sendFailureNotify(request);
    }

    const auto bytes = std::as_bytes(image.bytes);
    if (bytes.size() > kMaximumDirectPropertyBytes)
    {
        return beginIncrTransfer(
            request, property, atoms_.png, bytes, now);
    }
    return publishPropertyAndNotify(
        request, property, atoms_.png, 8, bytes);
}

bool
X11ClipboardAdapter::publishUriList(
    const xcb_selection_request_event_t &request,
    xcb_atom_t property) noexcept
{
    if (!fileOffered_ || !fileHandoffAvailable())
    {
        return sendFailureNotify(request);
    }

    std::array<
        char, kMaximumFileHandoffBytes + kMaximumCompletedFiles + 1U>
        payload{};
    std::size_t payloadBytes = 0U;
    for (std::size_t index = 0; index < fileUriListLength_; ++index)
    {
        if (fileUriList_[index] == '\n')
        {
            payload[payloadBytes++] = '\r';
            payload[payloadBytes++] = '\n';
            continue;
        }
        payload[payloadBytes++] = fileUriList_[index];
    }
    payload[payloadBytes++] = '\r';
    payload[payloadBytes++] = '\n';
    return publishPropertyAndNotify(
        request, property, atoms_.uriList, 8,
        std::as_bytes(std::span<const char>{
            payload.data(), payloadBytes}));
}

bool
X11ClipboardAdapter::publishGnomeCopiedFiles(
    const xcb_selection_request_event_t &request,
    xcb_atom_t property) noexcept
{
    if (!fileOffered_ || !fileHandoffAvailable())
    {
        return sendFailureNotify(request);
    }

    constexpr std::array<char, 5> kCopyPrefix{
        'c', 'o', 'p', 'y', '\n'};
    std::array<char, kMaximumFileHandoffBytes + kCopyPrefix.size()> payload{};
    std::copy(
        kCopyPrefix.begin(), kCopyPrefix.end(),
        payload.begin());
    std::copy_n(
        fileUriList_.begin(), fileUriListLength_,
        payload.begin() + kCopyPrefix.size());
    return publishPropertyAndNotify(
        request, property, atoms_.gnomeCopiedFiles, 8,
        std::as_bytes(std::span<const char>{
            payload.data(), kCopyPrefix.size() + fileUriListLength_}));
}

bool
X11ClipboardAdapter::publishKdeCopyMarker(
    const xcb_selection_request_event_t &request,
    xcb_atom_t property) noexcept
{
    if (!fileOffered_ || !fileHandoffAvailable())
    {
        return sendFailureNotify(request);
    }

    constexpr std::array<char, 1> kCopyMarker{'0'};
    return publishPropertyAndNotify(
        request, property, atoms_.kdeCutSelection, 8,
        std::as_bytes(std::span<const char>{
            kCopyMarker.data(), kCopyMarker.size()}));
}

bool
X11ClipboardAdapter::beginIncrTransfer(
    const xcb_selection_request_event_t &request, xcb_atom_t property,
    xcb_atom_t propertyType, std::span<const std::byte> bytes,
    PasteClock::time_point now) noexcept
{
    if (incr_.active || !currentPublicationValid() ||
        bytes.size() <= kMaximumDirectPropertyBytes ||
        bytes.size() > std::numeric_limits<std::uint32_t>::max())
    {
        return sendFailureNotify(request);
    }

    std::uint32_t previousEventMask = 0;
    if (!nativeOperations_.selectTransferEvents(
            nativeOperations_.context, request.requestor, previousEventMask))
    {
        return sendFailureNotify(request);
    }

    const std::uint32_t totalBytes = static_cast<std::uint32_t>(bytes.size());
    const auto sizeBytes =
        std::as_bytes(std::span<const std::uint32_t>{&totalBytes, 1});
    if (!nativeOperations_.changeProperty(
            nativeOperations_.context, request.requestor, property,
            atoms_.incr, 32, sizeBytes))
    {
        (void)nativeOperations_.restoreEventMask(
            nativeOperations_.context, request.requestor, previousEventMask);
        return sendFailureNotify(request);
    }
    if (!sendNotify(request, property))
    {
        (void)nativeOperations_.deleteProperty(
            nativeOperations_.context, request.requestor, property);
        (void)nativeOperations_.restoreEventMask(
            nativeOperations_.context, request.requestor, previousEventMask);
        return false;
    }

    incr_.request = request;
    incr_.property = property;
    incr_.propertyType = propertyType;
    incr_.bytes = bytes;
    incr_.offset = 0;
    incr_.previousEventMask = previousEventMask;
    incr_.deadline = now + kIncrTimeout;
    incr_.publicationGeneration = publicationGeneration_;
    incr_.ownershipEpoch = ownershipEpoch_;
    incr_.active = true;
    return true;
}

bool
X11ClipboardAdapter::serviceIncrTransfer(
    PasteClock::time_point now) noexcept
{
    if (!incr_.active)
    {
        return true;
    }
    if (now >= incr_.deadline || !currentPublicationValid() ||
        incr_.publicationGeneration != publicationGeneration_ ||
        incr_.ownershipEpoch != ownershipEpoch_)
    {
        cancelIncrTransfer(false);
    }
    return true;
}

void
X11ClipboardAdapter::handlePropertyNotify(
    const xcb_property_notify_event_t &property,
    PasteClock::time_point now) noexcept
{
    if (!incr_.active || property.window != incr_.request.requestor ||
        property.atom != incr_.property ||
        property.state != XCB_PROPERTY_DELETE)
    {
        return;
    }
    (void)serviceIncrTransfer(now);
    if (!incr_.active)
    {
        return;
    }

    if (incr_.offset < incr_.bytes.size())
    {
        const std::size_t remaining = incr_.bytes.size() - incr_.offset;
        const std::size_t chunkBytes =
            (std::min)(remaining, kIncrChunkBytes);
        const auto chunk = incr_.bytes.subspan(incr_.offset, chunkBytes);
        if (!nativeOperations_.changeProperty(
                nativeOperations_.context, incr_.request.requestor,
                incr_.property, incr_.propertyType, 8, chunk))
        {
            cancelIncrTransfer(false);
            return;
        }
        incr_.offset += chunkBytes;
        incr_.deadline = now + kIncrTimeout;
        return;
    }

    if (!nativeOperations_.changeProperty(
            nativeOperations_.context, incr_.request.requestor,
            incr_.property, incr_.propertyType, 8, {}))
    {
        cancelIncrTransfer(false);
        return;
    }
    cancelIncrTransfer(false);
}

void
X11ClipboardAdapter::handleDestroyNotify(
    const xcb_destroy_notify_event_t &destroy) noexcept
{
    if (incr_.active && destroy.window == incr_.request.requestor)
    {
        cancelIncrTransfer(true);
    }
}

void
X11ClipboardAdapter::cancelIncrTransfer(bool requestorDestroyed) noexcept
{
    if (!incr_.active)
    {
        return;
    }

    const IncrTransfer cancelled = incr_;
    incr_ = {};
    if (!requestorDestroyed)
    {
        (void)nativeOperations_.restoreEventMask(
            nativeOperations_.context, cancelled.request.requestor,
            cancelled.previousEventMask);
    }
}

bool
X11ClipboardAdapter::publishPropertyAndNotify(
    const xcb_selection_request_event_t &request,
    xcb_atom_t property, xcb_atom_t propertyType, std::uint8_t format,
    std::span<const std::byte> bytes) noexcept
{
    if (bytes.size() > kMaximumDirectPropertyBytes ||
        !nativeOperations_.changeProperty(
            nativeOperations_.context, request.requestor, property,
            propertyType, format, bytes))
    {
        return sendFailureNotify(request);
    }
    return sendNotify(request, property);
}

bool
X11ClipboardAdapter::sendNotify(
    const xcb_selection_request_event_t &request,
    xcb_atom_t property) noexcept
{
    xcb_selection_notify_event_t notify{};
    notify.response_type = XCB_SELECTION_NOTIFY;
    notify.sequence = 0;
    notify.time = request.time;
    notify.requestor = request.requestor;
    notify.selection = request.selection;
    notify.target = request.target;
    notify.property = property;
    return nativeOperations_.sendSelectionNotify(
        nativeOperations_.context, notify);
}

bool
X11ClipboardAdapter::sendFailureNotify(
    const xcb_selection_request_event_t &request) noexcept
{
    return sendNotify(request, XCB_ATOM_NONE);
}

bool
X11ClipboardAdapter::servicePendingPaste(
    PasteClock::time_point now) noexcept
{
    (void)serviceIncrTransfer(now);
    if (!pending_.active)
    {
        return true;
    }

    const auto result =
        remoteTransfer_.pollPasteRequest(pending_.pasteSequence, now);
    if (result.status == RemoteTransfer::PasteStatus::Pending)
    {
        return true;
    }

    const PendingSelectionRequest completed = pending_;
    pending_ = {};
    if (result.sequence != completed.pasteSequence ||
        result.generation != completed.publicationGeneration ||
        completed.publicationGeneration != publicationGeneration_ ||
        completed.ownershipEpoch != ownershipEpoch_ ||
        !currentPublicationValid())
    {
        return sendFailureNotify(completed.request);
    }

    if (result.status == RemoteTransfer::PasteStatus::ReadyUnicodeText &&
        completed.kind == RemoteTransfer::PasteKind::UnicodeText)
    {
        return publishText(
            completed.request, completed.property, result.text, now);
    }
    if (result.status == RemoteTransfer::PasteStatus::ReadyImage &&
        completed.kind == RemoteTransfer::PasteKind::Png && result.image &&
        result.image->format == RemoteTransfer::VerifiedImageFormat::Png &&
        result.image->sourceFormatId == completed.remoteFormatId)
    {
        return publishPng(
            completed.request, completed.property, *result.image, now);
    }

    return sendFailureNotify(completed.request);
}

void
X11ClipboardAdapter::failPendingSelection() noexcept
{
    if (!pending_.active)
    {
        return;
    }
    const auto request = pending_.request;
    pending_ = {};
    (void)sendFailureNotify(request);
}

void
X11ClipboardAdapter::cancelPendingForOwnerLoss() noexcept
{
    if (!pending_.active)
    {
        return;
    }

    const PendingSelectionRequest cancelled = pending_;
    (void)remoteTransfer_.cancelPasteRequestForOwnerLoss(
        cancelled.pasteSequence);
    // Consume OwnerLost or an already-terminal replacement/disconnect using
    // this exact sequence. A stale sequence remains a no-op.
    (void)remoteTransfer_.pollPasteRequest(
        cancelled.pasteSequence, PasteClock::time_point{});
    pending_ = {};
    (void)sendFailureNotify(cancelled.request);
}

void
X11ClipboardAdapter::handleSelectionClear(
    const xcb_selection_clear_event_t &clear) noexcept
{
    if (!ownsClipboard_ || clear.owner != ownerWindow_ ||
        clear.selection != atoms_.clipboard)
    {
        return;
    }
    yieldToLocalOwner();
}

void
X11ClipboardAdapter::observeClipboardOwner(xcb_window_t owner) noexcept
{
    if (!ownsClipboard_ || owner == ownerWindow_)
    {
        return;
    }
    yieldToLocalOwner();
}

void
X11ClipboardAdapter::yieldToLocalOwner() noexcept
{
    if (!ownsClipboard_)
    {
        return;
    }
    cancelPendingForOwnerLoss();
    cancelIncrTransfer(false);
    yieldedGeneration_ = publicationGeneration_;
    ownsClipboard_ = false;
    publicationGeneration_ = 0;
    textOffered_ = false;
    pngOffered_ = false;
    fileOffered_ = false;
    clearFileHandoff();
    contentSource_ = Source::LocalNative;
    lastOwnershipTransitionSource_ = Source::LocalNative;
}

void
X11ClipboardAdapter::clearFileHandoff() noexcept
{
    fileUriList_.fill(0);
    fileUriListLength_ = 0;
    fileHandoffFileCount_ = 0;
    fileHandoffGeneration_ = 0;
    fileOffered_ = false;
}

void
X11ClipboardAdapter::clearPublicationState() noexcept
{
    publicationGeneration_ = 0;
    textOffered_ = false;
    pngOffered_ = false;
    clearFileHandoff();
    if (!ownsClipboard_)
    {
        contentSource_ = Source::None;
    }
}

void
X11ClipboardAdapter::releaseNativeOwnership() noexcept
{
    if (!valid())
    {
        return;
    }
    if (pending_.active)
    {
        cancelPendingForOwnerLoss();
    }
    cancelIncrTransfer(false);

    if (ownsClipboard_)
    {
        lastOwnershipTransitionSource_ = Source::SelfGeneratedNativeTransition;
        const xcb_window_t currentOwner = nativeOperations_.selectionOwner(
            nativeOperations_.context, atoms_.clipboard);
        if (currentOwner == ownerWindow_)
        {
            (void)nativeOperations_.setSelectionOwner(
                nativeOperations_.context, XCB_WINDOW_NONE, atoms_.clipboard);
        }
    }
    ownsClipboard_ = false;
    clearPublicationState();
}

void
X11ClipboardAdapter::disconnect() noexcept
{
    if (!valid_ && ownerWindow_ == XCB_WINDOW_NONE)
    {
        return;
    }

    if (valid_)
    {
        releaseNativeOwnership();
    }
    if (ownerWindow_ != XCB_WINDOW_NONE && nativeOperations_.destroyWindow)
    {
        (void)nativeOperations_.destroyWindow(
            nativeOperations_.context, ownerWindow_);
    }

    pending_ = {};
    incr_ = {};
    ownerWindow_ = XCB_WINDOW_NONE;
    rootWindow_ = XCB_WINDOW_NONE;
    atoms_ = {};
    publicationGeneration_ = 0;
    yieldedGeneration_ = 0;
    clearFileHandoff();
    textOffered_ = false;
    pngOffered_ = false;
    fileOffered_ = false;
    ownsClipboard_ = false;
    valid_ = false;
    contentSource_ = Source::None;
}
