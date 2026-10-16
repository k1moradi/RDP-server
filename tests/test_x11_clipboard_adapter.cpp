// SPDX-License-Identifier: GPL-3.0-or-later

#include "clipboard/clipboard_protocol.h"
#include "server/clipboard/remote_transfer.h"
#include "x11/x11_clipboard_adapter.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using RemoteTransfer = rdp_server::server::clipboard::RemoteTransfer;
using Clock = RemoteTransfer::PasteClock;

constexpr xcb_atom_t kClipboardAtom = 101;
constexpr xcb_atom_t kTargetsAtom = 102;
constexpr xcb_atom_t kUtf8Atom = 103;
constexpr xcb_atom_t kPngAtom = 104;
constexpr xcb_atom_t kIncrAtom = 105;
constexpr xcb_window_t kOwnerWindow = 501;
constexpr xcb_window_t kRootWindow = 1;
constexpr xcb_window_t kRequestorWindow = 701;
constexpr xcb_atom_t kPropertyAtom = 801;
constexpr std::uint32_t kPngFormatId = 0xc001;

constexpr std::array<std::uint8_t, 70> kValidPng{
    0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,
    0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,
    0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
    0x08,0x06,0x00,0x00,0x00,0x1f,0x15,0xc4,0x89,
    0x00,0x00,0x00,0x0d,0x49,0x44,0x41,0x54,
    0x78,0x9c,0x63,0xf8,0xcf,0xc0,0xf0,0x1f,0x00,
    0x05,0x00,0x01,0xff,0x89,0x99,0x3d,0x1d,
    0x00,0x00,0x00,0x00,0x49,0x45,0x4e,0x44,
    0xae,0x42,0x60,0x82};

struct PropertyWrite
{
    xcb_window_t window{};
    xcb_atom_t property{};
    xcb_atom_t type{};
    std::uint8_t format{};
    std::vector<std::byte> bytes{};
};

struct FakeNative
{
    std::vector<std::string> internedNames{};
    std::vector<PropertyWrite> propertyWrites{};
    std::vector<xcb_selection_notify_event_t> notifications{};
    xcb_window_t currentSelectionOwner{};
    std::size_t createWindowCalls{};
    std::size_t destroyWindowCalls{};
    std::size_t setOwnerCalls{};
    std::size_t selectTransferEventsCalls{};
    std::size_t restoreEventMaskCalls{};
    std::size_t deletePropertyCalls{};
    std::uint32_t currentEventMask{
        static_cast<std::uint32_t>(XCB_EVENT_MASK_ENTER_WINDOW)};
    bool failPropertyWrite{};
    bool failNotification{};

    static FakeNative &self(void *context) noexcept
    {
        return *static_cast<FakeNative *>(context);
    }

    static xcb_atom_t internAtom(void *context, std::string_view name) noexcept
    {
        auto &state = self(context);
        state.internedNames.emplace_back(name);
        if (name == "CLIPBOARD") return kClipboardAtom;
        if (name == "TARGETS") return kTargetsAtom;
        if (name == "UTF8_STRING") return kUtf8Atom;
        if (name == "image/png") return kPngAtom;
        if (name == "INCR") return kIncrAtom;
        return XCB_ATOM_NONE;
    }

    static xcb_window_t createOwnerWindow(void *context,
                                          xcb_window_t rootWindow) noexcept
    {
        auto &state = self(context);
        ++state.createWindowCalls;
        return rootWindow == kRootWindow ? kOwnerWindow : xcb_window_t{};
    }

    static bool destroyWindow(void *context, xcb_window_t window) noexcept
    {
        auto &state = self(context);
        if (window != kOwnerWindow) return false;
        ++state.destroyWindowCalls;
        if (state.currentSelectionOwner == window)
            state.currentSelectionOwner = XCB_WINDOW_NONE;
        return true;
    }

    static bool setSelectionOwner(void *context, xcb_window_t owner,
                                  xcb_atom_t selection) noexcept
    {
        auto &state = self(context);
        if (selection != kClipboardAtom) return false;
        ++state.setOwnerCalls;
        state.currentSelectionOwner = owner;
        return true;
    }

    static xcb_window_t selectionOwner(void *context,
                                       xcb_atom_t selection) noexcept
    {
        return selection == kClipboardAtom
                   ? self(context).currentSelectionOwner
                   : xcb_window_t{};
    }

    static bool changeProperty(void *context, xcb_window_t window,
                               xcb_atom_t property, xcb_atom_t type,
                               std::uint8_t format,
                               std::span<const std::byte> bytes) noexcept
    {
        auto &state = self(context);
        if (state.failPropertyWrite) return false;
        try
        {
            state.propertyWrites.push_back(
                PropertyWrite{window, property, type, format,
                              std::vector<std::byte>{bytes.begin(), bytes.end()}});
        }
        catch (...)
        {
            return false;
        }
        return true;
    }

    static bool selectTransferEvents(
        void *context, xcb_window_t window,
        std::uint32_t &previousEventMask) noexcept
    {
        auto &state = self(context);
        if (window != kRequestorWindow) return false;
        ++state.selectTransferEventsCalls;
        previousEventMask = state.currentEventMask;
        state.currentEventMask |=
            static_cast<std::uint32_t>(XCB_EVENT_MASK_PROPERTY_CHANGE) |
            static_cast<std::uint32_t>(XCB_EVENT_MASK_STRUCTURE_NOTIFY);
        return true;
    }

    static bool restoreEventMask(
        void *context, xcb_window_t window, std::uint32_t eventMask) noexcept
    {
        auto &state = self(context);
        if (window != kRequestorWindow) return false;
        ++state.restoreEventMaskCalls;
        state.currentEventMask = eventMask;
        return true;
    }

    static bool deleteProperty(
        void *context, xcb_window_t window, xcb_atom_t property) noexcept
    {
        auto &state = self(context);
        if (window != kRequestorWindow || property == XCB_ATOM_NONE)
            return false;
        ++state.deletePropertyCalls;
        return true;
    }

    static bool sendSelectionNotify(
        void *context, const xcb_selection_notify_event_t &notify) noexcept
    {
        auto &state = self(context);
        if (state.failNotification) return false;
        try
        {
            state.notifications.push_back(notify);
        }
        catch (...)
        {
            return false;
        }
        return true;
    }

    X11ClipboardNativeOperations operations() noexcept
    {
        return X11ClipboardNativeOperations{
            this, internAtom, createOwnerWindow, destroyWindow,
            setSelectionOwner, selectionOwner, changeProperty,
            selectTransferEvents, restoreEventMask, deleteProperty,
            sendSelectionNotify};
    }
};

void appendLongFormat(std::vector<std::uint8_t> &payload,
                      std::uint32_t formatId, std::string_view name)
{
    for (unsigned shift = 0; shift < 32; shift += 8)
        payload.push_back(static_cast<std::uint8_t>(formatId >> shift));
    for (const char character : name)
    {
        payload.push_back(static_cast<std::uint8_t>(character));
        payload.push_back(0);
    }
    payload.push_back(0);
    payload.push_back(0);
}

std::vector<std::uint8_t> longFormatPdu(
    std::span<const std::uint8_t> payload)
{
    std::vector<std::uint8_t> wire;
    assert(rdp_server::clipboard::encodePdu(
        rdp_server::clipboard::kFormatList, 0, payload, wire));
    return wire;
}

std::vector<std::uint8_t> responsePdu(
    std::span<const std::uint8_t> payload)
{
    std::vector<std::uint8_t> wire;
    assert(rdp_server::clipboard::encodePdu(
        rdp_server::clipboard::kFormatDataResponse,
        rdp_server::clipboard::kResponseOk, payload, wire));
    return wire;
}

void offerTextAndPng(RemoteTransfer &transfer, bool includeDib = false)
{
    std::vector<std::uint8_t> formats;
    appendLongFormat(formats, rdp_server::clipboard::kFormatUnicodeText, "");
    appendLongFormat(formats, kPngFormatId, "PNG");
    if (includeDib) appendLongFormat(formats, 8, "");
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(formats)));
}

void storeText(RemoteTransfer &transfer, std::string_view text)
{
    std::vector<std::uint8_t> wire;
    wire.reserve(text.size() * 2U + 2U);
    for (const unsigned char character : text)
    {
        wire.push_back(character);
        wire.push_back(0);
    }
    wire.push_back(0);
    wire.push_back(0);

    std::vector<std::uint8_t> request;
    assert(transfer.beginRequest(
        rdp_server::clipboard::kFormatUnicodeText, request));
    const auto responseWire = responsePdu(wire);
    const auto response = transfer.receiveResponse(responseWire);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(transfer.storeVerifiedUnicodeText(response));
}

void storePngPayload(RemoteTransfer &transfer,
                     std::span<const std::uint8_t> png)
{
    std::vector<std::uint8_t> request;
    assert(transfer.beginRequest(kPngFormatId, request));
    const auto responseWire = responsePdu(png);
    const auto response = transfer.receiveResponse(responseWire);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(transfer.storeVerifiedImage(response));
}

void storePng(RemoteTransfer &transfer)
{
    storePngPayload(transfer, kValidPng);
}

std::vector<std::uint8_t> largeValidPng()
{
    constexpr std::size_t kPngPrefixBytes = 33;
    constexpr std::size_t kIdatChunkBytes = 25;
    constexpr std::size_t kIendChunkBytes = 12;
    constexpr std::size_t kRepeatedIdatChunks = 3000;

    std::vector<std::uint8_t> result;
    result.reserve(kPngPrefixBytes +
                   kRepeatedIdatChunks * kIdatChunkBytes +
                   kIendChunkBytes);
    result.insert(result.end(), kValidPng.begin(),
                  kValidPng.begin() + kPngPrefixBytes);
    for (std::size_t index = 0; index < kRepeatedIdatChunks; ++index)
    {
        result.insert(result.end(),
                      kValidPng.begin() + kPngPrefixBytes,
                      kValidPng.begin() + kPngPrefixBytes +
                          kIdatChunkBytes);
    }
    result.insert(result.end(),
                  kValidPng.end() - kIendChunkBytes, kValidPng.end());
    return result;
}

void storeDib(RemoteTransfer &transfer)
{
    std::array<std::uint8_t, 44> dib{};
    dib[0] = 40;
    dib[4] = 1;
    dib[8] = 1;
    dib[12] = 1;
    dib[14] = 32;
    dib[20] = 4;
    dib[40] = 0x11;
    dib[41] = 0x22;
    dib[42] = 0x33;
    dib[43] = 0xff;

    std::vector<std::uint8_t> request;
    assert(transfer.beginRequest(8, request));
    const auto responseWire = responsePdu(dib);
    const auto response = transfer.receiveResponse(responseWire);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(transfer.storeVerifiedImage(response));
    assert(transfer.verifiedImage()->format ==
           RemoteTransfer::VerifiedImageFormat::Dib);
}

xcb_selection_request_event_t requestFor(xcb_atom_t target,
                                         xcb_atom_t property = kPropertyAtom,
                                         xcb_timestamp_t time = 7)
{
    xcb_selection_request_event_t request{};
    request.response_type = XCB_SELECTION_REQUEST;
    request.time = time;
    request.owner = kOwnerWindow;
    request.requestor = kRequestorWindow;
    request.selection = kClipboardAtom;
    request.target = target;
    request.property = property;
    return request;
}

template <typename Event>
xcb_generic_event_t genericEvent(const Event &event)
{
    static_assert(sizeof(Event) <= sizeof(xcb_generic_event_t));
    xcb_generic_event_t generic{};
    std::memcpy(&generic, &event, sizeof(Event));
    return generic;
}

void dispatchRequest(X11ClipboardAdapter &adapter,
                     const xcb_selection_request_event_t &request,
                     Clock::time_point now)
{
    const auto event = genericEvent(request);
    adapter.handleAt(event, now);
}

void dispatchPropertyDelete(X11ClipboardAdapter &adapter,
                            xcb_atom_t property,
                            Clock::time_point now,
                            xcb_window_t window = kRequestorWindow)
{
    xcb_property_notify_event_t notify{};
    notify.response_type = XCB_PROPERTY_NOTIFY;
    notify.window = window;
    notify.atom = property;
    notify.time = 1;
    notify.state = XCB_PROPERTY_DELETE;
    const auto event = genericEvent(notify);
    adapter.handleAt(event, now);
}

void dispatchDestroy(X11ClipboardAdapter &adapter,
                     xcb_window_t window,
                     Clock::time_point now)
{
    xcb_destroy_notify_event_t destroy{};
    destroy.response_type = XCB_DESTROY_NOTIFY;
    destroy.event = window;
    destroy.window = window;
    const auto event = genericEvent(destroy);
    adapter.handleAt(event, now);
}

std::vector<xcb_atom_t> propertyAtoms(const PropertyWrite &write)
{
    assert(write.format == 32);
    assert(write.bytes.size() % sizeof(xcb_atom_t) == 0);
    std::vector<xcb_atom_t> atoms(write.bytes.size() / sizeof(xcb_atom_t));
    std::memcpy(atoms.data(), write.bytes.data(), write.bytes.size());
    return atoms;
}

std::uint32_t propertyUint32(const PropertyWrite &write)
{
    assert(write.format == 32);
    assert(write.bytes.size() == sizeof(std::uint32_t));
    std::uint32_t value = 0;
    std::memcpy(&value, write.bytes.data(), sizeof(value));
    return value;
}

std::string propertyText(const PropertyWrite &write)
{
    assert(write.format == 8);
    return std::string(
        reinterpret_cast<const char *>(write.bytes.data()),
        write.bytes.size());
}

void selectionOwnershipGeneration()
{
    RemoteTransfer transfer;
    FakeNative native;
    X11ClipboardAdapter adapter(transfer, native.operations(), kRootWindow);
    assert(adapter.valid());
    assert(adapter.clipboardAtom() == kClipboardAtom);
    assert(std::find(native.internedNames.begin(), native.internedNames.end(),
                     "PRIMARY") == native.internedNames.end());

    const Clock::time_point start{std::chrono::seconds{1}};
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    assert(adapter.publishCurrentRemoteOffer(start));
    assert(adapter.ownsClipboard());
    assert(adapter.publicationGeneration() == transfer.generation());
    assert(adapter.ownershipEpoch() == 1);
    assert(adapter.contentSource() == X11ClipboardAdapter::Source::RemoteRdp);
    assert(adapter.lastOwnershipTransitionSource() ==
           X11ClipboardAdapter::Source::SelfGeneratedNativeTransition);

    const std::size_t firstSetCount = native.setOwnerCalls;
    adapter.observeClipboardOwner(kOwnerWindow);
    assert(adapter.ownsClipboard());
    assert(adapter.publishCurrentRemoteOffer(start));
    assert(native.setOwnerCalls == firstSetCount);

    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    assert(adapter.publishCurrentRemoteOffer(start));
    assert(adapter.ownershipEpoch() == 2);
    assert(adapter.publicationGeneration() == 2);

    native.currentSelectionOwner = 999;
    adapter.observeClipboardOwner(999);
    assert(!adapter.ownsClipboard());
    assert(adapter.contentSource() == X11ClipboardAdapter::Source::LocalNative);
    const std::size_t localTakeoverSetCount = native.setOwnerCalls;
    assert(!adapter.publishCurrentRemoteOffer(start));
    assert(native.setOwnerCalls == localTakeoverSetCount);

    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    assert(adapter.publishCurrentRemoteOffer(start));
    assert(adapter.ownershipEpoch() == 3);
    assert(adapter.publicationGeneration() == 3);

    adapter.disconnect();
    adapter.disconnect();
    assert(!adapter.valid());
    assert(native.destroyWindowCalls == 1);
}

void targetsPublication()
{
    RemoteTransfer transfer;
    offerTextAndPng(transfer, true);
    FakeNative native;
    X11ClipboardAdapter adapter(transfer, native.operations(), kRootWindow);
    const Clock::time_point start{std::chrono::seconds{2}};
    assert(adapter.publishCurrentRemoteOffer(start));

    dispatchRequest(adapter, requestFor(kTargetsAtom), start);
    assert(native.propertyWrites.size() == 1);
    assert(native.notifications.size() == 1);
    const auto atoms = propertyAtoms(native.propertyWrites.back());
    assert((atoms ==
            std::vector<xcb_atom_t>{kTargetsAtom, kUtf8Atom, kPngAtom}));
    assert(native.propertyWrites.back().type == XCB_ATOM_ATOM);
    assert(native.notifications.back().property == kPropertyAtom);

    storeText(transfer, "hello\n");
    dispatchRequest(adapter, requestFor(kUtf8Atom), start);
    assert(native.propertyWrites.size() == 2);
    assert(native.propertyWrites.back().type == kUtf8Atom);
    assert(propertyText(native.propertyWrites.back()) == "hello\n");

    storePng(transfer);
    dispatchRequest(adapter, requestFor(kPngAtom), start);
    assert(native.propertyWrites.size() == 3);
    assert(native.propertyWrites.back().type == kPngAtom);
    assert(native.propertyWrites.back().bytes.size() == kValidPng.size());
    assert(std::memcmp(native.propertyWrites.back().bytes.data(),
                       kValidPng.data(), kValidPng.size()) == 0);

    // DIB is valid R8 data but is never mislabeled as image/png.
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 2>{
            rdp_server::clipboard::kFormatUnicodeText, 8}));
    assert(adapter.publishCurrentRemoteOffer(start));
    dispatchRequest(adapter, requestFor(kTargetsAtom), start);
    const auto dibOnlyTargets = propertyAtoms(native.propertyWrites.back());
    assert((dibOnlyTargets ==
            std::vector<xcb_atom_t>{kTargetsAtom, kUtf8Atom}));

}

void incrLargeTextProgression()
{
    RemoteTransfer transfer;
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    FakeNative native;
    X11ClipboardAdapter adapter(transfer, native.operations(), kRootWindow);
    const Clock::time_point start{std::chrono::seconds{6}};
    assert(adapter.publishCurrentRemoteOffer(start));

    const std::string largeText(
        X11ClipboardAdapter::kIncrChunkBytes * 2U + 17U, 'x');
    storeText(transfer, largeText);
    dispatchRequest(adapter, requestFor(kUtf8Atom, 841, 41), start);

    assert(adapter.incrAtom() == kIncrAtom);
    assert(adapter.incrTransferActive());
    assert(adapter.incrBytesSent() == 0);
    assert(native.selectTransferEventsCalls == 1);
    assert(native.propertyWrites.size() == 1);
    assert(native.propertyWrites.back().type == kIncrAtom);
    assert(propertyUint32(native.propertyWrites.back()) == largeText.size());
    assert(native.notifications.size() == 1);
    assert(native.notifications.back().property == 841);

    dispatchPropertyDelete(adapter, 999, start);
    assert(native.propertyWrites.size() == 1);

    dispatchPropertyDelete(adapter, 841, start + std::chrono::milliseconds{1});
    assert(native.propertyWrites.back().type == kUtf8Atom);
    assert(native.propertyWrites.back().bytes.size() ==
           X11ClipboardAdapter::kIncrChunkBytes);
    assert(adapter.incrBytesSent() == X11ClipboardAdapter::kIncrChunkBytes);

    dispatchPropertyDelete(adapter, 841, start + std::chrono::milliseconds{2});
    assert(native.propertyWrites.back().bytes.size() ==
           X11ClipboardAdapter::kIncrChunkBytes);
    assert(adapter.incrBytesSent() ==
           X11ClipboardAdapter::kIncrChunkBytes * 2U);

    dispatchPropertyDelete(adapter, 841, start + std::chrono::milliseconds{3});
    assert(native.propertyWrites.back().bytes.size() == 17U);
    assert(adapter.incrBytesSent() == largeText.size());

    dispatchPropertyDelete(adapter, 841, start + std::chrono::milliseconds{4});
    assert(!adapter.incrTransferActive());
    assert(native.propertyWrites.back().bytes.empty());
    assert(native.propertyWrites.back().type == kUtf8Atom);
    assert(native.restoreEventMaskCalls == 1);
    assert(native.currentEventMask ==
           static_cast<std::uint32_t>(XCB_EVENT_MASK_ENTER_WINDOW));
    assert(native.notifications.size() == 1);
}

void incrPngProgression()
{
    RemoteTransfer transfer;
    offerTextAndPng(transfer);
    FakeNative native;
    X11ClipboardAdapter adapter(transfer, native.operations(), kRootWindow);
    const Clock::time_point start{std::chrono::seconds{7}};
    assert(adapter.publishCurrentRemoteOffer(start));

    const auto png = largeValidPng();
    assert(png.size() > X11ClipboardAdapter::kMaximumDirectPropertyBytes);
    storePngPayload(transfer, png);
    dispatchRequest(adapter, requestFor(kPngAtom, 842, 42), start);
    assert(adapter.incrTransferActive());
    assert(native.propertyWrites.size() == 1);
    assert(native.propertyWrites.back().type == kIncrAtom);
    assert(propertyUint32(native.propertyWrites.back()) == png.size());

    std::size_t dataBytes = 0;
    std::size_t iterations = 0;
    while (adapter.incrTransferActive())
    {
        const std::size_t writesBefore = native.propertyWrites.size();
        dispatchPropertyDelete(
            adapter, 842,
            start + std::chrono::milliseconds{
                        static_cast<std::chrono::milliseconds::rep>(
                            ++iterations)});
        assert(native.propertyWrites.size() == writesBefore + 1U);
        const auto &write = native.propertyWrites.back();
        if (!write.bytes.empty())
        {
            assert(write.type == kPngAtom);
            assert(write.bytes.size() <= X11ClipboardAdapter::kIncrChunkBytes);
            dataBytes += write.bytes.size();
        }
        assert(iterations < 16U);
    }
    assert(dataBytes == png.size());
    assert(native.propertyWrites.back().bytes.empty());
    assert(native.propertyWrites.back().type == kPngAtom);
    assert(native.notifications.size() == 1);
    assert(native.restoreEventMaskCalls == 1);
}

void incrCancellation()
{
    RemoteTransfer transfer;
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    FakeNative native;
    X11ClipboardAdapter adapter(transfer, native.operations(), kRootWindow);
    const Clock::time_point start{std::chrono::seconds{8}};
    assert(adapter.publishCurrentRemoteOffer(start));
    const std::string largeText(
        X11ClipboardAdapter::kMaximumDirectPropertyBytes + 1U, 'y');
    storeText(transfer, largeText);

    dispatchRequest(adapter, requestFor(kUtf8Atom, 843, 43), start);
    assert(adapter.incrTransferActive());
    assert(adapter.servicePendingPaste(
        start + X11ClipboardAdapter::kIncrTimeout));
    assert(!adapter.incrTransferActive());
    assert(native.restoreEventMaskCalls == 1);
    assert(native.notifications.size() == 1);

    dispatchRequest(adapter, requestFor(kUtf8Atom, 844, 44), start);
    assert(adapter.incrTransferActive());
    const std::size_t writesBeforeReplacement = native.propertyWrites.size();
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    assert(adapter.publishCurrentRemoteOffer(
        start + std::chrono::milliseconds{1}));
    assert(!adapter.incrTransferActive());
    dispatchPropertyDelete(adapter, 844, start + std::chrono::milliseconds{2});
    assert(native.propertyWrites.size() == writesBeforeReplacement);

    storeText(transfer, largeText);
    dispatchRequest(adapter, requestFor(kUtf8Atom, 845, 45), start);
    assert(adapter.incrTransferActive());
    native.currentSelectionOwner = 999;
    adapter.observeClipboardOwner(999);
    assert(!adapter.incrTransferActive());
    assert(!adapter.ownsClipboard());

    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    assert(adapter.publishCurrentRemoteOffer(start));
    storeText(transfer, largeText);
    dispatchRequest(adapter, requestFor(kUtf8Atom, 846, 46), start);
    assert(adapter.incrTransferActive());
    const std::size_t restoresBeforeDestroy = native.restoreEventMaskCalls;
    dispatchDestroy(adapter, kRequestorWindow, start);
    assert(!adapter.incrTransferActive());
    assert(native.restoreEventMaskCalls == restoresBeforeDestroy);
}

void selectionRequestNonblocking()
{
    RemoteTransfer transfer;
    offerTextAndPng(transfer, true);
    FakeNative native;
    X11ClipboardAdapter adapter(transfer, native.operations(), kRootWindow);
    const Clock::time_point start{std::chrono::seconds{3}};
    assert(adapter.publishCurrentRemoteOffer(start));

    const auto textRequest = requestFor(kUtf8Atom, 811, 11);
    dispatchRequest(adapter, textRequest, start);
    assert(native.propertyWrites.empty());
    assert(native.notifications.empty());
    const auto textFetch = adapter.pendingRemoteFetch();
    assert(textFetch);
    assert(textFetch->generation == transfer.generation());
    assert(textFetch->formatId == rdp_server::clipboard::kFormatUnicodeText);
    assert(textFetch->kind == RemoteTransfer::PasteKind::UnicodeText);

    // One delayed native request only; a second is rejected deterministically.
    dispatchRequest(adapter, requestFor(kPngAtom, 812, 12), start);
    assert(native.notifications.size() == 1);
    assert(native.notifications.back().property == XCB_ATOM_NONE);
    assert(adapter.pendingRemoteFetch()->pasteSequence ==
           textFetch->pasteSequence);

    std::vector<std::uint8_t> request;
    assert(transfer.beginRequest(textFetch->formatId, request));
    assert(adapter.markRemoteFetchStarted(textFetch->pasteSequence));
    const std::array<std::uint8_t, 6> textWire{'O', 0, 'K', 0, 0, 0};
    const auto textResponseWire = responsePdu(textWire);
    const auto textResponse = transfer.receiveResponse(textResponseWire);
    assert(transfer.storeVerifiedUnicodeText(textResponse));
    assert(adapter.servicePendingPaste(start + std::chrono::milliseconds{1}));
    assert(native.propertyWrites.size() == 1);
    assert(propertyText(native.propertyWrites.back()) == "OK");
    assert(native.notifications.size() == 2);
    assert(native.notifications.back().property == 811);
    assert(adapter.servicePendingPaste(start + std::chrono::milliseconds{2}));
    assert(native.notifications.size() == 2);

    // Ready DIB cannot satisfy image/png. Keep waiting for the registered PNG.
    offerTextAndPng(transfer, true);
    assert(adapter.publishCurrentRemoteOffer(start));
    storeDib(transfer);
    dispatchRequest(adapter, requestFor(kPngAtom, 813, 13), start);
    const auto pngFetch = adapter.pendingRemoteFetch();
    assert(pngFetch);
    assert(pngFetch->kind == RemoteTransfer::PasteKind::Png);
    assert(pngFetch->formatId == kPngFormatId);
    assert(adapter.servicePendingPaste(start + std::chrono::milliseconds{1}));
    assert(adapter.pendingRemoteFetch());

    request.clear();
    assert(transfer.beginRequest(kPngFormatId, request));
    assert(adapter.markRemoteFetchStarted(pngFetch->pasteSequence));
    const auto pngResponseWire = responsePdu(kValidPng);
    const auto pngResponse = transfer.receiveResponse(pngResponseWire);
    assert(transfer.storeVerifiedImage(pngResponse));
    assert(adapter.servicePendingPaste(start + std::chrono::milliseconds{2}));
    assert(native.propertyWrites.back().type == kPngAtom);
    assert(native.notifications.back().property == 813);

    // Exact deadline expiry fails once.
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    assert(adapter.publishCurrentRemoteOffer(start));
    dispatchRequest(adapter, requestFor(kUtf8Atom, 814, 14), start);
    const std::size_t beforeTimeout = native.notifications.size();
    assert(adapter.servicePendingPaste(
        start + X11ClipboardAdapter::kPasteTimeout));
    assert(native.notifications.size() == beforeTimeout + 1);
    assert(native.notifications.back().property == XCB_ATOM_NONE);
    assert(adapter.servicePendingPaste(
        start + X11ClipboardAdapter::kPasteTimeout));
    assert(native.notifications.size() == beforeTimeout + 1);

    // Replacement and disconnect reject exact old requests, never stale data.
    dispatchRequest(adapter, requestFor(kUtf8Atom, 815, 15), start);
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    const std::size_t beforeReplace = native.notifications.size();
    assert(adapter.servicePendingPaste(start + std::chrono::milliseconds{1}));
    assert(native.notifications.size() == beforeReplace + 1);
    assert(native.notifications.back().property == XCB_ATOM_NONE);
    assert(adapter.publishCurrentRemoteOffer(start));

    dispatchRequest(adapter, requestFor(kUtf8Atom, 816, 16), start);
    transfer.resetAfterDisconnect();
    const std::size_t beforeDisconnect = native.notifications.size();
    assert(adapter.servicePendingPaste(start + std::chrono::milliseconds{1}));
    assert(native.notifications.size() == beforeDisconnect + 1);
    assert(native.notifications.back().property == XCB_ATOM_NONE);
}


void disconnectLatePasteFence()
{
    RemoteTransfer transfer;
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));

    FakeNative native;
    X11ClipboardAdapter adapter(transfer, native.operations(), kRootWindow);
    const Clock::time_point start{std::chrono::seconds{5}};
    assert(adapter.publishCurrentRemoteOffer(start));

    dispatchRequest(adapter, requestFor(kUtf8Atom, 831, 31), start);
    const auto fetch = adapter.pendingRemoteFetch();
    assert(fetch);
    assert(fetch->generation == transfer.generation());

    std::vector<std::uint8_t> request;
    assert(transfer.beginRequest(fetch->formatId, request));
    assert(adapter.markRemoteFetchStarted(fetch->pasteSequence));
    assert(transfer.hasOutstandingRequest());
    assert(transfer.hasPendingPasteRequest());

    const std::size_t writesBeforeDisconnect = native.propertyWrites.size();
    const std::size_t notificationsBeforeDisconnect =
        native.notifications.size();

    // R5/R8 native teardown must cancel the exact paste receipt before the
    // borrowed XCB window disappears. The already-sent CLIPRDR request may
    // still receive a late response, but that data has no native publisher.
    adapter.disconnect();
    assert(!adapter.valid());
    assert(!adapter.ownsClipboard());
    assert(!adapter.pendingRemoteFetch());
    assert(!transfer.hasPendingPasteRequest());
    assert(transfer.hasOutstandingRequest());
    assert(native.propertyWrites.size() == writesBeforeDisconnect);
    assert(native.notifications.size() ==
           notificationsBeforeDisconnect + 1U);
    assert(native.notifications.back().property == XCB_ATOM_NONE);
    assert(native.destroyWindowCalls == 1);

    const std::array<std::uint8_t, 10> textWire{
        'l', 0, 'a', 0, 't', 0, 'e', 0, 0, 0};
    const auto lateResponseWire = responsePdu(textWire);
    const auto lateResponse = transfer.receiveResponse(lateResponseWire);
    assert(lateResponse.status == RemoteTransfer::ResponseStatus::Received);
    assert(transfer.storeVerifiedUnicodeText(lateResponse));
    assert(!transfer.hasOutstandingRequest());

    // A late verified payload remains owned only by RemoteTransfer. The
    // disconnected adapter cannot emit a property, notify, or new fetch.
    assert(adapter.servicePendingPaste(
        start + std::chrono::milliseconds{1}));
    assert(native.propertyWrites.size() == writesBeforeDisconnect);
    assert(native.notifications.size() ==
           notificationsBeforeDisconnect + 1U);
    assert(!adapter.pendingRemoteFetch());
    assert(!adapter.markRemoteFetchStarted(fetch->pasteSequence));
    assert(!adapter.publishCurrentRemoteOffer(
        start + std::chrono::milliseconds{2}));

    adapter.disconnect();
    assert(native.destroyWindowCalls == 1);
}

void selectionOwnerLoss()
{
    RemoteTransfer transfer;
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    FakeNative native;
    X11ClipboardAdapter adapter(transfer, native.operations(), kRootWindow);
    const Clock::time_point start{std::chrono::seconds{4}};
    assert(adapter.publishCurrentRemoteOffer(start));

    dispatchRequest(adapter, requestFor(kUtf8Atom, 821, 21), start);
    const auto firstFetch = adapter.pendingRemoteFetch();
    assert(firstFetch);

    xcb_selection_clear_event_t clear{};
    clear.response_type = XCB_SELECTION_CLEAR;
    clear.owner = kOwnerWindow;
    clear.selection = kClipboardAtom;
    const auto clearEvent = genericEvent(clear);
    adapter.handleAt(clearEvent, start);
    assert(!adapter.ownsClipboard());
    assert(!adapter.pendingRemoteFetch());
    assert(native.notifications.back().property == XCB_ATOM_NONE);
    assert(!transfer.cancelPasteRequestForOwnerLoss(firstFetch->pasteSequence));

    const std::size_t afterClearSetCount = native.setOwnerCalls;
    assert(!adapter.publishCurrentRemoteOffer(start));
    assert(native.setOwnerCalls == afterClearSetCount);

    // A later generation may publish. A stale receipt cannot cancel the new one.
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    assert(adapter.publishCurrentRemoteOffer(start));
    adapter.observeClipboardOwner(kOwnerWindow);
    assert(adapter.ownsClipboard());
    dispatchRequest(adapter, requestFor(kUtf8Atom, 822, 22), start);
    const auto secondFetch = adapter.pendingRemoteFetch();
    assert(secondFetch &&
           secondFetch->pasteSequence != firstFetch->pasteSequence);
    assert(!transfer.cancelPasteRequestForOwnerLoss(firstFetch->pasteSequence));
    assert(transfer.hasPendingPasteRequest());

    native.currentSelectionOwner = 999;
    adapter.observeClipboardOwner(999);
    assert(!adapter.ownsClipboard());
    assert(!transfer.hasPendingPasteRequest());
    assert(native.notifications.back().property == XCB_ATOM_NONE);

    // A native property failure is terminal failure, never false success.
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    assert(adapter.publishCurrentRemoteOffer(start));
    storeText(transfer, "ready");
    native.failPropertyWrite = true;
    const std::size_t notifyBeforeFailure = native.notifications.size();
    dispatchRequest(adapter, requestFor(kUtf8Atom, 823, 23), start);
    assert(native.notifications.size() == notifyBeforeFailure + 1);
    assert(native.notifications.back().property == XCB_ATOM_NONE);
    assert(adapter.servicePendingPaste(start));
    assert(native.notifications.size() == notifyBeforeFailure + 1);

    adapter.disconnect();
    adapter.disconnect();
    assert(native.destroyWindowCalls == 1);
}

} // namespace

int main(int argc, char **argv)
{
    // add_rdp_test registers the first behavior as the executable's default;
    // the additional behavior-named CTests pass their case explicitly.
    assert(argc == 1 || argc == 2);
    const std::string_view behavior =
        argc == 1 ? "x11-selection-ownership-generation" : argv[1];
    if (behavior == "x11-selection-ownership-generation")
    {
        selectionOwnershipGeneration();
        return 0;
    }
    if (behavior == "x11-targets-publication")
    {
        targetsPublication();
        return 0;
    }
    if (behavior == "x11-selection-request-nonblocking")
    {
        selectionRequestNonblocking();
        return 0;
    }
    if (behavior == "x11-selection-owner-loss")
    {
        selectionOwnerLoss();
        return 0;
    }
    if (behavior == "x11-incr-large-text-progression")
    {
        incrLargeTextProgression();
        return 0;
    }
    if (behavior == "x11-incr-png-progression")
    {
        incrPngProgression();
        return 0;
    }
    if (behavior == "x11-incr-cancellation")
    {
        incrCancellation();
        return 0;
    }
    if (behavior == "x11-disconnect-late-paste-fence")
    {
        disconnectLatePasteFence();
        return 0;
    }
    assert(false && "unknown X11 clipboard behavior");
    return 1;
}
