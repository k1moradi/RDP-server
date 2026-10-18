// SPDX-License-Identifier: GPL-3.0-or-later
#include "clipboard/clipboard_protocol.h"
#include "server/clipboard/remote_transfer.h"
#include "windows/windows_clipboard_adapter.h"

#include <array>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

using rdp_server::server::clipboard::RemoteTransfer;
using namespace rdp_server::windows;

namespace
{

std::vector<std::uint8_t> responsePdu(
    std::span<const std::uint8_t> payload)
{
    std::vector<std::uint8_t> result;
    assert(rdp_server::clipboard::encodePdu(
        rdp_server::clipboard::kFormatDataResponse,
        rdp_server::clipboard::kResponseOk, payload, result));
    return result;
}

void appendLongFormat(std::vector<std::uint8_t> &payload,
                      std::uint32_t formatId, std::string_view name)
{
    for (unsigned shift = 0; shift < 32; shift += 8)
    {
        payload.push_back(static_cast<std::uint8_t>(formatId >> shift));
    }
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
    std::vector<std::uint8_t> result;
    assert(rdp_server::clipboard::encodePdu(
        rdp_server::clipboard::kFormatList, 0, payload, result));
    return result;
}

void put16(std::span<std::uint8_t> bytes, std::size_t offset,
           std::uint16_t value)
{
    assert(offset + 2U <= bytes.size());
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}

void put32(std::span<std::uint8_t> bytes, std::size_t offset,
           std::uint32_t value)
{
    assert(offset + 4U <= bytes.size());
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
}

std::vector<std::uint8_t> makeDib(std::uint32_t headerBytes)
{
    std::vector<std::uint8_t> dib(headerBytes + 4U, 0);
    put32(dib, 0, headerBytes);
    put32(dib, 4, 1U);
    put32(dib, 8, 1U);
    put16(dib, 12, 1U);
    put16(dib, 14, 32U);
    put32(dib, 16, 0U);
    put32(dib, 20, 4U);
    dib[headerBytes] = 0x11U;
    dib[headerBytes + 1U] = 0x22U;
    dib[headerBytes + 2U] = 0x33U;
    dib[headerBytes + 3U] = 0xffU;
    return dib;
}

void storeText(RemoteTransfer &owner,
               std::span<const std::uint8_t> wire)
{
    std::vector<std::uint8_t> request;
    assert(owner.beginRequest(
        rdp_server::clipboard::kFormatUnicodeText, request));
    // RemoteTransfer::Response::payload borrows this complete PDU. Keep its
    // backing vector alive through synchronous validation/storage.
    const auto completeResponse = responsePdu(wire);
    const auto response = owner.receiveResponse(completeResponse);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(owner.storeVerifiedUnicodeText(response));
}

void storeImage(RemoteTransfer &owner, std::uint32_t formatId,
                std::span<const std::uint8_t> wire)
{
    std::vector<std::uint8_t> request;
    assert(owner.beginRequest(formatId, request));
    // RemoteTransfer::Response::payload borrows this complete PDU. Keep its
    // backing vector alive through synchronous validation/storage.
    const auto completeResponse = responsePdu(wire);
    const auto response = owner.receiveResponse(completeResponse);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(owner.storeVerifiedImage(response));
}

struct FakeNative final
{
    struct Write final
    {
        WindowsClipboardFormat format{};
        std::vector<std::byte> bytes{};
    };

    static constexpr WindowsClipboardWindowToken kOwnerWindow = 0x1234U;
    static constexpr WindowsClipboardFormat kPngFormat = 0xc101U;

    std::vector<WindowsClipboardFormat> delayedFormats{};
    std::vector<Write> writes{};
    WindowsClipboardWindowToken currentOwner{};
    WindowsClipboardWindowToken openedFor{};
    unsigned openCalls{};
    unsigned emptyCalls{};
    unsigned closeCalls{};
    bool opened{};
    bool failOpen{};
    bool failEmpty{};
    bool failDelayed{};
    bool failWrite{};
    bool failClose{};
    bool reenterPublish{};
    bool disconnectDuringWrite{};
    bool retireDuringDelayedPublication{};
    bool retireDuringClose{};
    RemoteTransfer *remoteTransfer{};
    WindowsClipboardAdapter *adapter{};
    bool reentrantResult{true};

    static WindowsClipboardFormat registerFormat(
        void *context, std::string_view name) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        assert(name == "PNG");
        return self.kPngFormat;
    }

    static bool openClipboard(
        void *context, WindowsClipboardWindowToken owner) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.openCalls;
        self.openedFor = owner;
        if (self.failOpen)
        {
            return false;
        }
        self.opened = true;
        return true;
    }

    static bool emptyClipboard(void *context) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.emptyCalls;
        if (!self.opened || self.failEmpty)
        {
            return false;
        }
        const bool replacingSelf =
            self.currentOwner == self.openedFor &&
            self.adapter != nullptr;
        self.currentOwner = self.openedFor;
        self.delayedFormats.clear();
        self.writes.clear();
        if (replacingSelf)
        {
            self.adapter->onDestroyClipboard();
        }
        return true;
    }

    static bool setDelayedFormat(
        void *context, WindowsClipboardFormat format) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        if (!self.opened || self.failDelayed)
        {
            return false;
        }
        self.delayedFormats.push_back(format);
        if (self.retireDuringDelayedPublication &&
            self.remoteTransfer != nullptr)
        {
            self.retireDuringDelayedPublication = false;
            self.remoteTransfer->retireR3ChannelState();
        }
        if (self.reenterPublish && self.adapter != nullptr)
        {
            self.reentrantResult =
                self.adapter->publishReadyRemoteGeneration();
        }
        return true;
    }

    static bool setFormatBytes(
        void *context, WindowsClipboardFormat format,
        std::span<const std::byte> bytes) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        if (self.failWrite)
        {
            return false;
        }
        self.writes.push_back(
            Write{format, std::vector<std::byte>(bytes.begin(), bytes.end())});
        if (self.disconnectDuringWrite && self.adapter != nullptr)
        {
            self.disconnectDuringWrite = false;
            self.adapter->disconnect();
        }
        return true;
    }

    static bool closeClipboard(void *context) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.closeCalls;
        if (!self.opened)
        {
            return false;
        }
        self.opened = false;
        if (self.retireDuringClose && self.remoteTransfer != nullptr)
        {
            self.retireDuringClose = false;
            self.remoteTransfer->retireR3ChannelState();
        }
        return !self.failClose;
    }

    static WindowsClipboardWindowToken clipboardOwner(
        void *context) noexcept
    {
        return static_cast<FakeNative *>(context)->currentOwner;
    }

    [[nodiscard]] WindowsClipboardNativeOperations operations() noexcept
    {
        return {
            this,
            &registerFormat,
            &openClipboard,
            &emptyClipboard,
            &setDelayedFormat,
            &setFormatBytes,
            &closeClipboard,
            &clipboardOwner,
        };
    }
};

void windowsClipboardRemoteReadyPublication()
{
    RemoteTransfer owner;
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 2>{
            rdp_server::clipboard::kFormatUnicodeText,
            WindowsClipboardAdapter::kDibFormat}));

    const std::array<std::uint8_t, 10> textWire{
        'A', 0, '\r', 0, '\n', 0, 'B', 0, 0, 0};
    storeText(owner, textWire);
    const auto dib = makeDib(40U);
    storeImage(owner, WindowsClipboardAdapter::kDibFormat, dib);

    FakeNative native;
    WindowsClipboardAdapter adapter(
        owner, native.operations(), FakeNative::kOwnerWindow);
    native.adapter = &adapter;
    assert(adapter.valid());
    assert(adapter.pngFormat() == FakeNative::kPngFormat);
    assert(adapter.publishReadyRemoteGeneration());
    assert(adapter.ownsClipboard());
    assert(adapter.publicationGeneration() == owner.generation());
    assert((native.delayedFormats ==
            std::vector<WindowsClipboardFormat>{
                WindowsClipboardAdapter::kDibFormat,
                WindowsClipboardAdapter::kUnicodeTextFormat}));
    assert(native.writes.empty());

    assert(adapter.renderFormat(
        WindowsClipboardAdapter::kUnicodeTextFormat));
    assert(native.writes.size() == 1U);
    const std::array<std::uint8_t, 10> expectedText{
        'A', 0, '\r', 0, '\n', 0, 'B', 0, 0, 0};
    assert(native.writes.back().bytes.size() == expectedText.size());
    assert(std::memcmp(native.writes.back().bytes.data(),
                       expectedText.data(), expectedText.size()) == 0);

    assert(adapter.renderFormat(WindowsClipboardAdapter::kDibFormat));
    assert(native.writes.size() == 2U);
    assert(native.writes.back().bytes.size() == dib.size());
    assert(std::memcmp(native.writes.back().bytes.data(),
                       dib.data(), dib.size()) == 0);

    // Repeated WM_RENDERFORMAT is idempotent and never reallocates data.
    assert(adapter.renderFormat(WindowsClipboardAdapter::kDibFormat));
    assert(native.writes.size() == 2U);
    assert(!adapter.renderFormat(999U));
}

void windowsClipboardGenerationOwnerLoss()
{
    RemoteTransfer owner;
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    const std::array<std::uint8_t, 6> firstWire{
        'o', 0, 'n', 0, 0, 0};
    storeText(owner, firstWire);

    FakeNative native;
    WindowsClipboardAdapter adapter(
        owner, native.operations(), FakeNative::kOwnerWindow);
    native.adapter = &adapter;
    assert(adapter.publishReadyRemoteGeneration());

    // A local application takeover yields this remote generation. The adapter
    // must not immediately steal the clipboard back with the same offer.
    native.currentOwner = 0x9999U;
    adapter.onDestroyClipboard();
    assert(!adapter.ownsClipboard());
    const unsigned openBeforeYieldRetry = native.openCalls;
    assert(!adapter.publishReadyRemoteGeneration());
    assert(native.openCalls == openBeforeYieldRetry);

    // A new RDP generation can publish again.
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    const std::array<std::uint8_t, 8> secondWire{
        't', 0, 'w', 0, 'o', 0, 0, 0};
    storeText(owner, secondWire);
    assert(adapter.publishReadyRemoteGeneration());
    assert(adapter.publicationGeneration() == 2U);

    // Replacement after publication revokes delayed rendering immediately;
    // stale bytes from generation 2 are never copied into native memory.
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    const std::size_t writesBeforeStaleRender = native.writes.size();
    assert(!adapter.renderFormat(
        WindowsClipboardAdapter::kUnicodeTextFormat));
    assert(native.writes.size() == writesBeforeStaleRender);
}

void windowsClipboardR3RetirementSourceEpochFence()
{
    RemoteTransfer owner;
    const std::array<std::uint32_t, 1> formats{
        rdp_server::clipboard::kFormatUnicodeText};
    assert(owner.receiveFormatList(formats));
    const std::array<std::uint8_t, 8> firstWire{
        'o', 0, 'l', 0, 'd', 0, 0, 0};
    storeText(owner, firstWire);

    FakeNative native;
    WindowsClipboardAdapter adapter(
        owner, native.operations(), FakeNative::kOwnerWindow);
    native.adapter = &adapter;
    assert(adapter.publishReadyRemoteGeneration());
    const std::uint64_t retiredGeneration = owner.generation();
    const std::uint64_t retiredSourceEpoch = owner.sourceEpoch();

    owner.retireR3ChannelState();
    assert(owner.receiveFormatList(formats));
    assert(owner.generation() == retiredGeneration);
    assert(owner.sourceEpoch() > retiredSourceEpoch);
    const std::array<std::uint8_t, 8> replacementWire{
        'n', 0, 'e', 0, 'w', 0, 0, 0};
    storeText(owner, replacementWire);

    // An old WM_RENDERFORMAT belongs to the retired source even though the
    // replacement reused its numeric clipboard generation.
    const std::size_t writesBeforeStaleRender = native.writes.size();
    assert(!adapter.renderFormat(
        WindowsClipboardAdapter::kUnicodeTextFormat));
    assert(native.writes.size() == writesBeforeStaleRender);

    // Republish establishes a fresh native source identity; only then may the
    // replacement payload render through the existing Win32 owner.
    assert(adapter.publishReadyRemoteGeneration());
    assert(adapter.renderFormat(
        WindowsClipboardAdapter::kUnicodeTextFormat));
    assert(native.writes.size() == writesBeforeStaleRender + 1U);
    assert(native.writes.back().bytes.size() == replacementWire.size());
    assert(std::memcmp(native.writes.back().bytes.data(),
                       replacementWire.data(), replacementWire.size()) == 0);
}

void windowsClipboardPngDibRouting()
{
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

    RemoteTransfer owner;
    std::vector<std::uint8_t> formats;
    appendLongFormat(formats, 0xc210U, "PNG");
    assert(owner.receiveLongFormatListPdu(longFormatPdu(formats)));
    storeImage(owner, 0xc210U, kValidPng);

    FakeNative native;
    WindowsClipboardAdapter adapter(
        owner, native.operations(), FakeNative::kOwnerWindow);
    native.adapter = &adapter;
    assert(adapter.publishReadyRemoteGeneration());
    assert((native.delayedFormats ==
            std::vector<WindowsClipboardFormat>{FakeNative::kPngFormat}));
    assert(adapter.renderFormat(FakeNative::kPngFormat));
    assert(native.writes.size() == 1U);
    assert(native.writes.back().bytes.size() == kValidPng.size());

    // DIBV5 stays CF_DIBV5; no PNG label is fabricated for DIB bytes.
    assert(owner.receiveFormatList(std::array<std::uint32_t, 1>{
        WindowsClipboardAdapter::kDibV5Format}));
    const auto dibV5 = makeDib(124U);
    storeImage(owner, WindowsClipboardAdapter::kDibV5Format, dibV5);
    assert(adapter.publishReadyRemoteGeneration());
    assert((native.delayedFormats ==
            std::vector<WindowsClipboardFormat>{
                WindowsClipboardAdapter::kDibV5Format}));
    assert(!adapter.renderFormat(FakeNative::kPngFormat));
    assert(adapter.renderFormat(WindowsClipboardAdapter::kDibV5Format));
    assert(native.writes.back().bytes.size() == dibV5.size());
}

void windowsClipboardRenderAllAndDisconnect()
{
    RemoteTransfer owner;
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 2>{
            rdp_server::clipboard::kFormatUnicodeText,
            WindowsClipboardAdapter::kDibFormat}));
    const std::array<std::uint8_t, 6> textWire{
        'x', 0, 'y', 0, 0, 0};
    storeText(owner, textWire);
    const auto dib = makeDib(40U);
    storeImage(owner, WindowsClipboardAdapter::kDibFormat, dib);

    FakeNative native;
    WindowsClipboardAdapter adapter(
        owner, native.operations(), FakeNative::kOwnerWindow);
    native.adapter = &adapter;
    assert(adapter.publishReadyRemoteGeneration());

    const unsigned opensBeforeRenderAll = native.openCalls;
    assert(adapter.renderAllBeforeOwnerDestroy());
    assert(native.openCalls == opensBeforeRenderAll + 1U);
    assert(native.writes.size() == 2U);
    assert(native.writes[0].format == WindowsClipboardAdapter::kDibFormat);
    assert(native.writes[1].format ==
           WindowsClipboardAdapter::kUnicodeTextFormat);

    const unsigned emptiesBeforeDisconnect = native.emptyCalls;
    adapter.disconnect();
    assert(!adapter.valid());
    assert(!adapter.ownsClipboard());
    assert(native.emptyCalls == emptiesBeforeDisconnect + 1U);
    const unsigned opensAfterDisconnect = native.openCalls;
    adapter.disconnect();
    assert(native.openCalls == opensAfterDisconnect);
}

void windowsClipboardPublicationMidcallbackRetirement()
{
    const std::array<std::uint32_t, 1> formats{
        rdp_server::clipboard::kFormatUnicodeText};
    const std::array<std::uint8_t, 8> textWire{
        'o', 0, 'l', 0, 'd', 0, 0, 0};
    const std::array<std::uint8_t, 8> replacementWire{
        'n', 0, 'e', 0, 'w', 0, 0, 0};

    // Neither delayed SetClipboardData nor CloseClipboard may commit formats
    // belonging to a source retired synchronously by its native callback.
    for (const bool retireDuringClose : std::array{false, true})
    {
        RemoteTransfer owner;
        assert(owner.receiveFormatList(formats));
        storeText(owner, textWire);
        const std::uint64_t originalGeneration = owner.generation();
        const std::uint64_t originalSourceEpoch = owner.sourceEpoch();

        FakeNative native;
        native.remoteTransfer = &owner;
        native.retireDuringDelayedPublication = !retireDuringClose;
        native.retireDuringClose = retireDuringClose;
        WindowsClipboardAdapter adapter(
            owner, native.operations(), FakeNative::kOwnerWindow);
        native.adapter = &adapter;

        assert(!adapter.publishReadyRemoteGeneration());
        assert(owner.generation() == 0U);
        assert(owner.sourceEpoch() == originalSourceEpoch);
        assert(!adapter.ownsClipboard());
        assert(adapter.publicationGeneration() == 0U);
        assert(native.delayedFormats.empty());
        assert(native.writes.empty());
        assert(!adapter.renderFormat(
            WindowsClipboardAdapter::kUnicodeTextFormat));

        // Reused numeric generation is not authority for the retired epoch.
        assert(owner.receiveFormatList(formats));
        assert(owner.generation() == originalGeneration);
        assert(owner.sourceEpoch() > originalSourceEpoch);
        storeText(owner, replacementWire);
        assert(adapter.publishReadyRemoteGeneration());
        assert(adapter.ownsClipboard());
        assert(native.delayedFormats.size() == 1U);
        assert(adapter.renderFormat(
            WindowsClipboardAdapter::kUnicodeTextFormat));
    }
}

void windowsClipboardFailureAndReentryDenials()
{
    RemoteTransfer owner;
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    const std::array<std::uint8_t, 6> textWire{
        'o', 0, 'k', 0, 0, 0};
    storeText(owner, textWire);

    FakeNative native;
    WindowsClipboardAdapter adapter(
        owner, native.operations(), FakeNative::kOwnerWindow);
    native.adapter = &adapter;

    native.failOpen = true;
    assert(!adapter.publishReadyRemoteGeneration());
    assert(adapter.valid());
    assert(!adapter.ownsClipboard());
    native.failOpen = false;

    native.reenterPublish = true;
    assert(adapter.publishReadyRemoteGeneration());
    assert(!native.reentrantResult);
    native.reenterPublish = false;

    // Disconnect requested from inside SetClipboardData is deferred until the
    // native call returns, then clears the publication exactly once.
    native.disconnectDuringWrite = true;
    assert(!adapter.renderFormat(
        WindowsClipboardAdapter::kUnicodeTextFormat));
    assert(!adapter.valid());
    assert(!adapter.ownsClipboard());
}

} // namespace

int main(int argc, char **argv)
{
    assert(argc == 2);
    const std::string_view behavior{argv[1]};
    if (behavior == "windows-clipboard-remote-ready-publication")
    {
        windowsClipboardRemoteReadyPublication();
        return 0;
    }
    if (behavior == "windows-clipboard-generation-owner-loss")
    {
        windowsClipboardGenerationOwnerLoss();
        return 0;
    }
    if (behavior == "windows-clipboard-r3-retirement-source-epoch")
    {
        windowsClipboardR3RetirementSourceEpochFence();
        return 0;
    }
    if (behavior == "windows-clipboard-png-dib-routing")
    {
        windowsClipboardPngDibRouting();
        return 0;
    }
    if (behavior == "windows-clipboard-render-all-disconnect")
    {
        windowsClipboardRenderAllAndDisconnect();
        return 0;
    }
    if (behavior == "windows-clipboard-publication-midcallback-retirement")
    {
        windowsClipboardPublicationMidcallbackRetirement();
        return 0;
    }
    if (behavior == "windows-clipboard-failure-reentry-denials")
    {
        windowsClipboardFailureAndReentryDenials();
        return 0;
    }
    assert(false && "unknown Windows clipboard behavior");
    return 1;
}
