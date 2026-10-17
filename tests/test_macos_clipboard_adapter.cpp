// SPDX-License-Identifier: GPL-3.0-or-later
#include "clipboard/clipboard_protocol.h"
#include "platform/macos/mac_clipboard_adapter.h"
#include "server/clipboard/remote_transfer.h"

#include <array>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using rdp_server::server::clipboard::RemoteTransfer;
using namespace rdp::macos;

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

void appendLongFormat(
    std::vector<std::uint8_t> &payload, std::uint32_t formatId,
    std::string_view name)
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

void put16(
    std::span<std::uint8_t> bytes, std::size_t offset,
    std::uint16_t value)
{
    assert(offset + 2U <= bytes.size());
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}

void put32(
    std::span<std::uint8_t> bytes, std::size_t offset,
    std::uint32_t value)
{
    assert(offset + 4U <= bytes.size());
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
}

std::vector<std::uint8_t> makeDib()
{
    constexpr std::uint32_t kBitmapInfoHeaderBytes = 40U;
    std::vector<std::uint8_t> dib(kBitmapInfoHeaderBytes + 4U, 0);
    put32(dib, 0, kBitmapInfoHeaderBytes);
    put32(dib, 4, 1U);
    put32(dib, 8, 1U);
    put16(dib, 12, 1U);
    put16(dib, 14, 32U);
    put32(dib, 16, 0U);
    put32(dib, 20, 4U);
    dib[kBitmapInfoHeaderBytes] = 0x11U;
    dib[kBitmapInfoHeaderBytes + 1U] = 0x22U;
    dib[kBitmapInfoHeaderBytes + 2U] = 0x33U;
    dib[kBitmapInfoHeaderBytes + 3U] = 0xffU;
    return dib;
}

void storeText(
    RemoteTransfer &owner, std::span<const std::uint8_t> wire)
{
    std::vector<std::uint8_t> request;
    assert(owner.beginRequest(
        rdp_server::clipboard::kFormatUnicodeText, request));
    // Response::payload borrows this PDU through synchronous validation.
    const auto completeResponse = responsePdu(wire);
    const auto response = owner.receiveResponse(completeResponse);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(owner.storeVerifiedUnicodeText(response));
}

void storeImage(
    RemoteTransfer &owner, std::uint32_t formatId,
    std::span<const std::uint8_t> wire)
{
    std::vector<std::uint8_t> request;
    assert(owner.beginRequest(formatId, request));
    // Response::payload borrows this PDU through synchronous validation.
    const auto completeResponse = responsePdu(wire);
    const auto response = owner.receiveResponse(completeResponse);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(owner.storeVerifiedImage(response));
}

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

struct FakeNative final
{
    std::uint64_t changeCount{11U};
    std::string text{};
    std::vector<std::byte> png{};
    unsigned readCalls{};
    unsigned replaceCalls{};
    unsigned clearCalls{};
    bool hasText{};
    bool hasPng{};
    bool failRead{};
    bool failReplace{};
    bool failClear{};
    bool reenterPublish{};
    bool disconnectDuringReplace{};
    MacClipboardAdapter *adapter{};
    bool reentrantResult{true};

    static bool readChangeCount(
        void *context, std::uint64_t &value) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.readCalls;
        if (self.failRead)
        {
            return false;
        }
        value = self.changeCount;
        return true;
    }

    static bool replaceContents(
        void *context, const MacClipboardNativeContent &content) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.replaceCalls;
        if (self.failReplace || (!content.hasText && !content.hasPng))
        {
            return false;
        }

        ++self.changeCount;
        self.hasText = content.hasText;
        self.hasPng = content.hasPng;
        self.text = content.hasText
            ? std::string{content.utf8Text}
            : std::string{};
        self.png = content.hasPng
            ? std::vector<std::byte>{
                  content.pngBytes.begin(), content.pngBytes.end()}
            : std::vector<std::byte>{};

        if (self.reenterPublish && self.adapter != nullptr)
        {
            self.reentrantResult =
                self.adapter->publishReadyRemoteGeneration();
        }
        if (self.disconnectDuringReplace && self.adapter != nullptr)
        {
            self.disconnectDuringReplace = false;
            self.adapter->disconnect();
        }
        return true;
    }

    static bool clearContents(void *context) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.clearCalls;
        if (self.failClear)
        {
            return false;
        }
        ++self.changeCount;
        self.hasText = false;
        self.hasPng = false;
        self.text.clear();
        self.png.clear();
        return true;
    }

    [[nodiscard]] MacClipboardNativeOperations operations() noexcept
    {
        return {
            this,
            &readChangeCount,
            &replaceContents,
            &clearContents,
        };
    }

    void localTakeover()
    {
        ++changeCount;
        hasText = true;
        hasPng = false;
        text = "local";
        png.clear();
    }
};

void macosClipboardRemoteReadyPublication()
{
    constexpr std::uint32_t kPngFormatId = 0xc210U;
    RemoteTransfer owner;
    std::vector<std::uint8_t> formats;
    appendLongFormat(
        formats, rdp_server::clipboard::kFormatUnicodeText, "");
    appendLongFormat(formats, kPngFormatId, "PNG");
    assert(owner.receiveLongFormatListPdu(longFormatPdu(formats)));

    const std::array<std::uint8_t, 10> textWire{
        'A', 0, '\r', 0, '\n', 0, 'B', 0, 0, 0};
    storeText(owner, textWire);
    storeImage(owner, kPngFormatId, kValidPng);

    FakeNative native;
    MacClipboardAdapter adapter(owner, native.operations());
    native.adapter = &adapter;
    assert(adapter.valid());
    assert(adapter.publishReadyRemoteGeneration());
    assert(adapter.ownsPasteboard());
    assert(adapter.publicationGeneration() == owner.generation());
    assert(adapter.publicationChangeCount() == native.changeCount);
    assert(native.hasText);
    assert(native.hasPng);
    assert(native.text == "A\nB");
    assert(native.png.size() == kValidPng.size());
    assert(std::memcmp(
        native.png.data(), kValidPng.data(), kValidPng.size()) == 0);

    const unsigned replacements = native.replaceCalls;
    assert(adapter.publishReadyRemoteGeneration());
    assert(native.replaceCalls == replacements);
    assert(adapter.observePasteboardChange());
}

void macosClipboardGenerationOwnerLoss()
{
    RemoteTransfer owner;
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    const std::array<std::uint8_t, 6> firstWire{
        'o', 0, 'n', 0, 0, 0};
    storeText(owner, firstWire);

    FakeNative native;
    MacClipboardAdapter adapter(owner, native.operations());
    native.adapter = &adapter;
    assert(adapter.publishReadyRemoteGeneration());

    native.localTakeover();
    const unsigned clearsBeforeTakeover = native.clearCalls;
    assert(!adapter.observePasteboardChange());
    assert(!adapter.ownsPasteboard());
    assert(native.clearCalls == clearsBeforeTakeover);

    const unsigned replacementsBeforeYieldRetry = native.replaceCalls;
    assert(!adapter.publishReadyRemoteGeneration());
    assert(native.replaceCalls == replacementsBeforeYieldRetry);
    assert(native.text == "local");

    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    const std::array<std::uint8_t, 8> secondWire{
        't', 0, 'w', 0, 'o', 0, 0, 0};
    storeText(owner, secondWire);
    assert(adapter.publishReadyRemoteGeneration());
    assert(adapter.publicationGeneration() == owner.generation());

    const unsigned clearsBeforeReplacement = native.clearCalls;
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    adapter.onRemoteGenerationChanged();
    assert(!adapter.ownsPasteboard());
    assert(native.clearCalls == clearsBeforeReplacement + 1U);
    assert(!native.hasText);
}

void macosClipboardR3RetirementSourceEpochFence()
{
    RemoteTransfer owner;
    const std::array<std::uint32_t, 1> formats{
        rdp_server::clipboard::kFormatUnicodeText};
    assert(owner.receiveFormatList(formats));
    const std::array<std::uint8_t, 8> firstWire{
        'o', 0, 'l', 0, 'd', 0, 0, 0};
    storeText(owner, firstWire);

    FakeNative native;
    MacClipboardAdapter adapter(owner, native.operations());
    native.adapter = &adapter;
    assert(adapter.publishReadyRemoteGeneration());
    const std::uint64_t retiredGeneration = owner.generation();
    const std::uint64_t retiredSourceEpoch = owner.sourceEpoch();
    const unsigned clearsBeforeRetirement = native.clearCalls;

    owner.retireR3ChannelState();
    assert(owner.receiveFormatList(formats));
    assert(owner.generation() == retiredGeneration);
    assert(owner.sourceEpoch() > retiredSourceEpoch);

    // Same-number replacement is still a distinct source. The native owner
    // callback must clear the retired immediate pasteboard publication.
    adapter.onRemoteGenerationChanged();
    assert(!adapter.ownsPasteboard());
    assert(native.clearCalls == clearsBeforeRetirement + 1U);
    assert(!native.hasText);

    const std::array<std::uint8_t, 8> replacementWire{
        'n', 0, 'e', 0, 'w', 0, 0, 0};
    storeText(owner, replacementWire);
    assert(adapter.publishReadyRemoteGeneration());
    assert(native.text == "new");

    // Yielding the replacement must not suppress a later source that reuses
    // the same clipboard generation again.
    native.localTakeover();
    assert(!adapter.observePasteboardChange());
    owner.retireR3ChannelState();
    assert(owner.receiveFormatList(formats));
    storeText(owner, firstWire);
    assert(owner.generation() == retiredGeneration);
    assert(adapter.publishReadyRemoteGeneration());
    assert(native.text == "old");
}

void macosClipboardPngRouting()
{
    RemoteTransfer owner;
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{8U}));
    const auto dib = makeDib();
    storeImage(owner, 8U, dib);

    FakeNative native;
    MacClipboardAdapter adapter(owner, native.operations());
    native.adapter = &adapter;
    assert(!adapter.publishReadyRemoteGeneration());
    assert(native.replaceCalls == 0U);

    constexpr std::uint32_t kPngFormatId = 0xc211U;
    std::vector<std::uint8_t> formats;
    appendLongFormat(formats, kPngFormatId, "PNG");
    assert(owner.receiveLongFormatListPdu(longFormatPdu(formats)));
    storeImage(owner, kPngFormatId, kValidPng);
    assert(adapter.publishReadyRemoteGeneration());
    assert(!native.hasText);
    assert(native.hasPng);
    assert(native.png.size() == kValidPng.size());
}

void macosClipboardDisconnectOwnerFence()
{
    RemoteTransfer owner;
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    const std::array<std::uint8_t, 6> textWire{
        'o', 0, 'k', 0, 0, 0};
    storeText(owner, textWire);

    FakeNative native;
    {
        MacClipboardAdapter adapter(owner, native.operations());
        native.adapter = &adapter;
        assert(adapter.publishReadyRemoteGeneration());
        const unsigned clearsBeforeDisconnect = native.clearCalls;
        adapter.disconnect();
        assert(!adapter.valid());
        assert(native.clearCalls == clearsBeforeDisconnect + 1U);
        adapter.disconnect();
        assert(native.clearCalls == clearsBeforeDisconnect + 1U);
    }

    MacClipboardAdapter adapter(owner, native.operations());
    native.adapter = &adapter;
    assert(adapter.publishReadyRemoteGeneration());
    native.localTakeover();
    const unsigned clearsBeforeLocalOwnerDisconnect = native.clearCalls;
    adapter.disconnect();
    assert(!adapter.valid());
    assert(native.clearCalls == clearsBeforeLocalOwnerDisconnect);
    assert(native.text == "local");
}

void macosClipboardFailureAndReentryDenials()
{
    RemoteTransfer owner;
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    const std::array<std::uint8_t, 6> firstWire{
        'o', 0, 'k', 0, 0, 0};
    storeText(owner, firstWire);

    FakeNative native;
    MacClipboardAdapter adapter(owner, native.operations());
    native.adapter = &adapter;

    native.failReplace = true;
    assert(!adapter.publishReadyRemoteGeneration());
    assert(adapter.valid());
    assert(!adapter.ownsPasteboard());
    native.failReplace = false;

    native.reenterPublish = true;
    assert(adapter.publishReadyRemoteGeneration());
    assert(!native.reentrantResult);
    native.reenterPublish = false;

    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    const std::array<std::uint8_t, 8> secondWire{
        'n', 0, 'e', 0, 'w', 0, 0, 0};
    storeText(owner, secondWire);
    native.disconnectDuringReplace = true;
    assert(!adapter.publishReadyRemoteGeneration());
    assert(!adapter.valid());
    assert(!adapter.ownsPasteboard());

    FakeNative ambiguousNative;
    MacClipboardAdapter ambiguousAdapter(
        owner, ambiguousNative.operations());
    ambiguousNative.adapter = &ambiguousAdapter;
    assert(ambiguousAdapter.publishReadyRemoteGeneration());
    ambiguousNative.failRead = true;
    const unsigned clearsBeforeAmbiguousRead =
        ambiguousNative.clearCalls;
    assert(!ambiguousAdapter.observePasteboardChange());
    assert(!ambiguousAdapter.valid());
    assert(ambiguousNative.clearCalls ==
           clearsBeforeAmbiguousRead);
}

} // namespace

int main(int argc, char **argv)
{
    assert(argc == 2);
    const std::string_view behavior{argv[1]};
    if (behavior == "macos-clipboard-remote-ready-publication")
    {
        macosClipboardRemoteReadyPublication();
        return 0;
    }
    if (behavior == "macos-clipboard-generation-owner-loss")
    {
        macosClipboardGenerationOwnerLoss();
        return 0;
    }
    if (behavior == "macos-clipboard-r3-retirement-source-epoch")
    {
        macosClipboardR3RetirementSourceEpochFence();
        return 0;
    }
    if (behavior == "macos-clipboard-png-routing")
    {
        macosClipboardPngRouting();
        return 0;
    }
    if (behavior == "macos-clipboard-disconnect-owner-fence")
    {
        macosClipboardDisconnectOwnerFence();
        return 0;
    }
    if (behavior == "macos-clipboard-failure-reentry-denials")
    {
        macosClipboardFailureAndReentryDenials();
        return 0;
    }
    assert(false && "unknown macOS clipboard behavior");
    return 1;
}
