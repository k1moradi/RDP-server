// SPDX-License-Identifier: GPL-3.0-or-later
#include "clipboard/clipboard_protocol.h"
#include "server/clipboard/remote_transfer.h"
#include "platform/macos/mac_clipboard_adapter.h"
#include "platform/macos/mac_clipboard_file_destination.h"

#include <algorithm>
#include <array>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if defined(__APPLE__)
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

using rdp_server::server::clipboard::RemoteFileDestinationPlan;
using rdp_server::server::clipboard::RemoteTransfer;
using namespace rdp::macos;

namespace
{

constexpr std::uint32_t kFileListFormatId = 0xc620U;
constexpr std::size_t kDescriptorBytes = 592U;
constexpr std::uint32_t kFdFileSize = 0x00000040U;
constexpr std::uint32_t kFileFlags =
    rdp_server::clipboard::kUseLongFormatNames |
    rdp_server::clipboard::kStreamFileclipEnabled |
    rdp_server::clipboard::kFileclipNoFilePaths |
    rdp_server::clipboard::kHugeFileSupportEnabled;

std::vector<std::uint8_t> capabilitiesPdu(
    const std::uint32_t flags)
{
    const std::array<std::uint8_t, 16> payload{
        1,0,0,0, 1,0,12,0, 2,0,0,0,
        static_cast<std::uint8_t>(flags),
        static_cast<std::uint8_t>(flags >> 8U),
        static_cast<std::uint8_t>(flags >> 16U),
        static_cast<std::uint8_t>(flags >> 24U),
    };
    std::vector<std::uint8_t> result;
    assert(rdp_server::clipboard::encodePdu(
        rdp_server::clipboard::kClipCaps, 0, payload, result));
    return result;
}

void put32(
    std::span<std::uint8_t> bytes, const std::size_t offset,
    const std::uint32_t value)
{
    assert(offset + 4U <= bytes.size());
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
}

void put64(
    std::span<std::uint8_t> bytes, const std::size_t offset,
    const std::uint64_t value)
{
    put32(bytes, offset, static_cast<std::uint32_t>(value));
    put32(bytes, offset + 4U, static_cast<std::uint32_t>(value >> 32U));
}

void putDescriptorFileSize(
    std::span<std::uint8_t> descriptor,
    const std::uint64_t value)
{
    put32(descriptor, 64U, static_cast<std::uint32_t>(value >> 32U));
    put32(descriptor, 68U, static_cast<std::uint32_t>(value));
}

void putFileName(
    std::span<std::uint8_t> descriptor,
    const std::u16string_view name)
{
    constexpr std::size_t kNameOffset = 72U;
    assert(name.size() < 260U);
    for (std::size_t index = 0; index < name.size(); ++index)
    {
        const auto codeUnit =
            static_cast<std::uint16_t>(name[index]);
        descriptor[kNameOffset + index * 2U] =
            static_cast<std::uint8_t>(codeUnit);
        descriptor[kNameOffset + index * 2U + 1U] =
            static_cast<std::uint8_t>(codeUnit >> 8U);
    }
}

void appendLongFormat(
    std::vector<std::uint8_t> &payload,
    const std::uint32_t formatId,
    const std::string_view name)
{
    for (unsigned shift = 0; shift < 32; shift += 8)
    {
        payload.push_back(
            static_cast<std::uint8_t>(formatId >> shift));
    }
    for (const char character : name)
    {
        payload.push_back(
            static_cast<std::uint8_t>(character));
        payload.push_back(0);
    }
    payload.push_back(0);
    payload.push_back(0);
}

std::vector<std::uint8_t> longFormatPdu(
    const std::span<const std::uint8_t> payload)
{
    std::vector<std::uint8_t> result;
    assert(rdp_server::clipboard::encodePdu(
        rdp_server::clipboard::kFormatList, 0, payload, result));
    return result;
}

std::vector<std::uint8_t> formatDataResponsePdu(
    const std::span<const std::uint8_t> payload)
{
    std::vector<std::uint8_t> result;
    assert(rdp_server::clipboard::encodePdu(
        rdp_server::clipboard::kFormatDataResponse,
        rdp_server::clipboard::kResponseOk, payload, result));
    return result;
}

std::vector<std::uint8_t> fileContentsResponsePdu(
    const std::uint16_t flags,
    const std::uint32_t streamId,
    const std::span<const std::uint8_t> data = {})
{
    std::vector<std::uint8_t> payload(4U + data.size());
    put32(payload, 0, streamId);
    std::copy(data.begin(), data.end(), payload.begin() + 4U);
    std::vector<std::uint8_t> result;
    assert(rdp_server::clipboard::encodePdu(
        rdp_server::clipboard::kFileContentsResponse,
        flags, payload, result));
    return result;
}

struct OfferedFile final
{
    std::u16string_view name{};
    bool sizeKnown{};
    std::uint64_t size{};
};

void installFileOffer(
    RemoteTransfer &owner,
    const std::span<const OfferedFile> files)
{
    assert(!files.empty());
    assert(files.size() <= RemoteTransfer::kMaximumRemoteFiles);
    assert(owner.receiveCapabilitiesPdu(
        capabilitiesPdu(kFileFlags), kFileFlags));

    std::vector<std::uint8_t> formats;
    appendLongFormat(
        formats, kFileListFormatId, "FileGroupDescriptorW");
    assert(owner.receiveLongFormatListPdu(longFormatPdu(formats)));

    std::vector<std::uint8_t> request;
    assert(owner.beginFileGroupDescriptorRequest(request));

    std::vector<std::uint8_t> list(
        4U + files.size() * kDescriptorBytes, 0);
    put32(list, 0, static_cast<std::uint32_t>(files.size()));
    for (std::size_t index = 0; index < files.size(); ++index)
    {
        auto descriptor = std::span(list).subspan(
            4U + index * kDescriptorBytes, kDescriptorBytes);
        if (files[index].sizeKnown)
        {
            put32(descriptor, 0, kFdFileSize);
            putDescriptorFileSize(descriptor, files[index].size);
        }
        putFileName(descriptor, files[index].name);
    }

    const auto wire = formatDataResponsePdu(list);
    const auto response = owner.receiveResponse(wire);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(owner.storeFileGroupDescriptors(response));
    assert(owner.remoteFileCount() == files.size());
}

void installSingleFileOffer(
    RemoteTransfer &owner,
    const std::u16string_view name,
    const bool sizeKnown,
    const std::uint64_t size)
{
    const std::array<OfferedFile, 1> files{{
        {name, sizeKnown, size},
    }};
    installFileOffer(owner, files);
}

struct FakeNative final
{
    std::vector<std::byte> bytes{};
    MacClipboardFileDescriptorToken sourceToken{101};
    MacClipboardFileDescriptorToken ownedToken{202};
    unsigned duplicateCalls{};
    unsigned resizeCalls{};
    unsigned writeCalls{};
    unsigned flushCalls{};
    unsigned closeCalls{};
    bool failDuplicate{};
    bool failResize{};
    bool failWrite{};
    bool failFlush{};
    bool closed{};
    RemoteTransfer *replaceSourceOnWrite{};

    static bool duplicate(
        void *context, MacClipboardFileDescriptorToken source,
        MacClipboardFileDescriptorToken &owned) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.duplicateCalls;
        if (self.failDuplicate || source != self.sourceToken)
        {
            owned = kInvalidMacClipboardFileDescriptor;
            return false;
        }
        self.closed = false;
        owned = self.ownedToken;
        return true;
    }

    static bool resize(
        void *context, MacClipboardFileDescriptorToken token,
        std::uint64_t size) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.resizeCalls;
        if (self.failResize || token != self.ownedToken ||
            size > static_cast<std::uint64_t>(
                std::numeric_limits<std::size_t>::max()))
        {
            return false;
        }
        try
        {
            self.bytes.resize(static_cast<std::size_t>(size));
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    static bool write(
        void *context, MacClipboardFileDescriptorToken token,
        std::uint64_t offset,
        std::span<const std::byte> bytes) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.writeCalls;
        if (self.failWrite || token != self.ownedToken ||
            offset > self.bytes.size() ||
            bytes.size() >
                std::numeric_limits<std::size_t>::max() -
                    static_cast<std::size_t>(offset))
        {
            return false;
        }
        try
        {
            const std::size_t end =
                static_cast<std::size_t>(offset) + bytes.size();
            if (self.bytes.size() < end)
            {
                self.bytes.resize(end);
            }
            std::copy(
                bytes.begin(), bytes.end(),
                self.bytes.begin() +
                    static_cast<std::size_t>(offset));
            if (self.replaceSourceOnWrite != nullptr)
            {
                RemoteTransfer *const owner = self.replaceSourceOnWrite;
                self.replaceSourceOnWrite = nullptr;
                const std::array<std::uint32_t, 1> replacement{
                    rdp_server::clipboard::kFormatUnicodeText};
                if (!owner->receiveFormatList(replacement))
                {
                    return false;
                }
            }
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    static bool flush(
        void *context,
        MacClipboardFileDescriptorToken token) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.flushCalls;
        return !self.failFlush && token == self.ownedToken;
    }

    static void close(
        void *context,
        MacClipboardFileDescriptorToken token) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.closeCalls;
        assert(token == self.ownedToken);
        self.closed = true;
    }

    [[nodiscard]] MacClipboardFileNativeOperations
    operations() noexcept
    {
        return {
            this, &duplicate, &resize, &write, &flush, &close};
    }
};

struct FakePasteboard final
{
    std::uint64_t changeCount{31U};
    std::string fileUrl{};
    std::vector<std::string> fileUrls{};
    unsigned readCalls{};
    unsigned replaceCalls{};
    unsigned clearCalls{};
    bool hasFileUrl{};
    bool failReplace{};
    RemoteFileDestinationPlan *planToCancelOnReplace{};

    static bool readChangeCount(
        void *context, std::uint64_t &value) noexcept
    {
        auto &self = *static_cast<FakePasteboard *>(context);
        ++self.readCalls;
        value = self.changeCount;
        return true;
    }

    static bool replaceContents(
        void *context,
        const MacClipboardNativeContent &content) noexcept
    {
        auto &self = *static_cast<FakePasteboard *>(context);
        ++self.replaceCalls;
        if (self.failReplace || !content.hasFileUrls ||
            content.fileUrls.empty() ||
            content.hasText || content.hasPng)
        {
            return false;
        }

        try
        {
            std::vector<std::string> replacement;
            replacement.reserve(content.fileUrls.size());
            for (const std::string_view fileUrl : content.fileUrls)
            {
                if (fileUrl.empty())
                {
                    return false;
                }
                replacement.emplace_back(fileUrl);
            }
            ++self.changeCount;
            self.hasFileUrl = true;
            self.fileUrls = std::move(replacement);
            self.fileUrl = self.fileUrls.front();
            if (self.planToCancelOnReplace != nullptr)
            {
                self.planToCancelOnReplace->cancel();
                self.planToCancelOnReplace = nullptr;
            }
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    static bool clearContents(void *context) noexcept
    {
        auto &self = *static_cast<FakePasteboard *>(context);
        ++self.clearCalls;
        ++self.changeCount;
        self.hasFileUrl = false;
        self.fileUrl.clear();
        self.fileUrls.clear();
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
        hasFileUrl = true;
        fileUrl = "file:///tmp/local-owner.txt";
        fileUrls = {fileUrl};
    }
};

std::vector<std::uint8_t> makeChunk(
    const std::uint64_t offset,
    const std::size_t bytes)
{
    std::vector<std::uint8_t> result(bytes);
    for (std::size_t index = 0; index < bytes; ++index)
    {
        result[index] = static_cast<std::uint8_t>(
            (offset + index) % 251U);
    }
    return result;
}

void receiveRange(
    RemoteTransfer &owner,
    MacClipboardFileDestination &destination,
    const MacClipboardFileDestination::RequestIntent &intent,
    std::span<const std::uint8_t> bytes)
{
    std::vector<std::uint8_t> request;
    const auto receipt = owner.beginFileRangeRequest(
        intent.fileIndex, intent.offset,
        intent.requestedBytes, request);
    assert(receipt);
    assert(destination.bindRequest(*receipt));

    const auto wire = fileContentsResponsePdu(
        rdp_server::clipboard::kResponseOk,
        receipt->streamId, bytes);
    const auto result = owner.receiveFileContentsResponse(wire);
    assert(result.status ==
           RemoteTransfer::FileContentsStatus::ReceivedRange);
    assert(destination.acceptResult(result));
}

void macosFileDestinationStreaming()
{
    constexpr std::uint64_t kFileBytes = 70000U;
    RemoteTransfer owner;
    installSingleFileOffer(
        owner, u"payload.bin", true, kFileBytes);

    FakeNative native;
    native.bytes.assign(5U, std::byte{0x7f});
    MacClipboardFileDestination destination{
        owner, native.operations()};
    assert(destination.valid());
    assert(destination.begin(0, native.sourceToken));
    assert(native.bytes.empty());

    const auto first = destination.nextRequestIntent();
    assert(first);
    assert(first->offset == 0U);
    assert(first->requestedBytes ==
           RemoteTransfer::kMaximumFileContentsChunkBytes);
    const auto firstChunk =
        makeChunk(first->offset, first->requestedBytes);
    receiveRange(owner, destination, *first, firstChunk);

    const auto second = destination.nextRequestIntent();
    assert(second);
    assert(second->offset ==
           RemoteTransfer::kMaximumFileContentsChunkBytes);
    const auto secondChunk =
        makeChunk(second->offset, second->requestedBytes);
    receiveRange(owner, destination, *second, secondChunk);

    assert(destination.status() ==
           MacClipboardFileDestination::Status::Complete);
    assert(destination.bytesWritten() == kFileBytes);
    assert(native.bytes.size() == kFileBytes);
    assert(native.flushCalls == 1U);
    assert(native.closeCalls == 1U);
    assert(native.closed);
    for (const std::uint64_t offset :
         std::array<std::uint64_t, 5>{
             0U, 65535U, 65536U, 69998U, 69999U})
    {
        assert(static_cast<std::uint8_t>(
                   native.bytes[static_cast<std::size_t>(offset)]) ==
               static_cast<std::uint8_t>(offset % 251U));
    }
}

void macosFileDestinationSizeCancellation()
{
    RemoteTransfer owner;
    installSingleFileOffer(
        owner, u"unknown.bin", false, 0U);
    FakeNative native;
    MacClipboardFileDestination destination{
        owner, native.operations()};
    assert(destination.begin(0, native.sourceToken));
    assert(destination.status() ==
           MacClipboardFileDestination::Status::NeedSizeRequest);

    const auto intent = destination.nextRequestIntent();
    assert(intent && intent->requestedBytes == 8U);
    std::vector<std::uint8_t> request;
    const auto receipt = owner.beginFileSizeRequest(0, request);
    assert(receipt);
    assert(destination.bindRequest(*receipt));
    std::array<std::uint8_t, 8> sizeBytes{};
    put64(sizeBytes, 0, 10U);
    const auto wire = fileContentsResponsePdu(
        rdp_server::clipboard::kResponseOk,
        receipt->streamId, sizeBytes);
    const auto result = owner.receiveFileContentsResponse(wire);
    assert(result.status ==
           RemoteTransfer::FileContentsStatus::ReceivedSize);
    assert(destination.acceptResult(result));
    assert(destination.expectedSize() == 10U);

    const auto range = destination.nextRequestIntent();
    assert(range && range->requestedBytes == 10U);
    const auto shortChunk = makeChunk(0U, 4U);
    receiveRange(owner, destination, *range, shortChunk);
    assert(destination.bytesWritten() == 4U);
    destination.cancel();
    assert(destination.status() ==
           MacClipboardFileDestination::Status::Cancelled);
    assert(native.bytes.empty());
    assert(native.closeCalls == 1U);
}

void macosFileDestinationDestructorRetirement()
{
    RemoteTransfer owner;
    installSingleFileOffer(owner, u"partial.bin", true, 8U);

    FakeNative native;
    {
        MacClipboardFileDestination destination{
            owner, native.operations()};
        assert(destination.begin(0, native.sourceToken));

        const auto intent = destination.nextRequestIntent();
        assert(intent && intent->requestedBytes == 8U);
        const auto partial = makeChunk(0U, 4U);
        receiveRange(owner, destination, *intent, partial);

        assert(destination.active());
        assert(destination.bytesWritten() == partial.size());
        assert(native.bytes.size() == partial.size());
        assert(native.flushCalls == 0U);
        assert(native.closeCalls == 0U);
    }

    // Scope loss is terminal cancellation for a partial native destination:
    // the owned duplicate is truncated before close and is never flushed or
    // exposed as a completed file.
    assert(native.bytes.empty());
    assert(native.flushCalls == 0U);
    assert(native.closeCalls == 1U);
    assert(native.closed);
}

void macosFileDestinationWriteGenerationReplacement()
{
    RemoteTransfer owner;
    installSingleFileOffer(owner, u"replace-during-write.bin", true, 8U);
    FakeNative native;
    MacClipboardFileDestination destination{
        owner, native.operations()};
    assert(destination.begin(0, native.sourceToken));

    const std::uint64_t originalGeneration = destination.generation();
    const auto intent = destination.nextRequestIntent();
    assert(intent && intent->requestedBytes == 8U);

    std::vector<std::uint8_t> request;
    const auto receipt = owner.beginFileRangeRequest(
        intent->fileIndex, intent->offset,
        intent->requestedBytes, request);
    assert(receipt);
    assert(destination.bindRequest(*receipt));

    const auto bytes = makeChunk(0U, 4U);
    const auto wire = fileContentsResponsePdu(
        rdp_server::clipboard::kResponseOk,
        receipt->streamId, bytes);
    const auto result = owner.receiveFileContentsResponse(wire);
    assert(result.status ==
           RemoteTransfer::FileContentsStatus::ReceivedRange);

    // The native write accepts bytes, then a new clipboard source replaces
    // this destination's generation before the callback returns.
    native.replaceSourceOnWrite = &owner;
    assert(!destination.acceptResult(result));
    assert(owner.generation() > originalGeneration);
    assert(destination.status() ==
           MacClipboardFileDestination::Status::SourceReplaced);
    assert(destination.bytesWritten() == 0U);
    assert(native.bytes.empty());
    assert(native.flushCalls == 0U);
    assert(native.closeCalls == 1U);
    assert(native.closed);
    assert(native.replaceSourceOnWrite == nullptr);
}

void macosFileDestinationDenials()
{
    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"url.bin", true, 4U);
        FakeNative native;
        MacClipboardFileDestination destination{
            owner, native.operations()};
        assert(!destination.begin(
            0, native.sourceToken, "https://example.test/url.bin"));
        assert(!destination.begin(
            0, native.sourceToken, "file:///tmp/has space.bin"));
        assert(destination.status() ==
               MacClipboardFileDestination::Status::Idle);
        assert(native.duplicateCalls == 0U);
    }

    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"replace.bin", true, 8U);
        FakeNative native;
        MacClipboardFileDestination destination{
            owner, native.operations()};
        assert(destination.begin(0, native.sourceToken));
        const auto intent = destination.nextRequestIntent();
        assert(intent);
        const auto bytes = makeChunk(0U, 4U);
        receiveRange(owner, destination, *intent, bytes);
        assert(native.bytes.size() == 4U);

        assert(owner.receiveFormatList(
            std::array<std::uint32_t, 1>{
                rdp_server::clipboard::kFormatUnicodeText}));
        destination.onRemoteGenerationChanged();
        assert(destination.status() ==
               MacClipboardFileDestination::Status::SourceReplaced);
        assert(native.bytes.empty());
    }

    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"failure.bin", true, 4U);
        FakeNative native;
        MacClipboardFileDestination destination{
            owner, native.operations()};
        assert(destination.begin(0, native.sourceToken));
        const auto intent = destination.nextRequestIntent();
        assert(intent);
        std::vector<std::uint8_t> request;
        const auto receipt = owner.beginFileRangeRequest(
            intent->fileIndex, intent->offset,
            intent->requestedBytes, request);
        assert(receipt);
        assert(destination.bindRequest(*receipt));
        const auto wire = fileContentsResponsePdu(
            rdp_server::clipboard::kResponseFail,
            receipt->streamId);
        const auto result = owner.receiveFileContentsResponse(wire);
        assert(result.status ==
               RemoteTransfer::FileContentsStatus::RemoteFailure);
        assert(!destination.acceptResult(result));
        assert(destination.status() ==
               MacClipboardFileDestination::Status::RemoteFailure);
        assert(native.bytes.empty());
    }

    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"io.bin", true, 4U);
        FakeNative native;
        native.failWrite = true;
        MacClipboardFileDestination destination{
            owner, native.operations()};
        assert(destination.begin(0, native.sourceToken));
        const auto intent = destination.nextRequestIntent();
        assert(intent);
        const auto bytes = makeChunk(0U, 4U);
        std::vector<std::uint8_t> request;
        const auto receipt = owner.beginFileRangeRequest(
            0, 0, 4U, request);
        assert(receipt);
        assert(destination.bindRequest(*receipt));
        const auto wire = fileContentsResponsePdu(
            rdp_server::clipboard::kResponseOk,
            receipt->streamId, bytes);
        const auto result = owner.receiveFileContentsResponse(wire);
        assert(!destination.acceptResult(result));
        assert(destination.status() ==
               MacClipboardFileDestination::Status::NativeError);
        assert(native.bytes.empty());
    }
}


void macosCompletedMultiFileUrlHandoff()
{
    using Plan = RemoteFileDestinationPlan;
    constexpr std::string_view kFirstFileUrl{
        "file:///tmp/rdp-server-macos-first.bin"};
    constexpr std::string_view kSecondFileUrl{
        "file:///tmp/rdp-server-macos-second.bin"};

    RemoteTransfer owner;
    const std::array<OfferedFile, 2> files{{
        {u"duplicate.bin", true, 4U},
        {u"duplicate.bin", true, 6U},
    }};
    installFileOffer(owner, files);

    const std::array<Plan::Selection, 2> selections{{
        {0U, 0x7201U, std::nullopt},
        {1U, 0x7202U, std::nullopt},
    }};
    Plan plan;
    assert(plan.prepare(owner, owner.generation(), selections) ==
           Plan::PrepareStatus::Prepared);

    FakeNative firstNative;
    FakeNative secondNative;
    MacClipboardFileDestination first{
        owner, firstNative.operations()};
    MacClipboardFileDestination second{
        owner, secondNative.operations()};
    assert(first.begin(
        0U, firstNative.sourceToken, kFirstFileUrl));
    assert(second.begin(
        1U, secondNative.sourceToken, kSecondFileUrl));

    FakePasteboard pasteboard;
    MacClipboardAdapter adapter{owner, pasteboard.operations()};
    const std::array<const MacClipboardFileDestination *, 2>
        reversedDestinations{{&second, &first}};

    const auto firstIntent = first.nextRequestIntent();
    assert(firstIntent && firstIntent->fileIndex == 0U);
    receiveRange(
        owner, first, *firstIntent,
        makeChunk(firstIntent->offset, firstIntent->requestedBytes));
    assert(first.status() ==
           MacClipboardFileDestination::Status::Complete);
    assert(!adapter.publishCompletedFileDestinations(
        plan, reversedDestinations));
    assert(pasteboard.replaceCalls == 0U);

    const auto secondIntent = second.nextRequestIntent();
    assert(secondIntent && secondIntent->fileIndex == 1U);
    receiveRange(
        owner, second, *secondIntent,
        makeChunk(secondIntent->offset, secondIntent->requestedBytes));
    assert(second.status() ==
           MacClipboardFileDestination::Status::Complete);

    const std::array<const MacClipboardFileDestination *, 2>
        duplicateDestinations{{&first, &first}};
    assert(!adapter.publishCompletedFileDestinations(
        plan, duplicateDestinations));
    assert(pasteboard.replaceCalls == 0U);

    assert(adapter.publishCompletedFileDestinations(
        plan, reversedDestinations));
    assert(adapter.ownsPasteboard());
    assert(adapter.publicationGeneration() == owner.generation());
    assert(pasteboard.hasFileUrl);
    assert(pasteboard.fileUrls.size() == 2U);
    assert(pasteboard.fileUrls[0] == kFirstFileUrl);
    assert(pasteboard.fileUrls[1] == kSecondFileUrl);

    pasteboard.localTakeover();
    const unsigned replacementsBeforeTakeover =
        pasteboard.replaceCalls;
    const unsigned clearsBeforeTakeover = pasteboard.clearCalls;
    assert(!adapter.observePasteboardChange());
    assert(!adapter.publishCompletedFileDestinations(
        plan, reversedDestinations));
    assert(pasteboard.replaceCalls == replacementsBeforeTakeover);
    assert(pasteboard.clearCalls == clearsBeforeTakeover);
    assert(pasteboard.fileUrls.size() == 1U);
    assert(pasteboard.fileUrls[0] ==
           "file:///tmp/local-owner.txt");

    plan.cancel();
    assert(!adapter.publishCompletedFileDestinations(
        plan, reversedDestinations));

    Plan rollbackPlan;
    assert(rollbackPlan.prepare(
               owner, owner.generation(), selections) ==
           Plan::PrepareStatus::Prepared);
    FakePasteboard rollbackPasteboard;
    MacClipboardAdapter rollbackAdapter{
        owner, rollbackPasteboard.operations()};
    rollbackPasteboard.planToCancelOnReplace = &rollbackPlan;
    assert(!rollbackAdapter.publishCompletedFileDestinations(
        rollbackPlan, reversedDestinations));
    assert(!rollbackPlan.committed());
    assert(rollbackPasteboard.fileUrls.empty());
    assert(rollbackPasteboard.clearCalls == 1U);
    assert(!rollbackAdapter.ownsPasteboard());
}

void macosCompletedFileUrlHandoff()
{
    constexpr std::string_view kLocalFileUrl{
        "file:///tmp/rdp-server-macos-complete.bin"};

    RemoteTransfer owner;
    installSingleFileOffer(owner, u"remote-name.bin", true, 4U);

    FakeNative fileNative;
    MacClipboardFileDestination destination{
        owner, fileNative.operations()};
    assert(destination.begin(
        0, fileNative.sourceToken, kLocalFileUrl));
    assert(!destination.completedFileUrl());

    FakePasteboard pasteboard;
    MacClipboardAdapter adapter{owner, pasteboard.operations()};
    assert(!adapter.publishCompletedFileDestination(destination));
    assert(pasteboard.replaceCalls == 0U);

    const auto intent = destination.nextRequestIntent();
    assert(intent && intent->requestedBytes == 4U);
    const auto bytes = makeChunk(0U, 4U);
    receiveRange(owner, destination, *intent, bytes);
    assert(destination.status() ==
           MacClipboardFileDestination::Status::Complete);
    const auto completedUrl = destination.completedFileUrl();
    assert(completedUrl && *completedUrl == kLocalFileUrl);

    assert(adapter.publishCompletedFileDestination(destination));
    assert(adapter.ownsPasteboard());
    assert(adapter.publicationGeneration() == owner.generation());
    assert(pasteboard.hasFileUrl);
    assert(pasteboard.fileUrl == kLocalFileUrl);

    // A local owner wins the change-count race. R8 must not steal the same
    // generation back even though the completed local file still exists.
    pasteboard.localTakeover();
    const unsigned replacementsBeforeTakeover =
        pasteboard.replaceCalls;
    const unsigned clearsBeforeTakeover = pasteboard.clearCalls;
    assert(!adapter.observePasteboardChange());
    assert(!adapter.publishCompletedFileDestination(destination));
    assert(pasteboard.replaceCalls == replacementsBeforeTakeover);
    assert(pasteboard.clearCalls == clearsBeforeTakeover);
    assert(pasteboard.fileUrl == "file:///tmp/local-owner.txt");

    // A completed materialization is generation-bound and cannot be handed
    // off after a newer remote clipboard offer replaces its source.
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    assert(!adapter.publishCompletedFileDestination(destination));
}

#if defined(__APPLE__)
class ScopedMacFile final
{
public:
    ScopedMacFile()
    {
        path_ =
            "rdp-server-macos-file-destination-" +
            std::to_string(static_cast<long long>(::getpid())) +
            ".bin";
        descriptor_ = ::open(
            path_.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0600);
        assert(descriptor_ >= 0);
    }

    ~ScopedMacFile()
    {
        if (descriptor_ >= 0)
        {
            (void)::close(descriptor_);
        }
        (void)::unlink(path_.c_str());
    }

    [[nodiscard]] int descriptor() const noexcept
    {
        return descriptor_;
    }

private:
    std::string path_{};
    int descriptor_{-1};
};

void macosFileDestinationNativeDescriptor()
{
    constexpr std::uint64_t kFileBytes = 32U;
    RemoteTransfer owner;
    installSingleFileOffer(
        owner, u"native.bin", true, kFileBytes);

    ScopedMacFile file;
    MacClipboardFileDestination destination{
        owner, makeMacClipboardFileNativeOperations()};
    assert(destination.begin(
        0, static_cast<MacClipboardFileDescriptorToken>(
               file.descriptor())));

    const auto intent = destination.nextRequestIntent();
    assert(intent && intent->requestedBytes == kFileBytes);
    const auto bytes = makeChunk(0U, kFileBytes);
    receiveRange(owner, destination, *intent, bytes);
    assert(destination.status() ==
           MacClipboardFileDestination::Status::Complete);

    struct stat metadata{};
    assert(::fstat(file.descriptor(), &metadata) == 0);
    assert(metadata.st_size ==
           static_cast<off_t>(kFileBytes));

    std::array<std::uint8_t, kFileBytes> readBack{};
    ssize_t readBytes = -1;
    do
    {
        readBytes = ::pread(
            file.descriptor(), readBack.data(),
            readBack.size(), 0);
    } while (readBytes < 0 && errno == EINTR);
    assert(readBytes ==
           static_cast<ssize_t>(readBack.size()));
    assert(std::equal(
        bytes.begin(), bytes.end(), readBack.begin()));
}
#endif

} // namespace

int main(int argc, char **argv)
{
    assert(argc == 2);
    const std::string_view behavior{argv[1]};
    if (behavior == "macos-file-destination-streaming")
    {
        macosFileDestinationStreaming();
        return 0;
    }
    if (behavior == "macos-file-destination-size-cancel")
    {
        macosFileDestinationSizeCancellation();
        return 0;
    }
    if (behavior == "macos-file-destination-destructor-retirement")
    {
        macosFileDestinationDestructorRetirement();
        return 0;
    }
    if (behavior == "macos-file-destination-write-generation-replacement")
    {
        macosFileDestinationWriteGenerationReplacement();
        return 0;
    }
    if (behavior == "macos-file-destination-denials")
    {
        macosFileDestinationDenials();
        return 0;
    }
    if (behavior == "macos-completed-file-url-handoff")
    {
        macosCompletedFileUrlHandoff();
        return 0;
    }
    if (behavior == "macos-completed-multi-file-url-handoff")
    {
        macosCompletedMultiFileUrlHandoff();
        return 0;
    }
#if defined(__APPLE__)
    if (behavior == "macos-file-destination-native-descriptor")
    {
        macosFileDestinationNativeDescriptor();
        return 0;
    }
#endif
    assert(false && "unknown macOS clipboard file destination behavior");
    return 1;
}
