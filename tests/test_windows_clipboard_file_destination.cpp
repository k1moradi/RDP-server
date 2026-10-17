// SPDX-License-Identifier: GPL-3.0-or-later
#include "clipboard/clipboard_protocol.h"
#include "server/clipboard/remote_transfer.h"
#include "windows/windows_clipboard_adapter.h"
#include "windows/windows_clipboard_file_destination.h"

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

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

using rdp_server::server::clipboard::RemoteFileDestinationPlan;
using rdp_server::server::clipboard::RemoteTransfer;
using namespace rdp_server::windows;

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
    WindowsClipboardFileHandleToken sourceToken{0x101U};
    WindowsClipboardFileHandleToken ownedToken{0x202U};
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

    static bool duplicate(
        void *context, WindowsClipboardFileHandleToken source,
        WindowsClipboardFileHandleToken &owned) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.duplicateCalls;
        if (self.failDuplicate || source != self.sourceToken)
        {
            owned = 0U;
            return false;
        }
        self.closed = false;
        owned = self.ownedToken;
        return true;
    }

    static bool resize(
        void *context, WindowsClipboardFileHandleToken token,
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
        void *context, WindowsClipboardFileHandleToken token,
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
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    static bool flush(
        void *context,
        WindowsClipboardFileHandleToken token) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.flushCalls;
        return !self.failFlush && token == self.ownedToken;
    }

    static void close(
        void *context,
        WindowsClipboardFileHandleToken token) noexcept
    {
        auto &self = *static_cast<FakeNative *>(context);
        ++self.closeCalls;
        assert(token == self.ownedToken);
        self.closed = true;
    }

    [[nodiscard]] WindowsClipboardFileNativeOperations
    operations() noexcept
    {
        return {
            this, &duplicate, &resize, &write, &flush, &close};
    }
};

struct FakeClipboard final
{
    struct Write final
    {
        WindowsClipboardFormat format{};
        std::vector<std::byte> bytes{};
    };

    static constexpr WindowsClipboardWindowToken kOwnerWindow = 0x3030U;
    static constexpr WindowsClipboardFormat kPngFormat = 0xc303U;

    std::vector<Write> writes{};
    WindowsClipboardWindowToken currentOwner{};
    WindowsClipboardWindowToken openedFor{};
    unsigned openCalls{};
    unsigned emptyCalls{};
    unsigned closeCalls{};
    bool opened{};
    WindowsClipboardAdapter *adapter{};
    RemoteFileDestinationPlan *planToCancelOnWrite{};

    static WindowsClipboardFormat registerFormat(
        void *context, std::string_view name) noexcept
    {
        auto &self = *static_cast<FakeClipboard *>(context);
        assert(name == "PNG");
        return self.kPngFormat;
    }

    static bool openClipboard(
        void *context, WindowsClipboardWindowToken owner) noexcept
    {
        auto &self = *static_cast<FakeClipboard *>(context);
        ++self.openCalls;
        self.opened = true;
        self.openedFor = owner;
        return true;
    }

    static bool emptyClipboard(void *context) noexcept
    {
        auto &self = *static_cast<FakeClipboard *>(context);
        ++self.emptyCalls;
        if (!self.opened)
        {
            return false;
        }
        const bool replacingSelf =
            self.currentOwner == self.openedFor &&
            self.adapter != nullptr;
        self.currentOwner = self.openedFor;
        self.writes.clear();
        if (replacingSelf)
        {
            self.adapter->onDestroyClipboard();
        }
        return true;
    }

    static bool setDelayedFormat(
        void *, WindowsClipboardFormat) noexcept
    {
        return true;
    }

    static bool setFormatBytes(
        void *context, WindowsClipboardFormat format,
        std::span<const std::byte> bytes) noexcept
    {
        auto &self = *static_cast<FakeClipboard *>(context);
        if (!self.opened || bytes.empty())
        {
            return false;
        }
        self.writes.push_back(
            Write{format, std::vector<std::byte>{bytes.begin(), bytes.end()}});
        if (self.planToCancelOnWrite != nullptr)
        {
            self.planToCancelOnWrite->cancel();
            self.planToCancelOnWrite = nullptr;
        }
        return true;
    }

    static bool closeClipboard(void *context) noexcept
    {
        auto &self = *static_cast<FakeClipboard *>(context);
        ++self.closeCalls;
        if (!self.opened)
        {
            return false;
        }
        self.opened = false;
        return true;
    }

    static WindowsClipboardWindowToken clipboardOwner(
        void *context) noexcept
    {
        return static_cast<FakeClipboard *>(context)->currentOwner;
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

    void localTakeover() noexcept
    {
        currentOwner = 0x9090U;
        if (adapter != nullptr)
        {
            adapter->onDestroyClipboard();
        }
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
    WindowsClipboardFileDestination &destination,
    const WindowsClipboardFileDestination::RequestIntent &intent,
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

void windowsFileDestinationStreaming()
{
    constexpr std::uint64_t kFileBytes = 70000U;
    RemoteTransfer owner;
    installSingleFileOffer(
        owner, u"payload.bin", true, kFileBytes);

    FakeNative native;
    native.bytes.assign(5U, std::byte{0x7f});
    WindowsClipboardFileDestination destination{
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
           WindowsClipboardFileDestination::Status::Complete);
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

void windowsFileDestinationSizeCancellation()
{
    RemoteTransfer owner;
    installSingleFileOffer(
        owner, u"unknown.bin", false, 0U);
    FakeNative native;
    WindowsClipboardFileDestination destination{
        owner, native.operations()};
    assert(destination.begin(0, native.sourceToken));
    assert(destination.status() ==
           WindowsClipboardFileDestination::Status::NeedSizeRequest);

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
           WindowsClipboardFileDestination::Status::Cancelled);
    assert(native.bytes.empty());
    assert(native.closeCalls == 1U);
}

void windowsFileDestinationDestructorRetirement()
{
    RemoteTransfer owner;
    installSingleFileOffer(owner, u"partial.bin", true, 8U);

    FakeNative native;
    {
        WindowsClipboardFileDestination destination{
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
    // the owned HANDLE duplicate is truncated before close and never flushed
    // or exposed as a completed file.
    assert(native.bytes.empty());
    assert(native.flushCalls == 0U);
    assert(native.closeCalls == 1U);
    assert(native.closed);
}

void windowsFileDestinationDenials()
{
    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"path.bin", true, 4U);
        FakeNative native;
        WindowsClipboardFileDestination destination{
            owner, native.operations()};
        assert(!destination.begin(
            0, native.sourceToken, u"relative\\path.bin"));
        assert(!destination.begin(
            0, native.sourceToken, u"\\\\?\\C:\\device.bin"));
        assert(destination.status() ==
               WindowsClipboardFileDestination::Status::Idle);
        assert(native.duplicateCalls == 0U);
    }

    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"replace.bin", true, 8U);
        FakeNative native;
        WindowsClipboardFileDestination destination{
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
               WindowsClipboardFileDestination::Status::SourceReplaced);
        assert(native.bytes.empty());
    }

    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"failure.bin", true, 4U);
        FakeNative native;
        WindowsClipboardFileDestination destination{
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
               WindowsClipboardFileDestination::Status::RemoteFailure);
        assert(native.bytes.empty());
    }

    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"io.bin", true, 4U);
        FakeNative native;
        native.failWrite = true;
        WindowsClipboardFileDestination destination{
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
               WindowsClipboardFileDestination::Status::NativeError);
        assert(native.bytes.empty());
    }
}


void fileDestinationPlanNativeCapabilityIntegration()
{
    using Plan = RemoteFileDestinationPlan;
    constexpr std::u16string_view kLocalPath{
        u"C:\\Temp\\rdp-server-plan-capability.bin"};

    RemoteTransfer owner;
    installSingleFileOffer(owner, u"remote.bin", true, 4U);

    const std::array<Plan::Selection, 1> selections{{
        {0U, 0x303U, std::nullopt},
    }};
    Plan plan;
    assert(plan.prepare(owner, owner.generation(), selections) ==
           Plan::PrepareStatus::Prepared);
    const auto association = plan.association(owner, 0U);
    assert(association);
    assert(plan.associationStatus(owner, 0U) ==
           Plan::AssociationStatus::CurrentFile);

    // Stable selection metadata is deliberately not a writable capability.
    FakeNative metadataOnlyNative;
    WindowsClipboardFileDestination metadataOnlyDestination{
        owner, metadataOnlyNative.operations()};
    assert(!metadataOnlyDestination.begin(
        association->remoteFileIndex,
        static_cast<WindowsClipboardFileHandleToken>(
            association->localSelectionIdentity)));
    assert(metadataOnlyNative.duplicateCalls == 1U);
    assert(metadataOnlyNative.bytes.empty());

    // The real materializer gets the planned source index plus a separate
    // caller-selected native handle and remains the writable-resource owner.
    FakeNative native;
    WindowsClipboardFileDestination destination{
        owner, native.operations()};
    assert(destination.begin(
        association->remoteFileIndex, native.sourceToken, kLocalPath));
    assert(native.duplicateCalls == 1U);

    FakeClipboard clipboard;
    WindowsClipboardAdapter adapter{
        owner, clipboard.operations(), FakeClipboard::kOwnerWindow};
    clipboard.adapter = &adapter;
    assert(!adapter.publishCompletedFileDestination(destination));

    const auto intent = destination.nextRequestIntent();
    assert(intent && intent->fileIndex == association->remoteFileIndex);
    std::vector<std::uint8_t> request;
    const auto receipt = owner.beginFileRangeRequest(
        intent->fileIndex, intent->offset,
        intent->requestedBytes, request);
    assert(receipt);
    assert(destination.bindRequest(*receipt));
    assert(owner.hasOutstandingFileContentsRequest());

    plan.cancel();
    destination.cancel();
    assert(destination.status() ==
           WindowsClipboardFileDestination::Status::Cancelled);
    assert(!destination.completedFilePath());
    assert(native.bytes.empty());
    assert(!adapter.publishCompletedFileDestination(destination));

    // RemoteTransfer drains the one exact outstanding response, but neither
    // cancelled association can become complete or publishable again.
    const std::array<std::uint8_t, 4> bytes{1U, 2U, 3U, 4U};
    const auto wire = fileContentsResponsePdu(
        rdp_server::clipboard::kResponseOk,
        receipt->streamId, bytes);
    const auto result = owner.receiveFileContentsResponse(wire);
    assert(result.status ==
           RemoteTransfer::FileContentsStatus::ReceivedRange);
    assert(!owner.hasOutstandingFileContentsRequest());
    assert(!destination.acceptResult(result));
    assert(destination.status() ==
           WindowsClipboardFileDestination::Status::Cancelled);
    assert(plan.associationStatus(owner, 0U) ==
           Plan::AssociationStatus::Cancelled);
    assert(!adapter.publishCompletedFileDestination(destination));
    assert(clipboard.writes.empty());
}


void windowsCompletedMultiFileHdropHandoff()
{
    using Plan = RemoteFileDestinationPlan;
    constexpr std::u16string_view kFirstPath{
        u"C:\\Temp\\rdp-server-windows-first.bin"};
    constexpr std::u16string_view kSecondPath{
        u"C:\\Temp\\rdp-server-windows-second.bin"};

    RemoteTransfer owner;
    const std::array<OfferedFile, 2> files{{
        {u"duplicate.bin", true, 4U},
        {u"duplicate.bin", true, 6U},
    }};
    installFileOffer(owner, files);

    const std::array<Plan::Selection, 2> selections{{
        {0U, 0x7101U, std::nullopt},
        {1U, 0x7102U, std::nullopt},
    }};
    Plan plan;
    assert(plan.prepare(owner, owner.generation(), selections) ==
           Plan::PrepareStatus::Prepared);

    FakeNative firstNative;
    FakeNative secondNative;
    WindowsClipboardFileDestination first{
        owner, firstNative.operations()};
    WindowsClipboardFileDestination second{
        owner, secondNative.operations()};
    assert(first.begin(0U, firstNative.sourceToken, kFirstPath));
    assert(second.begin(1U, secondNative.sourceToken, kSecondPath));

    FakeClipboard clipboard;
    WindowsClipboardAdapter adapter{
        owner, clipboard.operations(), FakeClipboard::kOwnerWindow};
    clipboard.adapter = &adapter;

    const std::array<const WindowsClipboardFileDestination *, 2>
        reversedDestinations{{&second, &first}};

    const auto firstIntent = first.nextRequestIntent();
    assert(firstIntent && firstIntent->fileIndex == 0U);
    receiveRange(
        owner, first, *firstIntent,
        makeChunk(firstIntent->offset, firstIntent->requestedBytes));
    assert(first.status() ==
           WindowsClipboardFileDestination::Status::Complete);
    assert(!adapter.publishCompletedFileDestinations(
        plan, reversedDestinations));
    assert(clipboard.writes.empty());

    const auto secondIntent = second.nextRequestIntent();
    assert(secondIntent && secondIntent->fileIndex == 1U);
    receiveRange(
        owner, second, *secondIntent,
        makeChunk(secondIntent->offset, secondIntent->requestedBytes));
    assert(second.status() ==
           WindowsClipboardFileDestination::Status::Complete);

    const std::array<const WindowsClipboardFileDestination *, 2>
        duplicateDestinations{{&first, &first}};
    assert(!adapter.publishCompletedFileDestinations(
        plan, duplicateDestinations));
    assert(clipboard.writes.empty());

    assert(adapter.publishCompletedFileDestinations(
        plan, reversedDestinations));
    assert(adapter.ownsClipboard());
    assert(adapter.publicationGeneration() == owner.generation());
    assert(clipboard.writes.size() == 1U);

    const auto &drop = clipboard.writes.front();
    assert(drop.format == WindowsClipboardAdapter::kFileDropFormat);
    const std::size_t expectedCodeUnits =
        kFirstPath.size() + 1U +
        kSecondPath.size() + 1U + 1U;
    assert(drop.bytes.size() == 20U + expectedCodeUnits * 2U);

    const auto byteAt = [&drop](const std::size_t index)
    {
        return static_cast<std::uint8_t>(drop.bytes[index]);
    };
    assert(byteAt(0) == 20U && byteAt(1) == 0U &&
           byteAt(2) == 0U && byteAt(3) == 0U);
    assert(byteAt(16) == 1U && byteAt(17) == 0U &&
           byteAt(18) == 0U && byteAt(19) == 0U);

    std::size_t offset = 20U;
    const auto expectPath =
        [&byteAt, &offset](const std::u16string_view path)
    {
        for (const char16_t codeUnit : path)
        {
            const auto value = static_cast<std::uint16_t>(codeUnit);
            assert(byteAt(offset++) ==
                   static_cast<std::uint8_t>(value));
            assert(byteAt(offset++) ==
                   static_cast<std::uint8_t>(value >> 8U));
        }
        assert(byteAt(offset++) == 0U);
        assert(byteAt(offset++) == 0U);
    };
    expectPath(kFirstPath);
    expectPath(kSecondPath);
    assert(byteAt(offset++) == 0U);
    assert(byteAt(offset++) == 0U);
    assert(offset == drop.bytes.size());

    const std::size_t writesBeforeTakeover = clipboard.writes.size();
    clipboard.localTakeover();
    assert(!adapter.ownsClipboard());
    assert(!adapter.publishCompletedFileDestinations(
        plan, reversedDestinations));
    assert(clipboard.writes.size() == writesBeforeTakeover);

    plan.cancel();
    assert(!adapter.publishCompletedFileDestinations(
        plan, reversedDestinations));

    Plan rollbackPlan;
    assert(rollbackPlan.prepare(
               owner, owner.generation(), selections) ==
           Plan::PrepareStatus::Prepared);
    FakeClipboard rollbackClipboard;
    WindowsClipboardAdapter rollbackAdapter{
        owner, rollbackClipboard.operations(),
        FakeClipboard::kOwnerWindow};
    rollbackClipboard.adapter = &rollbackAdapter;
    rollbackClipboard.planToCancelOnWrite = &rollbackPlan;
    assert(!rollbackAdapter.publishCompletedFileDestinations(
        rollbackPlan, reversedDestinations));
    assert(!rollbackPlan.committed());
    assert(rollbackClipboard.writes.empty());
    assert(!rollbackAdapter.ownsClipboard());
}

void windowsCompletedFileHdropHandoff()
{
    constexpr std::u16string_view kLocalPath{
        u"C:\\Temp\\rdp-server-windows-complete.bin"};

    RemoteTransfer owner;
    installSingleFileOffer(owner, u"remote-name.bin", true, 4U);

    FakeNative fileNative;
    WindowsClipboardFileDestination destination{
        owner, fileNative.operations()};
    assert(destination.begin(
        0, fileNative.sourceToken, kLocalPath));
    assert(!destination.completedFilePath());

    FakeClipboard clipboard;
    WindowsClipboardAdapter adapter{
        owner, clipboard.operations(), FakeClipboard::kOwnerWindow};
    clipboard.adapter = &adapter;
    assert(!adapter.publishCompletedFileDestination(destination));
    assert(clipboard.writes.empty());

    const auto intent = destination.nextRequestIntent();
    assert(intent && intent->requestedBytes == 4U);
    const auto bytes = makeChunk(0U, 4U);
    receiveRange(owner, destination, *intent, bytes);
    assert(destination.status() ==
           WindowsClipboardFileDestination::Status::Complete);
    const auto completedPath = destination.completedFilePath();
    assert(completedPath && *completedPath == kLocalPath);

    assert(adapter.publishCompletedFileDestination(destination));
    assert(adapter.ownsClipboard());
    assert(adapter.publicationGeneration() == owner.generation());
    assert(clipboard.writes.size() == 1U);
    const auto &drop = clipboard.writes.front();
    assert(drop.format == WindowsClipboardAdapter::kFileDropFormat);
    assert(drop.bytes.size() == 20U + (kLocalPath.size() + 2U) * 2U);
    const auto byteAt = [&drop](const std::size_t index)
    {
        return static_cast<std::uint8_t>(drop.bytes[index]);
    };
    assert(byteAt(0) == 20U && byteAt(1) == 0U &&
           byteAt(2) == 0U && byteAt(3) == 0U);
    assert(byteAt(16) == 1U && byteAt(17) == 0U &&
           byteAt(18) == 0U && byteAt(19) == 0U);
    for (std::size_t index = 0; index < kLocalPath.size(); ++index)
    {
        const auto codeUnit = static_cast<std::uint16_t>(kLocalPath[index]);
        const std::size_t offset = 20U + index * 2U;
        assert(byteAt(offset) == static_cast<std::uint8_t>(codeUnit));
        assert(byteAt(offset + 1U) ==
               static_cast<std::uint8_t>(codeUnit >> 8U));
    }
    for (std::size_t offset =
             20U + kLocalPath.size() * 2U;
         offset < drop.bytes.size(); ++offset)
    {
        assert(byteAt(offset) == 0U);
    }

    const std::size_t writesBeforeTakeover = clipboard.writes.size();
    clipboard.localTakeover();
    assert(!adapter.ownsClipboard());
    assert(!adapter.publishCompletedFileDestination(destination));
    assert(clipboard.writes.size() == writesBeforeTakeover);

    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{
            rdp_server::clipboard::kFormatUnicodeText}));
    assert(!adapter.publishCompletedFileDestination(destination));
}

#ifdef _WIN32
class ScopedWin32File final
{
public:
    ScopedWin32File()
    {
        const DWORD processId = ::GetCurrentProcessId();
        const std::wstring name =
            L"rdp-server-windows-file-destination-" +
            std::to_wstring(processId) + L".bin";
        path_ = name;
        handle_ = ::CreateFileW(
            path_.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY,
            nullptr);
        assert(handle_ != INVALID_HANDLE_VALUE);
    }

    ~ScopedWin32File()
    {
        if (handle_ != INVALID_HANDLE_VALUE)
        {
            (void)::CloseHandle(handle_);
        }
        (void)::DeleteFileW(path_.c_str());
    }

    [[nodiscard]] HANDLE handle() const noexcept { return handle_; }

private:
    std::wstring path_{};
    HANDLE handle_{INVALID_HANDLE_VALUE};
};

void windowsFileDestinationNativeHandle()
{
    constexpr std::uint64_t kFileBytes = 32U;
    RemoteTransfer owner;
    installSingleFileOffer(
        owner, u"native.bin", true, kFileBytes);

    ScopedWin32File file;
    WindowsClipboardFileDestination destination{
        owner, makeWindowsClipboardFileNativeOperations()};
    assert(destination.begin(
        0, reinterpret_cast<WindowsClipboardFileHandleToken>(
               file.handle())));

    const auto intent = destination.nextRequestIntent();
    assert(intent && intent->requestedBytes == kFileBytes);
    const auto bytes = makeChunk(0U, kFileBytes);
    receiveRange(owner, destination, *intent, bytes);
    assert(destination.status() ==
           WindowsClipboardFileDestination::Status::Complete);

    LARGE_INTEGER size{};
    assert(::GetFileSizeEx(file.handle(), &size));
    assert(size.QuadPart == static_cast<LONGLONG>(kFileBytes));

    LARGE_INTEGER zero{};
    assert(::SetFilePointerEx(
        file.handle(), zero, nullptr, FILE_BEGIN));
    std::array<std::uint8_t, kFileBytes> readBack{};
    DWORD read{};
    assert(::ReadFile(
        file.handle(), readBack.data(),
        static_cast<DWORD>(readBack.size()),
        &read, nullptr));
    assert(read == readBack.size());
    assert(std::equal(bytes.begin(), bytes.end(), readBack.begin()));
}
#endif

} // namespace

int main(int argc, char **argv)
{
    assert(argc == 2);
    const std::string_view behavior{argv[1]};
    if (behavior == "windows-file-destination-streaming")
    {
        windowsFileDestinationStreaming();
        return 0;
    }
    if (behavior == "windows-file-destination-size-cancel")
    {
        windowsFileDestinationSizeCancellation();
        return 0;
    }
    if (behavior == "windows-file-destination-destructor-retirement")
    {
        windowsFileDestinationDestructorRetirement();
        return 0;
    }
    if (behavior == "windows-file-destination-denials")
    {
        windowsFileDestinationDenials();
        return 0;
    }
    if (behavior == "windows-completed-file-hdrop-handoff")
    {
        windowsCompletedFileHdropHandoff();
        return 0;
    }
    if (behavior == "windows-completed-multi-file-hdrop-handoff")
    {
        windowsCompletedMultiFileHdropHandoff();
        return 0;
    }
    if (behavior == "file-destination-plan-native-capability-integration")
    {
        fileDestinationPlanNativeCapabilityIntegration();
        return 0;
    }
#ifdef _WIN32
    if (behavior == "windows-file-destination-native-handle")
    {
        windowsFileDestinationNativeHandle();
        return 0;
    }
#endif
    assert(false && "unknown Windows clipboard file destination behavior");
    return 1;
}
