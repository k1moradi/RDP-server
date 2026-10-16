// SPDX-License-Identifier: GPL-3.0-or-later
#include "clipboard/clipboard_protocol.h"
#include "server/clipboard/remote_transfer.h"
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

void installSingleFileOffer(
    RemoteTransfer &owner,
    const std::u16string_view name,
    const bool sizeKnown,
    const std::uint64_t size)
{
    assert(owner.receiveCapabilitiesPdu(
        capabilitiesPdu(kFileFlags), kFileFlags));

    std::vector<std::uint8_t> formats;
    appendLongFormat(
        formats, kFileListFormatId, "FileGroupDescriptorW");
    assert(owner.receiveLongFormatListPdu(longFormatPdu(formats)));

    std::vector<std::uint8_t> request;
    assert(owner.beginFileGroupDescriptorRequest(request));

    std::vector<std::uint8_t> list(4U + kDescriptorBytes, 0);
    put32(list, 0, 1U);
    auto descriptor =
        std::span(list).subspan(4U, kDescriptorBytes);
    if (sizeKnown)
    {
        put32(descriptor, 0, kFdFileSize);
        putDescriptorFileSize(descriptor, size);
    }
    putFileName(descriptor, name);

    const auto wire = formatDataResponsePdu(list);
    const auto response = owner.receiveResponse(wire);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(owner.storeFileGroupDescriptors(response));
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

void macosFileDestinationDenials()
{
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
    if (behavior == "macos-file-destination-denials")
    {
        macosFileDestinationDenials();
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
