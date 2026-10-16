// SPDX-License-Identifier: GPL-3.0-or-later
#include "clipboard/clipboard_protocol.h"
#include "platform/linux/linux_clipboard_file_destination.h"
#include "server/clipboard/remote_transfer.h"

#include <algorithm>
#include <array>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using rdp::linux_platform::LinuxClipboardFileDestination;
using rdp_server::server::clipboard::RemoteTransfer;

namespace
{

constexpr std::uint32_t kFileListFormatId = 0xc520U;
constexpr std::size_t kDescriptorBytes = 592U;
constexpr std::uint32_t kFdFileSize = 0x00000040U;
constexpr std::uint32_t kFileFlags =
    rdp_server::clipboard::kUseLongFormatNames |
    rdp_server::clipboard::kStreamFileclipEnabled |
    rdp_server::clipboard::kFileclipNoFilePaths |
    rdp_server::clipboard::kHugeFileSupportEnabled;

std::vector<std::uint8_t> capabilitiesPdu(
    const std::uint32_t generalFlags)
{
    const std::array<std::uint8_t, 16> payload{
        1, 0, 0, 0,
        1, 0, 12, 0,
        2, 0, 0, 0,
        static_cast<std::uint8_t>(generalFlags),
        static_cast<std::uint8_t>(generalFlags >> 8U),
        static_cast<std::uint8_t>(generalFlags >> 16U),
        static_cast<std::uint8_t>(generalFlags >> 24U),
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
    // FILEDESCRIPTORW stores the high DWORD before the low DWORD.
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

    const auto completeResponse = formatDataResponsePdu(list);
    const auto response = owner.receiveResponse(completeResponse);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(owner.storeFileGroupDescriptors(response));
    assert(owner.remoteFileCount() == 1U);
}

class ScopedTestFile final
{
public:
    ScopedTestFile(
        const std::string_view stem,
        const int flags = O_CREAT | O_RDWR | O_TRUNC)
        : path_(
              std::string{stem} + "-" +
              std::to_string(static_cast<long long>(::getpid())) +
              ".bin")
    {
        descriptor_ = ::open(path_.c_str(), flags, 0600);
        assert(descriptor_ >= 0);
    }

    ~ScopedTestFile()
    {
        if (descriptor_ >= 0)
        {
            (void)::close(descriptor_);
        }
        (void)::unlink(path_.c_str());
    }

    ScopedTestFile(const ScopedTestFile &) = delete;
    ScopedTestFile &operator=(const ScopedTestFile &) = delete;

    [[nodiscard]] int descriptor() const noexcept
    {
        return descriptor_;
    }

private:
    std::string path_{};
    int descriptor_{-1};
};

std::uint64_t fileSize(const int descriptor)
{
    struct stat metadata{};
    assert(::fstat(descriptor, &metadata) == 0);
    assert(metadata.st_size >= 0);
    return static_cast<std::uint64_t>(metadata.st_size);
}

std::uint8_t readByteAt(
    const int descriptor, const std::uint64_t offset)
{
    std::uint8_t byte{};
    ssize_t result = -1;
    do
    {
        result = ::pread(
            descriptor, &byte, 1,
            static_cast<off_t>(offset));
    } while (result < 0 && errno == EINTR);
    assert(result == 1);
    return byte;
}

std::vector<std::uint8_t> makeChunk(
    const std::uint64_t offset,
    const std::size_t bytes)
{
    std::vector<std::uint8_t> chunk(bytes);
    for (std::size_t index = 0; index < chunk.size(); ++index)
    {
        chunk[index] = static_cast<std::uint8_t>(
            (offset + index) % 251U);
    }
    return chunk;
}

void receiveRange(
    RemoteTransfer &owner,
    LinuxClipboardFileDestination &destination,
    const LinuxClipboardFileDestination::RequestIntent &intent,
    const std::span<const std::uint8_t> bytes)
{
    std::vector<std::uint8_t> request;
    const auto receipt = owner.beginFileRangeRequest(
        intent.fileIndex, intent.offset,
        intent.requestedBytes, request);
    assert(receipt);
    assert(destination.bindRequest(*receipt));

    const auto completeResponse = fileContentsResponsePdu(
        rdp_server::clipboard::kResponseOk,
        receipt->streamId, bytes);
    const auto result =
        owner.receiveFileContentsResponse(completeResponse);
    assert(result.status ==
           RemoteTransfer::FileContentsStatus::ReceivedRange);
    // FileContentsResult::bytes borrows completeResponse, so consume it
    // synchronously while the backing PDU remains alive.
    assert(destination.acceptResult(result));
}

void linuxFileDestinationStreaming()
{
    constexpr std::uint64_t kFileBytes = 70000U;

    RemoteTransfer owner;
    installSingleFileOffer(
        owner, u"payload.bin", true, kFileBytes);

    ScopedTestFile file{"linux-clipboard-streaming"};
    const std::array<std::uint8_t, 5> stale{
        's', 't', 'a', 'l', 'e'};
    assert(::write(
               file.descriptor(), stale.data(), stale.size()) ==
           static_cast<ssize_t>(stale.size()));

    LinuxClipboardFileDestination destination{owner};
    constexpr std::string_view kLocalFileUri{
        "file:///rdp-server-tests/payload.bin"};
    assert(destination.begin(
        0, file.descriptor(), kLocalFileUri));
    assert(!destination.completedFileUri());
    assert(fileSize(file.descriptor()) == 0U);
    assert(destination.status() ==
           LinuxClipboardFileDestination::Status::NeedRangeRequest);
    assert((std::u16string_view{
                destination.sourceName().data(),
                destination.sourceName().size()} == u"payload.bin"));

    const auto first = destination.nextRequestIntent();
    assert(first);
    assert(first->kind == RemoteTransfer::FileContentsKind::Range);
    assert(first->offset == 0U);
    assert(first->requestedBytes ==
           RemoteTransfer::kMaximumFileContentsChunkBytes);
    const auto firstChunk =
        makeChunk(first->offset, first->requestedBytes);
    receiveRange(owner, destination, *first, firstChunk);
    assert(destination.bytesWritten() ==
           RemoteTransfer::kMaximumFileContentsChunkBytes);
    assert(destination.status() ==
           LinuxClipboardFileDestination::Status::NeedRangeRequest);

    const auto second = destination.nextRequestIntent();
    assert(second);
    assert(second->offset ==
           RemoteTransfer::kMaximumFileContentsChunkBytes);
    assert(second->requestedBytes ==
           kFileBytes -
               RemoteTransfer::kMaximumFileContentsChunkBytes);
    const auto secondChunk =
        makeChunk(second->offset, second->requestedBytes);
    receiveRange(owner, destination, *second, secondChunk);

    assert(destination.status() ==
           LinuxClipboardFileDestination::Status::Complete);
    assert(!destination.active());
    assert(!destination.nextRequestIntent());
    assert(destination.bytesWritten() == kFileBytes);
    assert(destination.expectedSizeKnown());
    assert(destination.expectedSize() == kFileBytes);
    assert(destination.completedFileUri());
    assert(*destination.completedFileUri() == kLocalFileUri);
    assert(fileSize(file.descriptor()) == kFileBytes);

    for (const std::uint64_t offset :
         std::array<std::uint64_t, 5>{
             0U, 65535U, 65536U, 69998U, 69999U})
    {
        assert(readByteAt(file.descriptor(), offset) ==
               static_cast<std::uint8_t>(offset % 251U));
    }
}

void linuxFileDestinationSizeDiscoveryCancellation()
{
    RemoteTransfer owner;
    installSingleFileOffer(
        owner, u"unknown-size.bin", false, 0U);

    ScopedTestFile file{"linux-clipboard-size-cancel"};
    LinuxClipboardFileDestination destination{owner};
    assert(destination.begin(0, file.descriptor()));
    assert(destination.status() ==
           LinuxClipboardFileDestination::Status::NeedSizeRequest);

    const auto sizeIntent = destination.nextRequestIntent();
    assert(sizeIntent);
    assert(sizeIntent->kind == RemoteTransfer::FileContentsKind::Size);
    assert(sizeIntent->requestedBytes == 8U);

    std::vector<std::uint8_t> request;
    const auto sizeReceipt =
        owner.beginFileSizeRequest(0, request);
    assert(sizeReceipt);
    assert(destination.bindRequest(*sizeReceipt));
    std::array<std::uint8_t, 8> sizeBytes{};
    put64(sizeBytes, 0, 10U);
    const auto sizeWire = fileContentsResponsePdu(
        rdp_server::clipboard::kResponseOk,
        sizeReceipt->streamId, sizeBytes);
    const auto sizeResult =
        owner.receiveFileContentsResponse(sizeWire);
    assert(sizeResult.status ==
           RemoteTransfer::FileContentsStatus::ReceivedSize);
    assert(destination.acceptResult(sizeResult));
    assert(destination.expectedSize() == 10U);
    assert(destination.status() ==
           LinuxClipboardFileDestination::Status::NeedRangeRequest);

    const auto rangeIntent = destination.nextRequestIntent();
    assert(rangeIntent && rangeIntent->requestedBytes == 10U);
    const auto partialChunk =
        makeChunk(rangeIntent->offset, 4U);
    receiveRange(
        owner, destination, *rangeIntent, partialChunk);
    assert(destination.bytesWritten() == 4U);
    assert(fileSize(file.descriptor()) == 4U);

    destination.cancel();
    assert(destination.status() ==
           LinuxClipboardFileDestination::Status::Cancelled);
    assert(fileSize(file.descriptor()) == 0U);
}

void linuxFileDestinationSourceAndNativeDenials()
{
    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"uri.bin", true, 4U);
        ScopedTestFile file{"linux-clipboard-uri-denials"};
        LinuxClipboardFileDestination destination{owner};
        for (const std::string_view invalidUri :
             std::array<std::string_view, 6>{
                 "",
                 "file://remote-host/tmp/uri.bin",
                 "file:///tmp/bad path.bin",
                 "file:///tmp/bad\\path.bin",
                 "file:///tmp/bad#fragment",
                 "file:///tmp/bad%2"})
        {
            assert(!destination.begin(
                0, file.descriptor(), invalidUri));
            assert(destination.status() ==
                   LinuxClipboardFileDestination::Status::Idle);
            assert(!destination.completedFileUri());
        }
    }

    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"append.bin", true, 4U);
        ScopedTestFile file{"linux-clipboard-append"};
        const std::array<std::uint8_t, 3> existing{1, 2, 3};
        assert(::write(
                   file.descriptor(), existing.data(), existing.size()) ==
               static_cast<ssize_t>(existing.size()));
        const int flags = ::fcntl(file.descriptor(), F_GETFL);
        assert(flags >= 0);
        assert(::fcntl(
                   file.descriptor(), F_SETFL,
                   flags | O_APPEND) == 0);

        LinuxClipboardFileDestination destination{owner};
        assert(!destination.begin(0, file.descriptor()));
        assert(destination.status() ==
               LinuxClipboardFileDestination::Status::NativeError);
        assert(fileSize(file.descriptor()) == existing.size());
    }

    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"replace.bin", true, 8U);
        ScopedTestFile file{"linux-clipboard-replacement"};
        LinuxClipboardFileDestination destination{owner};
        assert(destination.begin(0, file.descriptor()));

        const auto intent = destination.nextRequestIntent();
        assert(intent && intent->requestedBytes == 8U);
        const auto firstBytes = makeChunk(0U, 4U);
        receiveRange(owner, destination, *intent, firstBytes);
        assert(fileSize(file.descriptor()) == 4U);

        assert(owner.receiveFormatList(
            std::array<std::uint32_t, 1>{
                rdp_server::clipboard::kFormatUnicodeText}));
        destination.onRemoteGenerationChanged();
        assert(destination.status() ==
               LinuxClipboardFileDestination::Status::SourceReplaced);
        assert(fileSize(file.descriptor()) == 0U);
    }

    {
        RemoteTransfer owner;
        installSingleFileOffer(owner, u"failure.bin", true, 4U);
        ScopedTestFile file{"linux-clipboard-remote-failure"};
        LinuxClipboardFileDestination destination{owner};
        assert(destination.begin(0, file.descriptor()));
        const auto intent = destination.nextRequestIntent();
        assert(intent);

        std::vector<std::uint8_t> request;
        const auto receipt = owner.beginFileRangeRequest(
            intent->fileIndex, intent->offset,
            intent->requestedBytes, request);
        assert(receipt);
        assert(destination.bindRequest(*receipt));

        const auto failedWire = fileContentsResponsePdu(
            rdp_server::clipboard::kResponseFail,
            receipt->streamId);
        const auto failed =
            owner.receiveFileContentsResponse(failedWire);
        assert(failed.status ==
               RemoteTransfer::FileContentsStatus::RemoteFailure);
        assert(!destination.acceptResult(failed));
        assert(destination.status() ==
               LinuxClipboardFileDestination::Status::RemoteFailure);
        assert(fileSize(file.descriptor()) == 0U);
    }
}

} // namespace

int main(int argc, char **argv)
{
    assert(argc == 2);
    const std::string_view behavior{argv[1]};
    if (behavior == "linux-file-destination-streaming")
    {
        linuxFileDestinationStreaming();
        return 0;
    }
    if (behavior == "linux-file-destination-size-cancel")
    {
        linuxFileDestinationSizeDiscoveryCancellation();
        return 0;
    }
    if (behavior == "linux-file-destination-denials")
    {
        linuxFileDestinationSourceAndNativeDenials();
        return 0;
    }
    assert(false && "unknown Linux clipboard file destination behavior");
    return 1;
}
