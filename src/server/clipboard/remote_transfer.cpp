// SPDX-License-Identifier: GPL-3.0-or-later
#include "remote_transfer.h"

#include "clipboard/clipboard_protocol.h"
#include "transport/mcs_channel_connection.h"

#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <string_view>

namespace rdp_server::server::clipboard
{
// CLIPRDR wire constants are defined by our C++23 protocol header.
namespace
{
constexpr std::uint16_t kAllowedResponseFlags =
    rdp_server::clipboard::kResponseOk |
    rdp_server::clipboard::kResponseFail;
constexpr std::size_t kMaximumFormatNameCodeUnits = 256;
constexpr std::size_t kShortFormatEntryBytes = 36;
constexpr std::size_t kShortFormatNameBytes = 32;
constexpr std::uint16_t kAsciiNamesFlag = 0x0004;
constexpr std::uint16_t kGeneralCapabilityType = 1;
constexpr std::size_t kGeneralCapabilityBytes = 12;
constexpr std::size_t kCapabilityHeaderBytes = 4;
// Bound retained wire bytes separately from a prospective 32-bpp decode.
constexpr std::size_t kMaximumStoredImageBytes =
    rdp_server::clipboard::kMaximumPduBytes - 8U;
constexpr std::uint64_t kMaximumDecodedImageBytes =
    256ULL * 1024ULL * 1024ULL;

[[nodiscard]] bool decodedImageFits(std::uint32_t width,
                                    std::uint64_t height) noexcept
{
    constexpr std::uint64_t kBytesPerPixel = 4U;
    if (width == 0U || height == 0U)
    {
        return false;
    }
    const std::uint64_t rowBytes =
        static_cast<std::uint64_t>(width) * kBytesPerPixel;
    return rowBytes <= kMaximumDecodedImageBytes &&
           height <= kMaximumDecodedImageBytes / rowBytes;
}

[[nodiscard]] std::uint64_t absoluteDibHeight(
    std::uint32_t rawHeight) noexcept
{
    return rawHeight <= static_cast<std::uint32_t>(
                            std::numeric_limits<std::int32_t>::max())
               ? rawHeight
               : (std::uint64_t{1} << 32U) - rawHeight;
}

[[nodiscard]] std::uint16_t read16(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(bytes[offset + 1]) << 8U;
}

[[nodiscard]] std::uint32_t read32(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept
{
    return static_cast<std::uint32_t>(bytes[offset]) |
           static_cast<std::uint32_t>(bytes[offset + 1]) << 8U |
           static_cast<std::uint32_t>(bytes[offset + 2]) << 16U |
           static_cast<std::uint32_t>(bytes[offset + 3]) << 24U;
}

[[nodiscard]] std::uint64_t read64(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept
{
    return static_cast<std::uint64_t>(read32(bytes, offset)) |
           (static_cast<std::uint64_t>(read32(bytes, offset + 4U)) << 32U);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept
{
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value >> 24U);
}

[[nodiscard]] bool parseRemoteRelativeFileName(
    std::span<const std::uint8_t> bytes,
    std::array<char16_t, 260> &relativePath,
    std::uint16_t &relativePathLength,
    std::array<char16_t, 260> &leafName,
    std::uint16_t &leafNameLength,
    std::uint16_t &depth) noexcept
{
    if (bytes.size() != relativePath.size() * 2U)
        return false;

    relativePath.fill(u'\0');
    leafName.fill(u'\0');
    relativePathLength = 0;
    leafNameLength = 0;
    depth = 0;

    const auto validComponent = [&](const std::size_t begin,
                                    const std::size_t end) noexcept
    {
        if (begin >= end)
            return false;
        const std::size_t length = end - begin;
        return !(length == 1U && relativePath[begin] == u'.') &&
               !(length == 2U && relativePath[begin] == u'.' &&
                 relativePath[begin + 1U] == u'.');
    };

    bool terminated = false;
    bool pendingHighSurrogate = false;
    std::size_t componentStart = 0U;
    for (std::size_t index = 0; index < relativePath.size(); ++index)
    {
        const std::uint16_t codeUnit = read16(bytes, index * 2U);
        if (terminated)
        {
            if (codeUnit != 0U)
                return false;
            continue;
        }
        if (codeUnit == 0U)
        {
            if (pendingHighSurrogate ||
                !validComponent(componentStart, index))
                return false;
            terminated = true;
            relativePathLength = static_cast<std::uint16_t>(index);
            leafNameLength =
                static_cast<std::uint16_t>(index - componentStart);
            std::copy(relativePath.begin() + componentStart,
                      relativePath.begin() + index,
                      leafName.begin());
            continue;
        }

        // MS-RDPECLIP File List names can be relative. Backslash is retained
        // only as protocol structure; absolute/source-path forms remain
        // impossible because leading separators, drive colons, slash and
        // traversal components are rejected.
        if (codeUnit < 0x20U || codeUnit == '<' || codeUnit == '>' ||
            codeUnit == ':' || codeUnit == '"' || codeUnit == '/' ||
            codeUnit == '|' || codeUnit == '?' || codeUnit == '*')
            return false;
        if (codeUnit == '\\')
        {
            if (pendingHighSurrogate ||
                !validComponent(componentStart, index))
                return false;
            if (depth == (std::numeric_limits<std::uint16_t>::max)())
                return false;
            ++depth;
            relativePath[index] = u'\\';
            componentStart = index + 1U;
            continue;
        }
        if (codeUnit >= 0xd800U && codeUnit <= 0xdbffU)
        {
            if (pendingHighSurrogate)
                return false;
            pendingHighSurrogate = true;
        }
        else if (codeUnit >= 0xdc00U && codeUnit <= 0xdfffU)
        {
            if (!pendingHighSurrogate)
                return false;
            pendingHighSurrogate = false;
        }
        else if (pendingHighSurrogate)
            return false;
        relativePath[index] = static_cast<char16_t>(codeUnit);
    }
    return terminated;
}

// Registered names used for image/file negotiation are ASCII, but on the
// CLIPRDR wire they are encoded as UTF-16LE. Compare without allocating.
[[nodiscard]] bool matchesUtf16Name(std::span<const std::uint8_t> bytes,
                                    std::string_view name) noexcept
{
    if (bytes.size() != name.size() * 2U)
    {
        return false;
    }
    for (std::size_t index = 0; index < name.size(); ++index)
    {
        if (read16(bytes, index * 2U) !=
            static_cast<std::uint8_t>(name[index]))
        {
            return false;
        }
    }
    return true;
}

// Short names are padded with zeros; a 32-byte field without a terminator
// is also valid because the sender may truncate a longer registered name.
[[nodiscard]] bool validShortUnicodeName(
    std::span<const std::uint8_t> bytes, std::size_t &nameBytes) noexcept
{
    bool pendingHighSurrogate = false;
    nameBytes = bytes.size();
    for (std::size_t offset = 0; offset < bytes.size(); offset += 2U)
    {
        const std::uint16_t codeUnit = read16(bytes, offset);
        if (codeUnit == 0)
        {
            nameBytes = offset;
            return !pendingHighSurrogate &&
                   std::all_of(bytes.begin() + offset, bytes.end(),
                               [](std::uint8_t byte) { return byte == 0; });
        }
        if (codeUnit >= 0xd800U && codeUnit <= 0xdbffU)
        {
            if (pendingHighSurrogate)
            {
                return false;
            }
            pendingHighSurrogate = true;
        }
        else if (codeUnit >= 0xdc00U && codeUnit <= 0xdfffU)
        {
            if (!pendingHighSurrogate)
            {
                return false;
            }
            pendingHighSurrogate = false;
        }
        else if (pendingHighSurrogate)
        {
            return false;
        }
    }
    return !pendingHighSurrogate;
}

[[nodiscard]] bool matchesAsciiName(std::span<const std::uint8_t> bytes,
                                    std::string_view name) noexcept
{
    return bytes.size() == name.size() &&
           std::equal(bytes.begin(), bytes.end(), name.begin(),
                      [](std::uint8_t byte, char character) {
                          return byte == static_cast<std::uint8_t>(character);
                      });
}

[[nodiscard]] bool validTemporaryDirectoryPayload(
    std::span<const std::uint8_t> bytes) noexcept
{
    constexpr std::size_t kTemporaryDirectoryBytes = 520U;
    if (bytes.size() != kTemporaryDirectoryBytes)
    {
        return false;
    }

    bool sawCodeUnit = false;
    bool pendingHighSurrogate = false;
    for (std::size_t offset = 0; offset < bytes.size(); offset += 2U)
    {
        const std::uint16_t codeUnit = read16(bytes, offset);
        if (codeUnit == 0)
        {
            return sawCodeUnit && !pendingHighSurrogate;
        }
        sawCodeUnit = true;
        if (codeUnit >= 0xd800U && codeUnit <= 0xdbffU)
        {
            if (pendingHighSurrogate)
            {
                return false;
            }
            pendingHighSurrogate = true;
        }
        else if (codeUnit >= 0xdc00U && codeUnit <= 0xdfffU)
        {
            if (!pendingHighSurrogate)
            {
                return false;
            }
            pendingHighSurrogate = false;
        }
        else if (pendingHighSurrogate)
        {
            return false;
        }
    }
    return false;
}

} // namespace

bool RemoteTransfer::receiveFormatList(
    std::span<const std::uint32_t> advertisedFormatIds) noexcept
{
    // Partial Lock delivery is ambiguous: the peer might already have tagged
    // this exact generation. Do not discard its metadata before disconnect.
    if (fileLockWriteActive_ &&
        pendingFileLockWrite_.operation == FileLockOperation::Lock &&
        fileLockWrittenBytes_ != 0 &&
        fileLockWrittenBytes_ < pendingFileLockWrite_.bytes)
    {
        poisoned_ = true;
        return false;
    }

    lastFormatListResponseValid_ = false;
    verifiedTextUtf8_.clear();
    verifiedTextReady_ = false;
    verifiedImageBytes_.clear();
    verifiedImageGeneration_ = 0;
    verifiedImageSourceFormatId_ = 0;
    verifiedImageReady_ = false;
    remoteFiles_.fill({});
    remoteFileCount_ = 0;
    remoteFileGeneration_ = 0;
    remoteHierarchyGeneration_ = 0;
    remoteHierarchyStatus_ = RemoteHierarchyStatus::Unavailable;
    if (poisoned_ ||
        generation_ == std::numeric_limits<std::uint64_t>::max() ||
        sourceEpoch_ == std::numeric_limits<std::uint64_t>::max() ||
        advertisedFormatIds.size() > kMaximumFormats)
    {
        poisoned_ = true;
        return false;
    }

    // Small bounded lookup; reject malformed duplicates instead of creating
    // an ambiguous mapping between named and standard clipboard formats.
    for (std::size_t index = 0; index < advertisedFormatIds.size(); ++index)
    {
        const std::uint32_t formatId = advertisedFormatIds[index];
        if (formatId == 0 ||
            std::find(advertisedFormatIds.begin(),
                      advertisedFormatIds.begin() + index, formatId) !=
                advertisedFormatIds.begin() + index)
        {
            poisoned_ = true;
            return false;
        }
    }

    // A successfully validated new offer supersedes the native paste request
    // for the old generation. Keep the terminal receipt until the adapter
    // polls it; an in-flight wire reply is still drained by pending_ below.
    if (pasteRequestPresent_ &&
        pasteRequestStatus_ == PasteStatus::Pending)
    {
        pasteRequestStatus_ = PasteStatus::ClipboardReplaced;
    }

    std::copy(advertisedFormatIds.begin(), advertisedFormatIds.end(),
              advertisedFormats_.begin());
    advertisedCount_ = advertisedFormatIds.size();
    pngFormatId_ = 0;
    fileGroupDescriptorFormatId_ = 0;
    attemptedPrefetchIds_.fill(0);
    ++generation_;
    ++sourceEpoch_;
    // pending_ deliberately survives a new format list: CLIPRDR wire
    // responses carry no request generation. A stale response must be drained.
    return true;
}

bool RemoteTransfer::receiveLongFormatListPdu(
    std::span<const std::uint8_t> completePdu) noexcept
{
    using namespace rdp_server::clipboard;
    PduView pdu{};
    // CB_USE_LONG_FORMAT_NAMES is a general capability bit, NOT a PDU flag.
    if (poisoned_ || !decodePdu(completePdu, pdu) ||
        pdu.type != kFormatList || pdu.flags != 0)
    {
        poisoned_ = true;
        return false;
    }

    std::array<std::uint32_t, kMaximumFormats> formatIds{};
    std::size_t formatCount = 0;
    std::size_t offset = 0;
    std::uint32_t pngFormatId = 0;
    std::uint32_t fileGroupDescriptorFormatId = 0;
    while (offset < pdu.payload.size())
    {
        if (formatCount == formatIds.size() ||
            pdu.payload.size() - offset < 6U)
        {
            poisoned_ = true;
            return false;
        }
        const std::uint32_t formatId = read32(pdu.payload, offset);
        offset += 4U;
        const std::size_t nameStart = offset;
        std::size_t codeUnitCount = 0;
        bool pendingHighSurrogate = false;
        bool terminated = false;
        while (pdu.payload.size() - offset >= 2U)
        {
            const std::uint16_t codeUnit = read16(pdu.payload, offset);
            offset += 2U;
            if (codeUnit == 0)
            {
                if (pendingHighSurrogate)
                {
                    break;
                }
                terminated = true;
                break;
            }
            if (++codeUnitCount > kMaximumFormatNameCodeUnits)
            {
                break;
            }
            if (codeUnit >= 0xd800U && codeUnit <= 0xdbffU)
            {
                if (pendingHighSurrogate)
                {
                    break;
                }
                pendingHighSurrogate = true;
            }
            else if (codeUnit >= 0xdc00U && codeUnit <= 0xdfffU)
            {
                if (!pendingHighSurrogate)
                {
                    break;
                }
                pendingHighSurrogate = false;
            }
            else if (pendingHighSurrogate)
            {
                break;
            }
        }
        if (!terminated)
        {
            poisoned_ = true;
            return false;
        }
        // The final two bytes are the null terminator, not part of the name.
        const auto name = pdu.payload.subspan(nameStart, offset - nameStart - 2U);
        if (matchesUtf16Name(name, "PNG"))
        {
            if (pngFormatId != 0)
            {
                poisoned_ = true;
                return false;
            }
            pngFormatId = formatId;
        }
        else if (matchesUtf16Name(name, "FileGroupDescriptorW"))
        {
            if (fileGroupDescriptorFormatId != 0)
            {
                poisoned_ = true;
                return false;
            }
            fileGroupDescriptorFormatId = formatId;
        }
        formatIds[formatCount++] = formatId;
    }

    if (!receiveFormatList(std::span<const std::uint32_t>(
            formatIds.data(), formatCount)))
    {
        return false;
    }
    pngFormatId_ = pngFormatId;
    fileGroupDescriptorFormatId_ = fileGroupDescriptorFormatId;
    return true;
}

bool RemoteTransfer::receiveShortFormatListPdu(
    std::span<const std::uint8_t> completePdu) noexcept
{
    using namespace rdp_server::clipboard;
    PduView pdu{};
    if (poisoned_ || !decodePdu(completePdu, pdu) ||
        pdu.type != kFormatList ||
        (pdu.flags != 0 && pdu.flags != kAsciiNamesFlag) ||
        pdu.payload.size() % kShortFormatEntryBytes != 0 ||
        pdu.payload.size() / kShortFormatEntryBytes > kMaximumFormats)
    {
        poisoned_ = true;
        return false;
    }

    const bool asciiNames = pdu.flags == kAsciiNamesFlag;
    std::array<std::uint32_t, kMaximumFormats> formatIds{};
    const std::size_t formatCount = pdu.payload.size() / kShortFormatEntryBytes;
    std::uint32_t pngFormatId = 0;
    std::uint32_t fileGroupDescriptorFormatId = 0;
    for (std::size_t index = 0; index < formatCount; ++index)
    {
        const std::size_t offset = index * kShortFormatEntryBytes;
        const std::uint32_t formatId = read32(pdu.payload, offset);
        const auto nameField = pdu.payload.subspan(
            offset + sizeof(std::uint32_t), kShortFormatNameBytes);
        std::size_t nameBytes = nameField.size();
        if (asciiNames)
        {
            const auto terminator = std::find(nameField.begin(),
                                              nameField.end(), 0);
            nameBytes = static_cast<std::size_t>(terminator - nameField.begin());
            // A null byte terminates the name; all padding must be zero.
            if (!std::all_of(terminator, nameField.end(),
                             [](std::uint8_t byte) { return byte == 0; }))
            {
                poisoned_ = true;
                return false;
            }
        }
        else if (!validShortUnicodeName(nameField, nameBytes))
        {
            poisoned_ = true;
            return false;
        }

        const auto name = nameField.first(nameBytes);
        const bool isPng = asciiNames ? matchesAsciiName(name, "PNG") :
                                        matchesUtf16Name(name, "PNG");
        const bool isFileGroup = asciiNames ?
            matchesAsciiName(name, "FileGroupDescriptorW") :
            matchesUtf16Name(name, "FileGroupDescriptorW");
        if ((isPng && pngFormatId != 0) ||
            (isFileGroup && fileGroupDescriptorFormatId != 0))
        {
            poisoned_ = true;
            return false;
        }
        if (isPng)
        {
            pngFormatId = formatId;
        }
        if (isFileGroup)
        {
            fileGroupDescriptorFormatId = formatId;
        }
        formatIds[index] = formatId;
    }

    if (!receiveFormatList(std::span<const std::uint32_t>(
            formatIds.data(), formatCount)))
    {
        return false;
    }
    pngFormatId_ = pngFormatId;
    fileGroupDescriptorFormatId_ = fileGroupDescriptorFormatId;
    return true;
}

bool RemoteTransfer::receiveFormatListWithResponse(
    std::span<const std::uint8_t> completePdu,
    bool negotiatedLongFormatNames, bool nativeOfferAccepted,
    std::array<std::uint8_t, 8> &response) noexcept
{
    // MS-RDPECLIP 2.2.3.2: Format List Response has no payload and must
    // carry exactly one response status flag. Construct the failure packet
    // first, so even a malformed offer has a deterministic wire response.
    response = {0x03U, 0x00U, 0x02U, 0x00U, 0, 0, 0, 0};
    const bool parsed = negotiatedLongFormatNames ?
        receiveLongFormatListPdu(completePdu) :
        receiveShortFormatListPdu(completePdu);
    lastFormatListResponse_ = response;
    lastFormatListResponseValid_ = true;
    if (!parsed)
    {
        return false;
    }
    if (!nativeOfferAccepted)
    {
        // A valid but unusable clipboard replacement still supersedes the
        // old generation. Preserve its pending Format Data Request solely
        // for stale-response draining; never publish its obsolete contents.
        advertisedFormats_.fill(0);
        advertisedCount_ = 0;
        pngFormatId_ = 0;
        fileGroupDescriptorFormatId_ = 0;
        return false;
    }
    response[2] = 0x01U; // CB_RESPONSE_OK, rather than CB_RESPONSE_FAIL.
    lastFormatListResponse_ = response;
    return true;
}

bool RemoteTransfer::receiveCapabilitiesPdu(
    std::span<const std::uint8_t> completePdu,
    std::uint32_t localGeneralFlags) noexcept
{
    using namespace rdp_server::clipboard;
    PduView pdu{};
    if (poisoned_ || capabilitiesReceived_ ||
        !decodePdu(completePdu, pdu) || pdu.type != kClipCaps ||
        pdu.flags != 0 || pdu.payload.size() < kCapabilityHeaderBytes)
    {
        poisoned_ = true;
        return false;
    }

    const std::size_t capabilityCount = read16(pdu.payload, 0);
    if (capabilityCount > kMaximumCapabilitySets)
    {
        poisoned_ = true;
        return false;
    }

    // CB_CLIP_CAPS pad1 is ignored as required by MS-RDPECLIP 2.2.2.1.
    std::size_t offset = kCapabilityHeaderBytes;
    std::uint32_t peerGeneralFlags = 0;
    bool receivedGeneral = false;
    for (std::size_t index = 0; index < capabilityCount; ++index)
    {
        if (pdu.payload.size() - offset < kCapabilityHeaderBytes)
        {
            poisoned_ = true;
            return false;
        }
        const std::uint16_t type = read16(pdu.payload, offset);
        const std::size_t length = read16(pdu.payload, offset + 2U);
        if (length < kCapabilityHeaderBytes ||
            length > pdu.payload.size() - offset)
        {
            poisoned_ = true;
            return false;
        }
        if (type == kGeneralCapabilityType)
        {
            if (receivedGeneral || length != kGeneralCapabilityBytes)
            {
                poisoned_ = true;
                return false;
            }
            // version is informational; only mutually offered flags gate use.
            peerGeneralFlags = read32(pdu.payload, offset + 8U);
            receivedGeneral = true;
        }
        // Opaque, length-checked extension sets do not grant any features.
        offset += length;
    }
    if (offset != pdu.payload.size())
    {
        poisoned_ = true;
        return false;
    }

    peerGeneralFlags_ = peerGeneralFlags;
    localAdvertisedGeneralFlags_ = localGeneralFlags;
    negotiatedGeneralFlags_ = peerGeneralFlags & localGeneralFlags &
                              kSupportedGeneralFlags;
    capabilitiesReceived_ = true;
    return true;
}

std::uint32_t RemoteTransfer::negotiatedGeneralFlags() const noexcept
{
    return poisoned_ ? 0U : negotiatedGeneralFlags_;
}

bool RemoteTransfer::receiveTemporaryDirectoryPdu(
    std::span<const std::uint8_t> completePdu) noexcept
{
    using namespace rdp_server::clipboard;
    PduView pdu{};
    if (poisoned_ || !capabilitiesReceived_ || temporaryDirectoryReceived_ ||
        !decodePdu(completePdu, pdu) ||
        pdu.type != kTempDirectory || pdu.flags != 0 ||
        !validTemporaryDirectoryPayload(pdu.payload))
    {
        poisoned_ = true;
        return false;
    }
    temporaryDirectoryReceived_ = true;
    return true;
}

bool RemoteTransfer::receiveNegotiatedFormatListWithResponse(
    std::span<const std::uint8_t> completePdu,
    bool nativeOfferAccepted,
    std::array<std::uint8_t, 8> &response) noexcept
{
    return receiveFormatListWithResponse(
        completePdu, (negotiatedGeneralFlags() &
                       rdp_server::clipboard::kUseLongFormatNames) != 0,
        nativeOfferAccepted, response);
}

std::optional<std::size_t> RemoteTransfer::encodeJoinedFormatListResponse(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    std::uint16_t channelId,
    std::span<const std::uint8_t> completeResponse,
    std::span<std::uint8_t> output) const noexcept
{
    using namespace rdp_server::clipboard;
    // MS-RDPECLIP 2.2.3.2: exactly one status and no response payload.
    // Never allow untrusted bytes to masquerade as our outgoing acknowledgment.
    if (!lastFormatListResponseValid_ ||
        completeResponse.size() != lastFormatListResponse_.size() ||
        !std::equal(completeResponse.begin(), completeResponse.end(),
                    lastFormatListResponse_.begin()) ||
        completeResponse[0] != static_cast<std::uint8_t>(kFormatListResponse) ||
        completeResponse[1] != 0 ||
        (completeResponse[2] != static_cast<std::uint8_t>(kResponseOk) &&
         completeResponse[2] != static_cast<std::uint8_t>(kResponseFail)) ||
        completeResponse[3] != 0 ||
        !std::all_of(completeResponse.begin() + 4, completeResponse.end(),
                     [](std::uint8_t byte) { return byte == 0; }))
    {
        return std::nullopt;
    }

    // MS-RDPBCGR 2.2.6.1.1: CHANNEL_PDU_HEADER length excludes itself.
    // The eight-byte CLIPRDR PDU fits in one uncompressed static VC chunk.
    constexpr std::size_t kChannelHeaderBytes = 8;
    std::array<std::uint8_t, kChannelHeaderBytes + 8U> userData{};
    userData[0] = 8; // Uncompressed clipboard payload length.
    userData[4] = 0x03; // CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST.
    std::copy(completeResponse.begin(), completeResponse.end(),
              userData.begin() + kChannelHeaderBytes);

    // R3 requires confirmation of the actual MCS Channel Join before
    // serialization. Priority 1 and complete segmentation 3 mirror R3's
    // tested SendDataIndication wire contract. The caller still owns
    // encryption/authorization and the one outbound write lifecycle.
    return joinedChannels.encodeJoinedSendDataIndication(
        channelId, 1, 3, userData, output);
}

RemoteTransfer::JoinedReceiveResult
RemoteTransfer::receiveJoinedStaticChannelPdu(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    const transport::McsChannelRequest &request,
    std::uint16_t expectedCliprdrChannelId,
    bool authenticatedOsSessionAdmitted,
    std::uint32_t localAdvertisedGeneralFlags,
    bool nativeOfferAccepted) noexcept
{
    using namespace rdp_server::clipboard;
    JoinedReceiveResult result{};
    // R3's membership predicate is necessary but NEVER sufficient for
    // dispatch. Authentication/OS/role authority belongs to its caller.
    if (!authenticatedOsSessionAdmitted || expectedCliprdrChannelId == 0 ||
        request.channelId != expectedCliprdrChannelId ||
        request.segmentation != 3 ||
        !joinedChannels.matchesJoinedInboundSendData(request))
    {
        return result;
    }
    if (poisoned_)
    {
        result.status = JoinedReceiveStatus::ProtocolError;
        return result;
    }

    // MS-RDPBCGR 2.2.6.1.1: 8-byte CHANNEL_PDU_HEADER, length of the
    // UNCOMPRESSED clipboard PDU excluding this header. Reject fragmented
    // or compressed traffic until the sole R3/R9 intake reassembles it.
    constexpr std::uint32_t kFirstLast = 0x00000003U;
    constexpr std::uint32_t kIgnoredClientFlags = 0x000000f0U;
    constexpr std::size_t kChannelHeaderLength = 8;
    const auto wire = request.userData;
    if (wire.size() < kChannelHeaderLength + 8U ||
        wire.size() > kMaximumPduBytes + kChannelHeaderLength ||
        read32(wire, 0) != wire.size() - kChannelHeaderLength ||
        (read32(wire, 4) & kFirstLast) != kFirstLast ||
        (read32(wire, 4) & ~(kFirstLast | kIgnoredClientFlags)) != 0)
    {
        poisoned_ = true;
        result.status = JoinedReceiveStatus::ProtocolError;
        return result;
    }

    const auto completeClipboardPdu = wire.subspan(kChannelHeaderLength);
    PduView pdu{};
    if (!decodePdu(completeClipboardPdu, pdu))
    {
        poisoned_ = true;
        result.status = JoinedReceiveStatus::ProtocolError;
        return result;
    }
    switch (pdu.type)
    {
    case kClipCaps:
        result.status = receiveCapabilitiesPdu(
            completeClipboardPdu, localAdvertisedGeneralFlags) ?
            JoinedReceiveStatus::CapabilitiesAccepted :
            JoinedReceiveStatus::ProtocolError;
        return result;
    case kTempDirectory:
        result.status = receiveTemporaryDirectoryPdu(completeClipboardPdu) ?
            JoinedReceiveStatus::TemporaryDirectoryAccepted :
            JoinedReceiveStatus::ProtocolError;
        return result;
    case kFormatList:
        result.status = receiveNegotiatedFormatListWithResponse(
            completeClipboardPdu, nativeOfferAccepted,
            result.acknowledgment) ?
            JoinedReceiveStatus::FormatListAccepted :
            (poisoned_ ? JoinedReceiveStatus::ProtocolError :
                         JoinedReceiveStatus::FormatListDeclined);
        result.acknowledgmentReady = true;
        return result;
    case kFormatDataResponse:
        result.data = receiveResponse(completeClipboardPdu);
        switch (result.data.status)
        {
        case ResponseStatus::Received:
            result.status = JoinedReceiveStatus::DataReceived;
            break;
        case ResponseStatus::RemoteFailure:
            result.status = JoinedReceiveStatus::DataFailed;
            break;
        case ResponseStatus::DiscardedPreviousGeneration:
            result.status = JoinedReceiveStatus::ObsoleteDataDiscarded;
            break;
        case ResponseStatus::ProtocolError:
            result.status = JoinedReceiveStatus::ProtocolError;
            break;
        }
        return result;
    default:
        // MS-RDPECLIP 3.1.5.1: ignore unexpected messages, never
        // treat their payload as clipboard data or an implicit offer.
        result.status = JoinedReceiveStatus::Ignored;
        return result;
    }
}

std::uint32_t RemoteTransfer::namedFormatId(std::string_view name) const noexcept
{
    if (poisoned_ || generation_ == 0)
    {
        return 0;
    }
    if (name == "PNG")
    {
        return pngFormatId_;
    }
    return name == "FileGroupDescriptorW" ? fileGroupDescriptorFormatId_ : 0;
}

bool RemoteTransfer::beginRequest(
    std::uint32_t formatId, std::vector<std::uint8_t> &output) noexcept
{
    output.clear();
    if (poisoned_ || generation_ == 0 || pendingValid_ ||
        pendingFileContentsValid_ || fileLockWriteActive_ ||
        !advertises(formatId))
    {
        return false;
    }
    const std::array<std::uint8_t, 4> payload{
        static_cast<std::uint8_t>(formatId),
        static_cast<std::uint8_t>(formatId >> 8U),
        static_cast<std::uint8_t>(formatId >> 16U),
        static_cast<std::uint8_t>(formatId >> 24U),
    };
    if (!rdp_server::clipboard::encodePdu(
            rdp_server::clipboard::kFormatDataRequest, 0, payload, output))
    {
        return false;
    }
    pending_ = PendingRequest{generation_, formatId};
    pendingValid_ = true;
    return true;
}

std::optional<RemoteTransfer::JoinedRequestReceipt>
RemoteTransfer::prepareJoinedFormatDataRequest(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
    std::uint32_t formatId, std::span<std::uint8_t> output) noexcept
{
    using namespace rdp_server::clipboard;
    if (poisoned_ || generation_ == 0 || pendingValid_ ||
        pendingFileContentsValid_ || joinedRequestActive_ ||
        joinedRequestSequence_ == UINT64_MAX ||
        channelId == 0 || channelId != expectedCliprdrChannelId ||
        !joinedChannels.channelJoinConfirmed(channelId) ||
        !advertises(formatId))
        return std::nullopt;

    // MS-RDPECLIP 2.2.5.1: CB_FORMAT_DATA_REQUEST is an exact 12-byte
    // PDU with one 32-bit currently advertised format identifier.
    // Stage the codec output before reserving the single-flight slot.
    const std::array<std::uint8_t, 4> format{
        static_cast<std::uint8_t>(formatId),
        static_cast<std::uint8_t>(formatId >> 8U),
        static_cast<std::uint8_t>(formatId >> 16U),
        static_cast<std::uint8_t>(formatId >> 24U),
    };
    std::vector<std::uint8_t> pdu;
    if (!encodePdu(kFormatDataRequest, 0, format, pdu) || pdu.size() != 12)
        return std::nullopt;

    // MS-RDPBCGR 2.2.6.1.1: uncompressed data size, then FIRST|LAST,
    // then the complete clipboard PDU. The VC payload is only 12 bytes.
    std::array<std::uint8_t, 20> channelData{};
    channelData[0] = 12;
    channelData[4] = 3;
    std::copy(pdu.begin(), pdu.end(), channelData.begin() + 8);
    const auto framed = joinedChannels.encodeJoinedSendDataIndication(
        channelId, 1, 3, channelData, output);
    if (!framed)
        return std::nullopt;

    // Commit *after* all checks and serialization. The caller owns the
    // fully encoded output; R3 alone can admit, queue and complete writes.
    ++joinedRequestSequence_;
    pending_ = PendingRequest{generation_, formatId};
    pendingValid_ = true;
    joinedRequestActiveSequence_ = joinedRequestSequence_;
    joinedRequestFrameBytes_ = *framed;
    joinedRequestWrittenBytes_ = 0;
    joinedRequestActive_ = true;
    return JoinedRequestReceipt{joinedRequestSequence_, generation_, *framed};
}

bool RemoteTransfer::joinedRequestMayWrite(std::uint64_t sequence) const noexcept
{
    return !poisoned_ && pendingValid_ && joinedRequestActive_ &&
           sequence != 0 && sequence == joinedRequestActiveSequence_ &&
           pending_.generation == generation_ &&
           joinedRequestWrittenBytes_ < joinedRequestFrameBytes_;
}

bool RemoteTransfer::recordJoinedRequestWritten(
    std::uint64_t sequence, std::size_t cumulativeBytes) noexcept
{
    if (poisoned_ || !pendingValid_ || !joinedRequestActive_ ||
        sequence == 0 || sequence != joinedRequestActiveSequence_)
        return false;
    if (cumulativeBytes < joinedRequestWrittenBytes_ ||
        cumulativeBytes > joinedRequestFrameBytes_ ||
        (pending_.generation != generation_ &&
         cumulativeBytes > joinedRequestWrittenBytes_))
    {
        poisoned_ = true;
        return false;
    }
    joinedRequestWrittenBytes_ = cumulativeBytes;
    return true;
}

bool RemoteTransfer::cancelUnwrittenJoinedRequest(
    std::uint64_t sequence) noexcept
{
    if (poisoned_ || !pendingValid_ || !joinedRequestActive_ ||
        sequence == 0 || sequence != joinedRequestActiveSequence_ ||
        joinedRequestWrittenBytes_ != 0)
        return false;
    pending_ = {};
    pendingValid_ = false;
    joinedRequestActive_ = false;
    joinedRequestActiveSequence_ = 0;
    joinedRequestFrameBytes_ = 0;
    return true;
}

bool RemoteTransfer::abandonJoinedRequest(std::uint64_t sequence) noexcept
{
    if (!pendingValid_ || !joinedRequestActive_ || sequence == 0 ||
        sequence != joinedRequestActiveSequence_)
        return false;
    if (joinedRequestWrittenBytes_ == 0)
        return cancelUnwrittenJoinedRequest(sequence);
    poisoned_ = true; // Partial/uncertain send: never reassign its reply.
    return true;
}

bool RemoteTransfer::fileLockSessionPrerequisitesMet() const noexcept
{
    using namespace rdp_server::clipboard;
    return !poisoned_ && capabilitiesReceived_ && temporaryDirectoryReceived_ &&
           (peerGeneralFlags_ & kCanLockClipdata) != 0 &&
           (localAdvertisedGeneralFlags_ & kCanLockClipdata) != 0 &&
           (negotiatedGeneralFlags_ & kStreamFileclipEnabled) != 0;
}

bool RemoteTransfer::fileLockWriteSourceStillValid() const noexcept
{
    if (!fileLockWriteActive_)
    {
        return false;
    }
    if (pendingFileLockWrite_.operation == FileLockOperation::Lock)
    {
        return !fileLockPresent_ &&
               pendingFileLockWrite_.generation == generation_ &&
               remoteFileGeneration_ == generation_;
    }
    return fileLockPresent_ &&
           pendingFileLockWrite_.clipDataId == lockedClipDataId_ &&
           pendingFileLockWrite_.generation == lockedRemoteFileGeneration_;
}

std::optional<RemoteTransfer::JoinedFileLockReceipt>
RemoteTransfer::prepareJoinedFileLockOperation(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
    FileLockOperation operation, std::uint32_t clipDataId,
    std::span<std::uint8_t> output) noexcept
{
    using namespace rdp_server::clipboard;
    if (!fileLockSessionPrerequisitesMet() || fileLockWriteActive_ ||
        pendingValid_ || pendingFileContentsValid_ ||
        fileLockReceiptSequence_ == UINT64_MAX ||
        channelId == 0 || channelId != expectedCliprdrChannelId ||
        !joinedChannels.channelJoinConfirmed(channelId))
    {
        return std::nullopt;
    }

    std::uint32_t selectedClipDataId = clipDataId;
    std::uint64_t sourceGeneration = 0;
    if (operation == FileLockOperation::Lock)
    {
        if (fileLockPresent_ || generation_ == 0 ||
            remoteFileGeneration_ != generation_ ||
            fileGroupDescriptorFormatId_ == 0 ||
            !advertises(fileGroupDescriptorFormatId_) ||
            clipDataIdSequence_ >=
                static_cast<std::uint64_t>(
                    std::numeric_limits<std::uint32_t>::max()))
        {
            return std::nullopt;
        }
        selectedClipDataId =
            static_cast<std::uint32_t>(clipDataIdSequence_ + 1U);
        sourceGeneration = generation_;
    }
    else
    {
        if (!fileLockPresent_ || selectedClipDataId == 0 ||
            selectedClipDataId != lockedClipDataId_)
        {
            return std::nullopt;
        }
        sourceGeneration = lockedRemoteFileGeneration_;
    }

    std::array<std::uint8_t, 4> payload{};
    write32(payload, 0, selectedClipDataId);
    std::vector<std::uint8_t> pdu;
    const std::uint16_t pduType =
        operation == FileLockOperation::Lock ? kLockClipdata :
                                                kUnlockClipdata;
    if (!encodePdu(pduType, 0, payload, pdu) || pdu.size() != 12U)
    {
        return std::nullopt;
    }

    std::array<std::uint8_t, 20> channelData{};
    write32(channelData, 0, static_cast<std::uint32_t>(pdu.size()));
    write32(channelData, 4, 3U);
    std::copy(pdu.begin(), pdu.end(), channelData.begin() + 8U);
    const auto framed = joinedChannels.encodeJoinedSendDataIndication(
        channelId, 1, 3, channelData, output);
    if (!framed)
    {
        return std::nullopt;
    }

    ++fileLockReceiptSequence_;
    if (operation == FileLockOperation::Lock)
    {
        // A prepared ID is burned even if its fully unwritten frame is later
        // cancelled. Reconnect/cancellation must never create clipDataId ABA.
        clipDataIdSequence_ = selectedClipDataId;
    }
    pendingFileLockWrite_ = JoinedFileLockReceipt{
        fileLockReceiptSequence_, sourceGeneration, selectedClipDataId,
        *framed, operation};
    fileLockWrittenBytes_ = 0;
    fileLockWriteActive_ = true;
    return pendingFileLockWrite_;
}

std::optional<RemoteTransfer::JoinedFileLockReceipt>
RemoteTransfer::prepareJoinedFileLock(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
    std::span<std::uint8_t> output) noexcept
{
    return prepareJoinedFileLockOperation(
        joinedChannels, channelId, expectedCliprdrChannelId,
        FileLockOperation::Lock, 0, output);
}

std::optional<RemoteTransfer::JoinedFileLockReceipt>
RemoteTransfer::prepareJoinedFileUnlock(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
    std::uint32_t clipDataId, std::span<std::uint8_t> output) noexcept
{
    return prepareJoinedFileLockOperation(
        joinedChannels, channelId, expectedCliprdrChannelId,
        FileLockOperation::Unlock, clipDataId, output);
}

bool RemoteTransfer::joinedFileLockMayWrite(
    std::uint64_t sequence) const noexcept
{
    return !poisoned_ && fileLockWriteActive_ && sequence != 0 &&
           sequence == pendingFileLockWrite_.sequence &&
           fileLockWriteSourceStillValid() &&
           fileLockWrittenBytes_ < pendingFileLockWrite_.bytes;
}

bool RemoteTransfer::recordJoinedFileLockWritten(
    std::uint64_t sequence, std::size_t cumulativeBytes) noexcept
{
    if (poisoned_ || !fileLockWriteActive_ || sequence == 0 ||
        sequence != pendingFileLockWrite_.sequence)
    {
        return false;
    }
    if (cumulativeBytes < fileLockWrittenBytes_ ||
        cumulativeBytes > pendingFileLockWrite_.bytes)
    {
        poisoned_ = true;
        return false;
    }
    if (!fileLockWriteSourceStillValid())
    {
        if (cumulativeBytes > fileLockWrittenBytes_)
        {
            poisoned_ = true;
        }
        return false;
    }

    fileLockWrittenBytes_ = cumulativeBytes;
    if (fileLockWrittenBytes_ != pendingFileLockWrite_.bytes)
    {
        return true;
    }

    if (pendingFileLockWrite_.operation == FileLockOperation::Lock)
    {
        lockedRemoteFiles_ = remoteFiles_;
        lockedRemoteFileCount_ = remoteFileCount_;
        lockedRemoteFileGeneration_ = pendingFileLockWrite_.generation;
        lockedClipDataId_ = pendingFileLockWrite_.clipDataId;
        fileLockPresent_ = true;
    }
    else
    {
        lockedRemoteFiles_.fill({});
        lockedRemoteFileCount_ = 0;
        lockedRemoteFileGeneration_ = 0;
        lockedClipDataId_ = 0;
        fileLockPresent_ = false;
    }

    pendingFileLockWrite_ = {};
    fileLockWrittenBytes_ = 0;
    fileLockWriteActive_ = false;
    return true;
}

bool RemoteTransfer::cancelUnwrittenJoinedFileLock(
    std::uint64_t sequence) noexcept
{
    if (poisoned_ || !fileLockWriteActive_ || sequence == 0 ||
        sequence != pendingFileLockWrite_.sequence ||
        fileLockWrittenBytes_ != 0)
    {
        return false;
    }
    pendingFileLockWrite_ = {};
    fileLockWrittenBytes_ = 0;
    fileLockWriteActive_ = false;
    return true;
}

bool RemoteTransfer::abandonJoinedFileLock(std::uint64_t sequence) noexcept
{
    if (!fileLockWriteActive_ || sequence == 0 ||
        sequence != pendingFileLockWrite_.sequence)
    {
        return false;
    }
    if (fileLockWrittenBytes_ == 0)
    {
        return cancelUnwrittenJoinedFileLock(sequence);
    }
    poisoned_ = true;
    return true;
}

bool RemoteTransfer::fileStreamingAvailable() const noexcept
{
    using namespace rdp_server::clipboard;
    return !poisoned_ && generation_ != 0 &&
           fileGroupDescriptorFormatId_ != 0 &&
           advertises(fileGroupDescriptorFormatId_) &&
           (negotiatedGeneralFlags_ & kStreamFileclipEnabled) != 0;
}

bool RemoteTransfer::beginFileGroupDescriptorRequest(
    std::vector<std::uint8_t> &output) noexcept
{
    output.clear();
    return fileStreamingAvailable() &&
           beginRequest(fileGroupDescriptorFormatId_, output);
}

bool RemoteTransfer::storeFileGroupDescriptors(
    const Response &response) noexcept
{
    using namespace rdp_server::clipboard;
    constexpr std::size_t kDescriptorBytes = 592U;
    constexpr std::size_t kNameOffset = 72U;
    constexpr std::size_t kNameBytes = 520U;
    constexpr std::uint32_t kFdAttributes = 0x00000004U;
    constexpr std::uint32_t kFdFileSize = 0x00000040U;
    constexpr std::uint32_t kFileAttributeDirectory = 0x00000010U;

    if (!fileStreamingAvailable() || pendingValid_ ||
        pendingFileContentsValid_ ||
        response.status != ResponseStatus::Received ||
        response.generation != generation_ ||
        response.formatId != fileGroupDescriptorFormatId_ ||
        response.payload.size() < 4U)
    {
        return false;
    }

    const std::size_t count = read32(response.payload, 0);
    if (count > kMaximumRemoteFiles ||
        count > (std::numeric_limits<std::size_t>::max() - 4U) /
                    kDescriptorBytes ||
        response.payload.size() != 4U + count * kDescriptorBytes)
    {
        return false;
    }

    std::array<RemoteFileDescriptor, kMaximumRemoteFiles> candidate{};
    const bool hugeFiles =
        (negotiatedGeneralFlags_ & kHugeFileSupportEnabled) != 0;
    for (std::size_t index = 0; index < count; ++index)
    {
        const auto descriptor =
            response.payload.subspan(4U + index * kDescriptorBytes,
                                     kDescriptorBytes);
        auto &file = candidate[index];
        const std::uint32_t flags = read32(descriptor, 0);
        file.attributes =
            (flags & kFdAttributes) != 0 ? read32(descriptor, 36U) : 0U;
        file.directory =
            (flags & kFdAttributes) != 0 &&
            (file.attributes & kFileAttributeDirectory) != 0;
        file.sizeKnown = (flags & kFdFileSize) != 0;
        if (file.sizeKnown)
        {
            const std::uint32_t high = read32(descriptor, 64U);
            const std::uint32_t low = read32(descriptor, 68U);
            if (!hugeFiles && high != 0)
            {
                return false;
            }
            file.size = static_cast<std::uint64_t>(low) |
                        (static_cast<std::uint64_t>(high) << 32U);
        }
        if (!parseRemoteRelativeFileName(
                descriptor.subspan(kNameOffset, kNameBytes),
                file.relativePath, file.relativePathLength,
                file.name, file.nameLength, file.hierarchyDepth))
        {
            return false;
        }
    }

    RemoteHierarchyStatus hierarchyStatus =
        count == 0U ? RemoteHierarchyStatus::Unavailable :
                      RemoteHierarchyStatus::VerifiedRelativePaths;
    if (count != 0U &&
        (negotiatedGeneralFlags_ & kFileclipNoFilePaths) == 0U)
    {
        hierarchyStatus =
            RemoteHierarchyStatus::UnsupportedSourcePathsAllowed;
    }

    if (hierarchyStatus == RemoteHierarchyStatus::VerifiedRelativePaths)
    {
        for (std::size_t index = 0; index < count; ++index)
        {
            if (candidate[index].hierarchyDepth >
                kMaximumRemoteHierarchyDepth)
            {
                hierarchyStatus =
                    RemoteHierarchyStatus::UnsupportedDepthExceeded;
                break;
            }
            for (std::size_t previous = 0; previous < index; ++previous)
            {
                if (candidate[previous].relativePathLength ==
                        candidate[index].relativePathLength &&
                    std::equal(
                        candidate[index].relativePath.begin(),
                        candidate[index].relativePath.begin() +
                            candidate[index].relativePathLength,
                        candidate[previous].relativePath.begin()))
                {
                    hierarchyStatus =
                        RemoteHierarchyStatus::UnsupportedDuplicateNode;
                    break;
                }
            }
            if (hierarchyStatus !=
                RemoteHierarchyStatus::VerifiedRelativePaths)
                break;
        }
    }

    if (hierarchyStatus == RemoteHierarchyStatus::VerifiedRelativePaths)
    {
        for (std::size_t index = 0; index < count; ++index)
        {
            auto &file = candidate[index];
            if (file.hierarchyDepth == 0U)
                continue;

            std::size_t parentPathLength = 0U;
            for (std::size_t offset = file.relativePathLength;
                 offset != 0U; --offset)
            {
                if (file.relativePath[offset - 1U] == u'\\')
                {
                    parentPathLength = offset - 1U;
                    break;
                }
            }
            if (parentPathLength == 0U)
            {
                hierarchyStatus =
                    RemoteHierarchyStatus::UnsupportedMissingParent;
                break;
            }

            std::optional<std::size_t> parentIndex;
            for (std::size_t candidateIndex = 0;
                 candidateIndex < count; ++candidateIndex)
            {
                const auto &parentCandidate = candidate[candidateIndex];
                if (parentCandidate.relativePathLength != parentPathLength ||
                    !std::equal(
                        file.relativePath.begin(),
                        file.relativePath.begin() + parentPathLength,
                        parentCandidate.relativePath.begin()))
                    continue;
                parentIndex = candidateIndex;
                break;
            }
            if (!parentIndex)
            {
                hierarchyStatus =
                    RemoteHierarchyStatus::UnsupportedMissingParent;
                break;
            }
            if (!candidate[*parentIndex].directory)
            {
                hierarchyStatus =
                    RemoteHierarchyStatus::UnsupportedParentNotDirectory;
                break;
            }
            file.hierarchyParentIndex = *parentIndex;
            file.hierarchyParentPresent = true;
        }
    }

    if (hierarchyStatus == RemoteHierarchyStatus::VerifiedRelativePaths)
    {
        for (std::size_t start = 0; start < count; ++start)
        {
            std::array<bool, kMaximumRemoteFiles> visited{};
            std::size_t current = start;
            while (candidate[current].hierarchyParentPresent)
            {
                if (visited[current])
                {
                    hierarchyStatus =
                        RemoteHierarchyStatus::UnsupportedParentCycle;
                    break;
                }
                visited[current] = true;
                current = candidate[current].hierarchyParentIndex;
                if (current >= count)
                {
                    hierarchyStatus =
                        RemoteHierarchyStatus::UnsupportedMissingParent;
                    break;
                }
            }
            if (hierarchyStatus !=
                RemoteHierarchyStatus::VerifiedRelativePaths)
                break;
        }
    }

    // Flat descriptors remain independently usable even when the optional
    // hierarchy proof is unavailable. Commit both descriptor and hierarchy
    // facts together for this generation; node queries fail closed unless the
    // complete graph verified.
    remoteFiles_ = candidate;
    remoteFileCount_ = count;
    remoteFileGeneration_ = generation_;
    remoteHierarchyGeneration_ = generation_;
    remoteHierarchyStatus_ = hierarchyStatus;
    return true;
}

RemoteTransfer::RemoteHierarchyStatus
RemoteTransfer::remoteHierarchyStatus() const noexcept
{
    if (poisoned_ || remoteHierarchyGeneration_ != generation_)
        return RemoteHierarchyStatus::Unavailable;
    return remoteHierarchyStatus_;
}

std::optional<RemoteTransfer::RemoteHierarchyNodeView>
RemoteTransfer::remoteHierarchyNode(const std::size_t fileIndex) const noexcept
{
    if (remoteHierarchyStatus() !=
            RemoteHierarchyStatus::VerifiedRelativePaths ||
        fileIndex >= remoteFileCount_)
        return std::nullopt;

    const auto &file = remoteFiles_[fileIndex];
    return RemoteHierarchyNodeView{
        fileIndex,
        file.hierarchyParentPresent
            ? std::optional<std::size_t>{file.hierarchyParentIndex}
            : std::nullopt,
        file.hierarchyDepth,
        file.directory,
    };
}

std::size_t RemoteTransfer::remoteFileCount() const noexcept
{
    return !poisoned_ && remoteFileGeneration_ == generation_
               ? remoteFileCount_
               : 0U;
}

std::optional<RemoteTransfer::RemoteFileView>
RemoteTransfer::remoteFile(std::size_t fileIndex) const noexcept
{
    if (poisoned_ || remoteFileGeneration_ != generation_ ||
        fileIndex >= remoteFileCount_)
    {
        return std::nullopt;
    }
    const auto &file = remoteFiles_[fileIndex];
    return RemoteFileView{
        std::span<const char16_t>{file.name.data(), file.nameLength},
        file.size,
        file.attributes,
        file.sizeKnown,
        file.directory,
    };
}

std::optional<RemoteTransfer::FileContentsRequestReceipt>
RemoteTransfer::beginFileContentsRequest(
    FileContentsKind kind, std::uint32_t clipDataId,
    std::size_t fileIndex, std::uint64_t offset,
    std::size_t requestedBytes,
    std::vector<std::uint8_t> &output) noexcept
{
    using namespace rdp_server::clipboard;
    output.clear();
    if (poisoned_ || pendingValid_ || pendingFileContentsValid_ ||
        fileLockWriteActive_ ||
        fileContentsSequence_ >=
            std::numeric_limits<std::uint32_t>::max())
    {
        return std::nullopt;
    }

    const RemoteFileDescriptor *file = nullptr;
    std::uint64_t sourceGeneration = 0;
    if (clipDataId == 0)
    {
        if (!fileStreamingAvailable() ||
            remoteFileGeneration_ != generation_ ||
            fileIndex >= remoteFileCount_)
        {
            return std::nullopt;
        }
        file = &remoteFiles_[fileIndex];
        sourceGeneration = generation_;
    }
    else
    {
        if (!fileLockSessionPrerequisitesMet() || !fileLockPresent_ ||
            clipDataId != lockedClipDataId_ ||
            lockedRemoteFileGeneration_ == 0 ||
            fileIndex >= lockedRemoteFileCount_)
        {
            return std::nullopt;
        }
        file = &lockedRemoteFiles_[fileIndex];
        sourceGeneration = lockedRemoteFileGeneration_;
    }

    const bool hugeFiles =
        (negotiatedGeneralFlags_ & kHugeFileSupportEnabled) != 0;
    if (kind == FileContentsKind::Size)
    {
        if (offset != 0 || requestedBytes != 8U)
        {
            return std::nullopt;
        }
    }
    else if (file->directory || !file->sizeKnown || requestedBytes == 0 ||
             requestedBytes > kMaximumFileContentsChunkBytes ||
             offset >= file->size ||
             requestedBytes > file->size - offset ||
             (!hugeFiles &&
              (file->size > std::numeric_limits<std::uint32_t>::max() ||
               offset > static_cast<std::uint64_t>(
                            std::numeric_limits<std::int32_t>::max()))))
    {
        return std::nullopt;
    }

    const std::uint64_t nextSequence = fileContentsSequence_ + 1U;
    const std::uint32_t streamId = static_cast<std::uint32_t>(nextSequence);
    std::array<std::uint8_t, 28> payload{};
    write32(payload, 0, streamId);
    write32(payload, 4, static_cast<std::uint32_t>(fileIndex));
    write32(payload, 8, kind == FileContentsKind::Size ?
                            kFileContentsSize : kFileContentsRange);
    write32(payload, 12, static_cast<std::uint32_t>(offset));
    write32(payload, 16, static_cast<std::uint32_t>(offset >> 32U));
    write32(payload, 20, static_cast<std::uint32_t>(requestedBytes));
    const std::size_t payloadBytes = clipDataId == 0 ? 24U : 28U;
    if (clipDataId != 0)
    {
        write32(payload, 24, clipDataId);
    }

    std::vector<std::uint8_t> candidate;
    if (!encodePdu(kFileContentsRequest, 0,
                   std::span<const std::uint8_t>{payload}.first(payloadBytes),
                   candidate))
    {
        return std::nullopt;
    }

    output.swap(candidate);
    fileContentsSequence_ = nextSequence;
    pendingFileContents_ = PendingFileContentsRequest{
        nextSequence, sourceGeneration, streamId, clipDataId, fileIndex,
        offset, requestedBytes, kind};
    pendingFileContentsValid_ = true;
    return FileContentsRequestReceipt{
        nextSequence, sourceGeneration, streamId, clipDataId, fileIndex,
        offset, requestedBytes, kind};
}

std::optional<RemoteTransfer::FileContentsRequestReceipt>
RemoteTransfer::beginFileSizeRequest(
    std::size_t fileIndex,
    std::vector<std::uint8_t> &output) noexcept
{
    return beginFileContentsRequest(
        FileContentsKind::Size, 0, fileIndex, 0, 8U, output);
}

std::optional<RemoteTransfer::FileContentsRequestReceipt>
RemoteTransfer::beginFileRangeRequest(
    std::size_t fileIndex, std::uint64_t offset,
    std::size_t requestedBytes,
    std::vector<std::uint8_t> &output) noexcept
{
    return beginFileContentsRequest(
        FileContentsKind::Range, 0, fileIndex, offset,
        requestedBytes, output);
}

std::optional<RemoteTransfer::FileContentsRequestReceipt>
RemoteTransfer::beginLockedFileSizeRequest(
    std::uint32_t clipDataId, std::size_t fileIndex,
    std::vector<std::uint8_t> &output) noexcept
{
    return beginFileContentsRequest(
        FileContentsKind::Size, clipDataId, fileIndex, 0, 8U, output);
}

std::optional<RemoteTransfer::FileContentsRequestReceipt>
RemoteTransfer::beginLockedFileRangeRequest(
    std::uint32_t clipDataId, std::size_t fileIndex,
    std::uint64_t offset, std::size_t requestedBytes,
    std::vector<std::uint8_t> &output) noexcept
{
    return beginFileContentsRequest(
        FileContentsKind::Range, clipDataId, fileIndex, offset,
        requestedBytes, output);
}

std::optional<RemoteTransfer::JoinedFileContentsRequestReceipt>
RemoteTransfer::prepareJoinedFileContentsRequest(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
    FileContentsKind kind, std::uint32_t clipDataId,
    std::size_t fileIndex, std::uint64_t offset,
    std::size_t requestedBytes,
    std::span<std::uint8_t> output) noexcept
{
    if (poisoned_ || pendingFileContentsValid_ ||
        joinedFileContentsActive_ || fileLockWriteActive_ ||
        channelId == 0 || channelId != expectedCliprdrChannelId ||
        !joinedChannels.channelJoinConfirmed(channelId))
    {
        return std::nullopt;
    }

    std::vector<std::uint8_t> pdu;
    const auto request = beginFileContentsRequest(
        kind, clipDataId, fileIndex, offset, requestedBytes, pdu);
    if (!request)
    {
        return std::nullopt;
    }

    constexpr std::size_t kUnlockedPduBytes = 32U;
    constexpr std::size_t kLockedPduBytes = 36U;
    constexpr std::size_t kStaticChannelHeaderBytes = 8U;
    const std::size_t expectedPduBytes =
        clipDataId == 0 ? kUnlockedPduBytes : kLockedPduBytes;
    if (pdu.size() != expectedPduBytes)
    {
        (void)cancelUnsentFileContentsRequest(request->sequence);
        return std::nullopt;
    }

    std::array<std::uint8_t,
               kStaticChannelHeaderBytes + kLockedPduBytes> channelData{};
    auto channelDataView = std::span<std::uint8_t>{channelData}.first(
        kStaticChannelHeaderBytes + pdu.size());
    write32(channelDataView, 0, static_cast<std::uint32_t>(pdu.size()));
    write32(channelDataView, 4, 3U);
    std::copy(pdu.begin(), pdu.end(),
              channelDataView.begin() + kStaticChannelHeaderBytes);
    const auto framed = joinedChannels.encodeJoinedSendDataIndication(
        channelId, 1, 3, channelDataView, output);
    if (!framed)
    {
        (void)cancelUnsentFileContentsRequest(request->sequence);
        return std::nullopt;
    }

    joinedFileContentsActiveSequence_ = request->sequence;
    joinedFileContentsFrameBytes_ = *framed;
    joinedFileContentsWrittenBytes_ = 0;
    joinedFileContentsActive_ = true;
    return JoinedFileContentsRequestReceipt{*request, *framed};
}

std::optional<RemoteTransfer::JoinedFileContentsRequestReceipt>
RemoteTransfer::prepareJoinedFileSizeRequest(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
    std::size_t fileIndex, std::span<std::uint8_t> output) noexcept
{
    return prepareJoinedFileContentsRequest(
        joinedChannels, channelId, expectedCliprdrChannelId,
        FileContentsKind::Size, 0, fileIndex, 0, 8U, output);
}

std::optional<RemoteTransfer::JoinedFileContentsRequestReceipt>
RemoteTransfer::prepareJoinedFileRangeRequest(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
    std::size_t fileIndex, std::uint64_t offset,
    std::size_t requestedBytes, std::span<std::uint8_t> output) noexcept
{
    return prepareJoinedFileContentsRequest(
        joinedChannels, channelId, expectedCliprdrChannelId,
        FileContentsKind::Range, 0, fileIndex, offset,
        requestedBytes, output);
}

std::optional<RemoteTransfer::JoinedFileContentsRequestReceipt>
RemoteTransfer::prepareJoinedLockedFileSizeRequest(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
    std::uint32_t clipDataId, std::size_t fileIndex,
    std::span<std::uint8_t> output) noexcept
{
    return prepareJoinedFileContentsRequest(
        joinedChannels, channelId, expectedCliprdrChannelId,
        FileContentsKind::Size, clipDataId, fileIndex, 0, 8U, output);
}

std::optional<RemoteTransfer::JoinedFileContentsRequestReceipt>
RemoteTransfer::prepareJoinedLockedFileRangeRequest(
    const transport::McsChannelJoinWriteGate &joinedChannels,
    std::uint16_t channelId, std::uint16_t expectedCliprdrChannelId,
    std::uint32_t clipDataId, std::size_t fileIndex,
    std::uint64_t offset, std::size_t requestedBytes,
    std::span<std::uint8_t> output) noexcept
{
    return prepareJoinedFileContentsRequest(
        joinedChannels, channelId, expectedCliprdrChannelId,
        FileContentsKind::Range, clipDataId, fileIndex, offset,
        requestedBytes, output);
}

bool RemoteTransfer::fileContentsRequestSourceStillValid(
    const PendingFileContentsRequest &request) const noexcept
{
    if (request.clipDataId == 0)
    {
        return request.generation == generation_ &&
               remoteFileGeneration_ == request.generation &&
               request.fileIndex < remoteFileCount_;
    }
    return fileLockPresent_ &&
           request.clipDataId == lockedClipDataId_ &&
           request.generation == lockedRemoteFileGeneration_ &&
           request.fileIndex < lockedRemoteFileCount_;
}

bool RemoteTransfer::joinedFileContentsRequestMayWrite(
    std::uint64_t sequence) const noexcept
{
    return !poisoned_ && pendingFileContentsValid_ &&
           joinedFileContentsActive_ && sequence != 0 &&
           sequence == joinedFileContentsActiveSequence_ &&
           fileContentsRequestSourceStillValid(pendingFileContents_) &&
           joinedFileContentsWrittenBytes_ < joinedFileContentsFrameBytes_;
}

bool RemoteTransfer::recordJoinedFileContentsRequestWritten(
    std::uint64_t sequence, std::size_t cumulativeBytes) noexcept
{
    if (poisoned_ || !pendingFileContentsValid_ ||
        !joinedFileContentsActive_ || sequence == 0 ||
        sequence != joinedFileContentsActiveSequence_)
    {
        return false;
    }
    if (cumulativeBytes < joinedFileContentsWrittenBytes_ ||
        cumulativeBytes > joinedFileContentsFrameBytes_)
    {
        poisoned_ = true;
        return false;
    }
    if (!fileContentsRequestSourceStillValid(pendingFileContents_))
    {
        if (cumulativeBytes > joinedFileContentsWrittenBytes_)
        {
            poisoned_ = true;
        }
        return false;
    }
    joinedFileContentsWrittenBytes_ = cumulativeBytes;
    return true;
}

bool RemoteTransfer::cancelUnwrittenJoinedFileContentsRequest(
    std::uint64_t sequence) noexcept
{
    if (poisoned_ || !pendingFileContentsValid_ ||
        !joinedFileContentsActive_ || sequence == 0 ||
        sequence != joinedFileContentsActiveSequence_ ||
        joinedFileContentsWrittenBytes_ != 0)
    {
        return false;
    }
    pendingFileContents_ = {};
    pendingFileContentsValid_ = false;
    joinedFileContentsActiveSequence_ = 0;
    joinedFileContentsFrameBytes_ = 0;
    joinedFileContentsWrittenBytes_ = 0;
    joinedFileContentsActive_ = false;
    return true;
}

bool RemoteTransfer::abandonJoinedFileContentsRequest(
    std::uint64_t sequence) noexcept
{
    if (!pendingFileContentsValid_ || !joinedFileContentsActive_ ||
        sequence == 0 || sequence != joinedFileContentsActiveSequence_)
    {
        return false;
    }
    if (joinedFileContentsWrittenBytes_ == 0)
    {
        return cancelUnwrittenJoinedFileContentsRequest(sequence);
    }
    poisoned_ = true;
    return true;
}

RemoteTransfer::FileContentsResult
RemoteTransfer::receiveFileContentsResponse(
    std::span<const std::uint8_t> completePdu) noexcept
{
    using namespace rdp_server::clipboard;
    FileContentsResult result{};
    PduView pdu{};
    if (poisoned_ || !pendingFileContentsValid_ ||
        !decodePdu(completePdu, pdu) ||
        pdu.type != kFileContentsResponse ||
        (pdu.flags != kResponseOk && pdu.flags != kResponseFail) ||
        pdu.payload.size() < 4U)
    {
        poisoned_ = true;
        result.status = FileContentsStatus::ProtocolError;
        return result;
    }

    if (joinedFileContentsActive_ &&
        joinedFileContentsWrittenBytes_ != joinedFileContentsFrameBytes_)
    {
        poisoned_ = true;
        result.status = FileContentsStatus::ProtocolError;
        return result;
    }

    const PendingFileContentsRequest completed = pendingFileContents_;
    const bool sourceStillValid =
        fileContentsRequestSourceStillValid(completed);
    result.sequence = completed.sequence;
    result.generation = completed.generation;
    result.streamId = completed.streamId;
    result.clipDataId = completed.clipDataId;
    result.fileIndex = completed.fileIndex;
    result.offset = completed.offset;
    const std::uint32_t streamId = read32(pdu.payload, 0);
    if (streamId != completed.streamId)
    {
        poisoned_ = true;
        result.status = FileContentsStatus::ProtocolError;
        return result;
    }

    pendingFileContents_ = {};
    pendingFileContentsValid_ = false;
    joinedFileContentsActiveSequence_ = 0;
    joinedFileContentsFrameBytes_ = 0;
    joinedFileContentsWrittenBytes_ = 0;
    joinedFileContentsActive_ = false;

    if (completed.clipDataId != 0 && !sourceStillValid)
    {
        poisoned_ = true;
        result.status = FileContentsStatus::ProtocolError;
        return result;
    }
    const bool obsoleteCurrentGeneration =
        completed.clipDataId == 0 && !sourceStillValid;

    if (pdu.flags == kResponseFail)
    {
        if (pdu.payload.size() != 4U)
        {
            poisoned_ = true;
            result.status = FileContentsStatus::ProtocolError;
            return result;
        }
        result.status = obsoleteCurrentGeneration ?
            FileContentsStatus::DiscardedPreviousGeneration :
            FileContentsStatus::RemoteFailure;
        return result;
    }

    if (completed.kind == FileContentsKind::Size)
    {
        if (pdu.payload.size() != 12U)
        {
            poisoned_ = true;
            result.status = FileContentsStatus::ProtocolError;
            return result;
        }
        const std::uint64_t fileSize = read64(pdu.payload, 4U);
        if ((negotiatedGeneralFlags_ & kHugeFileSupportEnabled) == 0 &&
            fileSize > std::numeric_limits<std::uint32_t>::max())
        {
            poisoned_ = true;
            result.status = FileContentsStatus::ProtocolError;
            return result;
        }
        result.fileSize = fileSize;
        if (obsoleteCurrentGeneration)
        {
            result.status = FileContentsStatus::DiscardedPreviousGeneration;
            return result;
        }

        auto &file = completed.clipDataId == 0 ?
            remoteFiles_[completed.fileIndex] :
            lockedRemoteFiles_[completed.fileIndex];
        file.size = fileSize;
        file.sizeKnown = true;
        result.status = FileContentsStatus::ReceivedSize;
        return result;
    }

    const auto bytes = pdu.payload.subspan(4U);
    if (bytes.empty() || bytes.size() > completed.requestedBytes)
    {
        poisoned_ = true;
        result.status = FileContentsStatus::ProtocolError;
        return result;
    }
    if (obsoleteCurrentGeneration)
    {
        result.status = FileContentsStatus::DiscardedPreviousGeneration;
        return result;
    }

    const auto &file = completed.clipDataId == 0 ?
        remoteFiles_[completed.fileIndex] :
        lockedRemoteFiles_[completed.fileIndex];
    if (!file.sizeKnown || completed.offset >= file.size ||
        bytes.size() > file.size - completed.offset)
    {
        poisoned_ = true;
        result.status = FileContentsStatus::ProtocolError;
        return result;
    }
    result.bytes = bytes;
    result.status = FileContentsStatus::ReceivedRange;
    return result;
}

bool RemoteTransfer::cancelUnsentFileContentsRequest(
    std::uint64_t sequence) noexcept
{
    if (poisoned_ || !pendingFileContentsValid_ ||
        joinedFileContentsActive_ || sequence == 0 ||
        sequence != pendingFileContents_.sequence)
    {
        return false;
    }
    pendingFileContents_ = {};
    pendingFileContentsValid_ = false;
    return true;
}

bool RemoteTransfer::hasOutstandingFileContentsRequest() const noexcept
{
    return pendingFileContentsValid_;
}

bool RemoteTransfer::beginNextPrefetch(
    PrefetchKind kind,
    std::uint32_t &selectedFormatId,
    std::vector<std::uint8_t> &output) noexcept
{
    selectedFormatId = 0;
    output.clear();
    // Without a wire request ID, a pending format-data reply cannot be
    // overtaken even if a new offer replaced the current generation.
    if (poisoned_ || generation_ == 0 || pendingValid_ ||
        hasPendingPasteRequest())
        return false;

    constexpr std::uint32_t kDibV5FormatId = 17;
    constexpr std::uint32_t kDibFormatId = 8;
    const std::array<std::uint32_t, 3> preferences =
        kind == PrefetchKind::UnicodeText
            ? std::array<std::uint32_t, 3>{rdp_server::clipboard::kFormatUnicodeText, 0, 0}
            : std::array<std::uint32_t, 3>{pngFormatId_, kDibV5FormatId,
                                           kDibFormatId};
    for (const auto id : preferences)
    {
        if (id == 0 || !advertises(id) ||
            std::find(attemptedPrefetchIds_.begin(),
                      attemptedPrefetchIds_.end(), id) !=
                attemptedPrefetchIds_.end())
            continue;
        // Every selected ID must have one unused bookkeeping slot.
        const auto slot = std::find(
            attemptedPrefetchIds_.begin(), attemptedPrefetchIds_.end(), 0U);
        if (slot == attemptedPrefetchIds_.end() ||
            !beginRequest(id, output))
            return false;
        *slot = id;
        selectedFormatId = id;
        return true;
    }
    return false;
}

RemoteTransfer::Response RemoteTransfer::receiveResponse(
    std::span<const std::uint8_t> completePdu) noexcept
{
    using namespace rdp_server::clipboard;
    PduView pdu{};
    if (poisoned_ || !pendingValid_ || !decodePdu(completePdu, pdu) ||
        pdu.type != kFormatDataResponse ||
        (pdu.flags != kResponseOk && pdu.flags != kResponseFail) ||
        (pdu.flags & ~kAllowedResponseFlags) != 0 ||
        (pdu.flags == kResponseFail && !pdu.payload.empty()))
    {
        poisoned_ = true;
        return {};
    }

    // An early reply cannot prove a prepared or partially written request
    // was delivered; leave the channel poisoned instead of reusing its slot.
    if (joinedRequestActive_ &&
        joinedRequestWrittenBytes_ != joinedRequestFrameBytes_)
    {
        poisoned_ = true;
        return {};
    }
    const PendingRequest completed = pending_;
    pending_ = {};
    pendingValid_ = false;
    joinedRequestActive_ = false;
    joinedRequestActiveSequence_ = 0;
    joinedRequestFrameBytes_ = 0;
    joinedRequestWrittenBytes_ = 0;
    if (completed.generation != generation_)
    {
        return {ResponseStatus::DiscardedPreviousGeneration,
                completed.generation, completed.formatId, {}};
    }
    if (pdu.flags == kResponseFail)
    {
        return {ResponseStatus::RemoteFailure,
                completed.generation, completed.formatId, {}};
    }
    return {ResponseStatus::Received, completed.generation,
            completed.formatId, pdu.payload};
}

bool RemoteTransfer::storeVerifiedUnicodeText(
    const Response &response) noexcept
{
    using rdp_server::clipboard::kFormatUnicodeText;
    verifiedTextReady_ = false;
    verifiedTextUtf8_.clear();
    if (poisoned_ || generation_ == 0 || pendingValid_ ||
        response.status != ResponseStatus::Received ||
        response.generation != generation_ ||
        response.formatId != kFormatUnicodeText ||
        !advertises(kFormatUnicodeText))
        return false;

    // Win32 CF_UNICODETEXT: exactly one terminal UTF-16LE NUL, no interior
    // NUL, strict surrogate pairs. One MiB wire cap bounds UTF-8 below
    // 1.5 MiB; never publish a partially decoded or truncated string.
    constexpr std::size_t kMaximumTextBytes = 1024U * 1024U;
    const auto wire = response.payload;
    if (wire.size() < 2U || wire.size() > kMaximumTextBytes ||
        wire.size() % 2U != 0 || wire[wire.size() - 1U] != 0 ||
        wire[wire.size() - 2U] != 0)
        return false;

    std::string candidate;
    try
    {
        candidate.reserve(wire.size());
        for (std::size_t offset = 0; offset < wire.size() - 2U;
             offset += 2U)
        {
            std::uint32_t value = read16(wire, offset);
            if (value == 0)
                return false;
            if (value >= 0xd800U && value <= 0xdbffU)
            {
                if (offset + 4U >= wire.size())
                    return false;
                const std::uint32_t low = read16(wire, offset + 2U);
                if (low < 0xdc00U || low > 0xdfffU)
                    return false;
                value = 0x10000U + ((value - 0xd800U) << 10U) +
                        (low - 0xdc00U);
                offset += 2U;
            }
            else if (value >= 0xdc00U && value <= 0xdfffU)
                return false;

            // Windows line endings are CRLF; native text presentation
            // uses LF. A standalone CR or LF is preserved for interop.
            if (value == '\r' && offset + 4U < wire.size() &&
                read16(wire, offset + 2U) == '\n')
            {
                value = '\n';
                offset += 2U;
            }
            if (value <= 0x7fU)
                candidate.push_back(static_cast<char>(value));
            else if (value <= 0x7ffU)
            {
                candidate.push_back(static_cast<char>(0xc0U | (value >> 6U)));
                candidate.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
            }
            else if (value <= 0xffffU)
            {
                candidate.push_back(static_cast<char>(0xe0U | (value >> 12U)));
                candidate.push_back(static_cast<char>(0x80U |
                                                      ((value >> 6U) & 0x3fU)));
                candidate.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
            }
            else
            {
                candidate.push_back(static_cast<char>(0xf0U | (value >> 18U)));
                candidate.push_back(static_cast<char>(0x80U |
                                                      ((value >> 12U) & 0x3fU)));
                candidate.push_back(static_cast<char>(0x80U |
                                                      ((value >> 6U) & 0x3fU)));
                candidate.push_back(static_cast<char>(0x80U | (value & 0x3fU)));
            }
        }
    }
    catch (...)
    {
        return false;
    }
    verifiedTextUtf8_.swap(candidate);
    verifiedTextReady_ = true;
    return true;
}

std::optional<std::string_view>
RemoteTransfer::verifiedUnicodeText() const noexcept
{
    if (poisoned_ || !verifiedTextReady_)
        return std::nullopt;
    return std::string_view{verifiedTextUtf8_};
}

bool RemoteTransfer::storeVerifiedImage(const Response &response) noexcept
{
    using namespace rdp_server::clipboard;
    constexpr std::uint32_t kDibFormatId = 8;
    constexpr std::uint32_t kDibV5FormatId = 17;
    constexpr std::uint32_t kBitmapV5HeaderBytes = 124;
    const auto wire = response.payload;
    if (poisoned_ || generation_ == 0 || pendingValid_ ||
        response.status != ResponseStatus::Received ||
        response.generation != generation_ || !advertises(response.formatId) ||
        wire.empty() || wire.size() > kMaximumStoredImageBytes)
    {
        return false;
    }

    VerifiedImageFormat candidateFormat{};
    std::uint32_t width = 0;
    std::uint64_t height = 0;
    // Registered PNG is generation-scoped and may numerically collide with a
    // standard format. Resolve the advertised name before numeric fallbacks.
    if (pngFormatId_ != 0 && response.formatId == pngFormatId_)
    {
        PngInfo info{};
        if (!validatePng(wire, info))
        {
            return false;
        }
        candidateFormat = VerifiedImageFormat::Png;
        width = info.width;
        height = info.height;
    }
    else if (response.formatId == kDibV5FormatId)
    {
        if (wire.size() < kBitmapV5HeaderBytes ||
            read32(wire, 0) != kBitmapV5HeaderBytes || !validateDib(wire))
        {
            return false;
        }
        candidateFormat = VerifiedImageFormat::DibV5;
        width = read32(wire, 4);
        height = absoluteDibHeight(read32(wire, 8));
    }
    else if (response.formatId == kDibFormatId)
    {
        if (!validateDib(wire))
        {
            return false;
        }
        candidateFormat = VerifiedImageFormat::Dib;
        width = read32(wire, 4);
        height = absoluteDibHeight(read32(wire, 8));
    }
    else
    {
        return false;
    }
    if (!decodedImageFits(width, height))
    {
        return false;
    }

    std::vector<std::uint8_t> candidate;
    try
    {
        candidate.assign(wire.begin(), wire.end());
    }
    catch (...)
    {
        return false;
    }
    verifiedImageBytes_.swap(candidate);
    verifiedImageFormat_ = candidateFormat;
    verifiedImageGeneration_ = response.generation;
    verifiedImageSourceFormatId_ = response.formatId;
    verifiedImageReady_ = true;
    return true;
}

std::optional<RemoteTransfer::VerifiedImage>
RemoteTransfer::verifiedImage() const noexcept
{
    if (poisoned_ || !verifiedImageReady_ ||
        verifiedImageGeneration_ != generation_)
    {
        return std::nullopt;
    }
    return VerifiedImage{
        verifiedImageFormat_, verifiedImageGeneration_,
        verifiedImageSourceFormatId_,
        std::span<const std::uint8_t>{verifiedImageBytes_.data(),
                                      verifiedImageBytes_.size()}};
}

std::optional<RemoteTransfer::PasteRequestReceipt>
RemoteTransfer::beginPasteRequest(
    PasteKind kind, PasteClock::time_point now,
    PasteClock::time_point deadline) noexcept
{
    using rdp_server::clipboard::kFormatUnicodeText;
    if (poisoned_ || generation_ == 0 || pasteRequestPresent_ ||
        pasteRequestSequence_ == UINT64_MAX || deadline <= now)
    {
        return std::nullopt;
    }

    constexpr std::uint32_t kDibFormatId = 8;
    constexpr std::uint32_t kDibV5FormatId = 17;
    const bool pngOffered =
        pngFormatId_ != 0 && advertises(pngFormatId_);
    const bool contentOffered =
        kind == PasteKind::UnicodeText
            ? advertises(kFormatUnicodeText)
            : kind == PasteKind::Png
                  ? pngOffered
                  : (pngOffered || advertises(kDibV5FormatId) ||
                     advertises(kDibFormatId));
    if (!contentOffered)
    {
        return std::nullopt;
    }

    ++pasteRequestSequence_;
    pasteRequestActiveSequence_ = pasteRequestSequence_;
    pasteRequestGeneration_ = generation_;
    pasteRequestDeadline_ = deadline;
    pasteRequestKind_ = kind;
    pasteRequestStatus_ = PasteStatus::Pending;
    pasteRequestPresent_ = true;
    return PasteRequestReceipt{pasteRequestActiveSequence_,
                               pasteRequestGeneration_};
}

RemoteTransfer::PasteResult RemoteTransfer::pollPasteRequest(
    std::uint64_t sequence, PasteClock::time_point now) noexcept
{
    PasteResult result{};
    if (!pasteRequestPresent_ || sequence == 0 ||
        sequence != pasteRequestActiveSequence_)
    {
        return result;
    }

    if (pasteRequestStatus_ == PasteStatus::Pending)
    {
        if (poisoned_)
        {
            pasteRequestStatus_ = PasteStatus::ChannelError;
        }
        else if (pasteRequestGeneration_ != generation_)
        {
            pasteRequestStatus_ = PasteStatus::ClipboardReplaced;
        }
        else if (now >= pasteRequestDeadline_)
        {
            pasteRequestStatus_ = PasteStatus::TimedOut;
        }
        else if (pasteRequestKind_ == PasteKind::UnicodeText)
        {
            if (verifiedUnicodeText())
            {
                pasteRequestStatus_ = PasteStatus::ReadyUnicodeText;
            }
        }
        else if (pasteRequestKind_ == PasteKind::Png)
        {
            const auto image = verifiedImage();
            if (image &&
                image->format == VerifiedImageFormat::Png &&
                pngFormatId_ != 0 &&
                image->sourceFormatId == pngFormatId_)
            {
                pasteRequestStatus_ = PasteStatus::ReadyImage;
            }
        }
        else if (verifiedImage())
        {
            pasteRequestStatus_ = PasteStatus::ReadyImage;
        }
    }

    result.status = pasteRequestStatus_;
    result.sequence = pasteRequestActiveSequence_;
    result.generation = pasteRequestGeneration_;
    if (pasteRequestStatus_ == PasteStatus::Pending)
    {
        return result;
    }
    if (pasteRequestStatus_ == PasteStatus::ReadyUnicodeText)
    {
        const auto text = verifiedUnicodeText();
        if (!text)
        {
            result.status = PasteStatus::ChannelError;
        }
        else
        {
            result.text = *text;
        }
    }
    else if (pasteRequestStatus_ == PasteStatus::ReadyImage)
    {
        result.image = verifiedImage();
        if (!result.image)
        {
            result.status = PasteStatus::ChannelError;
        }
    }

    // Terminal outcomes are delivered exactly once. The underlying verified
    // payload remains owned by this generation until replacement/disconnect.
    pasteRequestPresent_ = false;
    pasteRequestActiveSequence_ = 0;
    pasteRequestGeneration_ = 0;
    pasteRequestDeadline_ = {};
    pasteRequestStatus_ = PasteStatus::InvalidSequence;
    return result;
}

bool RemoteTransfer::cancelPasteRequestForOwnerLoss(
    std::uint64_t sequence) noexcept
{
    if (!pasteRequestPresent_ || pasteRequestStatus_ != PasteStatus::Pending ||
        sequence == 0 || sequence != pasteRequestActiveSequence_)
    {
        return false;
    }
    pasteRequestStatus_ = PasteStatus::OwnerLost;
    return true;
}

bool RemoteTransfer::hasPendingPasteRequest() const noexcept
{
    return pasteRequestPresent_ &&
           pasteRequestStatus_ == PasteStatus::Pending;
}

void RemoteTransfer::abandonRequest() noexcept
{
    if (pendingValid_)
    {
        poisoned_ = true;
    }
}

void RemoteTransfer::retireR3ChannelState() noexcept
{
    resetAfterDisconnect();
}

void RemoteTransfer::resetAfterDisconnect() noexcept
{
    if (pasteRequestPresent_ &&
        pasteRequestStatus_ == PasteStatus::Pending)
    {
        pasteRequestStatus_ = PasteStatus::Disconnected;
    }
    verifiedTextUtf8_.clear();
    verifiedTextReady_ = false;
    verifiedImageBytes_.clear();
    verifiedImageGeneration_ = 0;
    verifiedImageSourceFormatId_ = 0;
    verifiedImageReady_ = false;
    lastFormatListResponse_.fill(0);
    lastFormatListResponseValid_ = false;
    advertisedFormats_.fill(0);
    advertisedCount_ = 0;
    pngFormatId_ = 0;
    fileGroupDescriptorFormatId_ = 0;
    remoteFiles_.fill({});
    remoteFileCount_ = 0;
    remoteFileGeneration_ = 0;
    lockedRemoteFiles_.fill({});
    lockedRemoteFileCount_ = 0;
    lockedRemoteFileGeneration_ = 0;
    lockedClipDataId_ = 0;
    fileLockPresent_ = false;
    pendingFileLockWrite_ = {};
    fileLockWrittenBytes_ = 0;
    fileLockWriteActive_ = false;
    pendingFileContents_ = {};
    joinedFileContentsActiveSequence_ = 0;
    joinedFileContentsFrameBytes_ = 0;
    joinedFileContentsWrittenBytes_ = 0;
    pendingFileContentsValid_ = false;
    joinedFileContentsActive_ = false;
    attemptedPrefetchIds_.fill(0);
    generation_ = 0;
    negotiatedGeneralFlags_ = 0;
    peerGeneralFlags_ = 0;
    localAdvertisedGeneralFlags_ = 0;
    capabilitiesReceived_ = false;
    temporaryDirectoryReceived_ = false;
    pending_ = {};
    pendingValid_ = false;
    joinedRequestActiveSequence_ = 0;
    joinedRequestFrameBytes_ = 0;
    joinedRequestWrittenBytes_ = 0;
    joinedRequestActive_ = false;
    // Request/file/lock receipt sequences, clipDataIdSequence_ and
    // sourceEpoch_ remain monotonic across reconnects so stale callbacks or
    // destination plans cannot acquire a fresh identity or resurrect an old
    // generation.
    poisoned_ = false;
}

bool RemoteTransfer::synchronized() const noexcept
{
    return !poisoned_;
}

bool RemoteTransfer::hasOutstandingRequest() const noexcept
{
    return pendingValid_;
}

bool RemoteTransfer::waitingForObsoleteResponse() const noexcept
{
    return pendingValid_ && pending_.generation != generation_;
}

std::uint64_t RemoteTransfer::generation() const noexcept
{
    return generation_;
}

std::uint64_t RemoteTransfer::sourceEpoch() const noexcept
{
    return sourceEpoch_;
}

bool RemoteTransfer::advertises(std::uint32_t formatId) const noexcept
{
    return !poisoned_ && formatId != 0 &&
           std::find(advertisedFormats_.begin(),
                     advertisedFormats_.begin() + advertisedCount_,
                     formatId) !=
               advertisedFormats_.begin() + advertisedCount_;
}


RemoteFileDestinationPlan::PrepareStatus
RemoteFileDestinationPlan::prepare(
    const RemoteTransfer &source, const std::uint64_t expectedGeneration,
    const std::span<const Selection> selections) noexcept
{
    if (state_ == State::Committed)
    {
        return PrepareStatus::AlreadyCommitted;
    }
    if (state_ == State::Cancelled)
    {
        return PrepareStatus::Cancelled;
    }
    if (state_ == State::Closed)
    {
        return PrepareStatus::Closed;
    }
    if (!source.synchronized())
    {
        return PrepareStatus::SourceNotSynchronized;
    }
    if (expectedGeneration == 0U)
    {
        return PrepareStatus::GenerationRequired;
    }
    if (source.generation() != expectedGeneration)
    {
        return PrepareStatus::StaleGeneration;
    }

    const std::size_t remoteFileCount = source.remoteFileCount();
    if (remoteFileCount == 0U)
    {
        return PrepareStatus::NoRemoteDescriptors;
    }
    if (selections.size() > kMaximumAssociations)
    {
        return PrepareStatus::TooManySelections;
    }
    if (selections.empty())
    {
        return PrepareStatus::EmptyManifest;
    }

    std::array<Association, kMaximumAssociations> candidates{};
    std::array<bool, kMaximumAssociations> mapped{};
    for (const Selection &selection : selections)
    {
        if (selection.remoteFileIndex >= remoteFileCount)
        {
            return PrepareStatus::RemoteIndexOutOfRange;
        }
        if (selection.localSelectionIdentity == 0U)
        {
            return PrepareStatus::MissingDestination;
        }

        const std::size_t remoteFileIndex = selection.remoteFileIndex;
        if (mapped[remoteFileIndex])
        {
            const Association &existing = candidates[remoteFileIndex];
            if (existing.localSelectionIdentity !=
                    selection.localSelectionIdentity ||
                existing.parentRemoteFileIndex !=
                    selection.parentRemoteFileIndex)
            {
                return PrepareStatus::AmbiguousPlacement;
            }
            return PrepareStatus::DuplicateRemoteIndex;
        }

        for (std::size_t index = 0; index < remoteFileCount; ++index)
        {
            if (mapped[index] &&
                candidates[index].localSelectionIdentity ==
                    selection.localSelectionIdentity)
            {
                return PrepareStatus::DuplicateDestination;
            }
        }

        const auto file = source.remoteFile(remoteFileIndex);
        if (!file)
        {
            return PrepareStatus::DescriptorUnavailable;
        }

        const auto hierarchyNode =
            source.remoteHierarchyNode(remoteFileIndex);
        candidates[remoteFileIndex] = Association{
            remoteFileIndex,
            selection.localSelectionIdentity,
            selection.parentRemoteFileIndex,
            hierarchyNode ? hierarchyNode->parentRemoteFileIndex :
                            std::nullopt,
            hierarchyNode ? hierarchyNode->depth : std::uint16_t{0},
            file->directory ? RemoteEntryRole::Directory :
                              RemoteEntryRole::File,
        };
        mapped[remoteFileIndex] = true;
    }

    // A batch is all-or-nothing. A caller that selects only a subset must use
    // a separate future contract rather than accidentally publishing a partial
    // manifest as a completed set.
    if (selections.size() != remoteFileCount)
    {
        return PrepareStatus::IncompleteManifest;
    }
    for (std::size_t index = 0; index < remoteFileCount; ++index)
    {
        if (!mapped[index])
        {
            return PrepareStatus::IncompleteManifest;
        }

        const auto parent = candidates[index].parentRemoteFileIndex;
        if (!parent)
        {
            continue;
        }
        if (*parent >= remoteFileCount || !mapped[*parent])
        {
            return PrepareStatus::MissingParent;
        }
        if (*parent == index)
        {
            return PrepareStatus::SelfParent;
        }
        if (candidates[*parent].remoteRole != RemoteEntryRole::Directory)
        {
            return PrepareStatus::ParentNotDirectory;
        }
    }

    // Parent metadata is caller-selected local placement only. Bound it anyway
    // so a future native directory capability cannot inherit cycles or
    // unbounded traversal from this contract.
    for (std::size_t startIndex = 0;
         startIndex < remoteFileCount; ++startIndex)
    {
        std::array<bool, kMaximumAssociations> inPath{};
        inPath[startIndex] = true;
        std::size_t depth = 0U;
        auto parent = candidates[startIndex].parentRemoteFileIndex;
        while (parent)
        {
            if (*parent >= remoteFileCount || !mapped[*parent])
            {
                return PrepareStatus::MissingParent;
            }
            if (inPath[*parent])
            {
                return PrepareStatus::ParentCycle;
            }
            inPath[*parent] = true;
            ++depth;
            if (depth > kMaximumPlacementDepth)
            {
                return PrepareStatus::PlacementDepthExceeded;
            }
            parent = candidates[*parent].parentRemoteFileIndex;
        }
    }

    associations_ = candidates;
    associationCount_ = remoteFileCount;
    generation_ = expectedGeneration;
    sourceEpoch_ = source.sourceEpoch_;
    source_ = &source;
    state_ = State::Committed;
    return PrepareStatus::Prepared;
}

bool RemoteFileDestinationPlan::current(
    const RemoteTransfer &source) const noexcept
{
    if (state_ != State::Committed || source_ != &source ||
        !source.synchronized() || generation_ == 0U ||
        source.generation() != generation_ ||
        source.sourceEpoch_ != sourceEpoch_ ||
        source.remoteFileCount() != associationCount_)
    {
        return false;
    }

    for (std::size_t index = 0; index < associationCount_; ++index)
    {
        const auto file = source.remoteFile(index);
        if (!file)
        {
            return false;
        }
        const RemoteEntryRole currentRole =
            file->directory ? RemoteEntryRole::Directory :
                              RemoteEntryRole::File;
        if (associations_[index].remoteFileIndex != index ||
            associations_[index].remoteRole != currentRole)
        {
            return false;
        }
    }
    return true;
}

std::optional<RemoteFileDestinationPlan::Association>
RemoteFileDestinationPlan::association(
    const RemoteTransfer &source,
    const std::size_t remoteFileIndex) const noexcept
{
    if (!current(source) || remoteFileIndex >= associationCount_)
    {
        return std::nullopt;
    }
    return associations_[remoteFileIndex];
}

RemoteFileDestinationPlan::AssociationStatus
RemoteFileDestinationPlan::associationStatus(
    const RemoteTransfer &source,
    const std::size_t remoteFileIndex) const noexcept
{
    if (state_ == State::Empty)
    {
        return AssociationStatus::NotCommitted;
    }
    if (state_ == State::Cancelled)
    {
        return AssociationStatus::Cancelled;
    }
    if (state_ == State::Closed)
    {
        return AssociationStatus::Closed;
    }
    if (!current(source))
    {
        return AssociationStatus::StaleSource;
    }
    if (remoteFileIndex >= associationCount_)
    {
        return AssociationStatus::MissingAssociation;
    }
    return associations_[remoteFileIndex].remoteRole ==
                   RemoteEntryRole::Directory
               ? AssociationStatus::UnsupportedDirectoryMaterialization
               : AssociationStatus::CurrentFile;
}

void RemoteFileDestinationPlan::retireMetadata(
    const State terminalState) noexcept
{
    associations_.fill({});
    associationCount_ = 0U;
    generation_ = 0U;
    sourceEpoch_ = 0U;
    source_ = nullptr;
    state_ = terminalState;
}

void RemoteFileDestinationPlan::cancel() noexcept
{
    if (state_ == State::Cancelled || state_ == State::Closed)
    {
        return;
    }
    retireMetadata(State::Cancelled);
}

void RemoteFileDestinationPlan::close() noexcept
{
    if (state_ == State::Cancelled || state_ == State::Closed)
    {
        return;
    }
    retireMetadata(State::Closed);
}

} // namespace rdp_server::server::clipboard
