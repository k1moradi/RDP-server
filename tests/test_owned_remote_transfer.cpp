// SPDX-License-Identifier: GPL-3.0-or-later
#include "clipboard/clipboard_protocol.h"
#include "transport/mcs_channel_connection.h"
#include "clipboard/remote_transfer.h"

#include <algorithm>
#include <array>
// Release builds set NDEBUG. Keep all correctness checks live under -O3.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <chrono>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using rdp_server::server::clipboard::RemoteTransfer;
using rdp_server::clipboard::PduView;
using rdp_server::clipboard::decodePdu;
using rdp_server::clipboard::encodePdu;

namespace
{
std::vector<std::uint8_t> responsePdu(
    std::uint16_t flags, std::span<const std::uint8_t> payload = {})
{
    std::vector<std::uint8_t> result;
    assert(encodePdu(rdp_server::clipboard::kFormatDataResponse,
                     flags, payload, result));
    return result;
}

std::vector<std::uint8_t> capabilitiesPdu(std::uint32_t generalFlags)
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
    assert(encodePdu(rdp_server::clipboard::kClipCaps, 0, payload, result));
    return result;
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

void put64(std::span<std::uint8_t> bytes, std::size_t offset,
           std::uint64_t value)
{
    put32(bytes, offset, static_cast<std::uint32_t>(value));
    put32(bytes, offset + 4U, static_cast<std::uint32_t>(value >> 32U));
}

void putFileName(std::span<std::uint8_t> descriptor,
                 std::u16string_view name)
{
    constexpr std::size_t kNameOffset = 72U;
    constexpr std::size_t kMaximumNameCodeUnits = 260U;
    assert(name.size() < kMaximumNameCodeUnits);
    assert(descriptor.size() >= kNameOffset + kMaximumNameCodeUnits * 2U);
    for (std::size_t index = 0; index < name.size(); ++index)
    {
        const std::uint16_t codeUnit = static_cast<std::uint16_t>(name[index]);
        descriptor[kNameOffset + index * 2U] =
            static_cast<std::uint8_t>(codeUnit);
        descriptor[kNameOffset + index * 2U + 1U] =
            static_cast<std::uint8_t>(codeUnit >> 8U);
    }
}

std::vector<std::uint8_t> fileContentsResponsePdu(
    std::uint16_t flags, std::uint32_t streamId,
    std::span<const std::uint8_t> data = {})
{
    std::vector<std::uint8_t> payload(4U + data.size());
    put32(payload, 0, streamId);
    std::copy(data.begin(), data.end(), payload.begin() + 4U);
    std::vector<std::uint8_t> result;
    assert(encodePdu(rdp_server::clipboard::kFileContentsResponse,
                     flags, payload, result));
    return result;
}

void testBasicRequestAndFailure()
{
    RemoteTransfer transfer;
    const std::array<std::uint32_t, 3> formats{13, 8, 40005};
    assert(transfer.receiveFormatList(formats));
    assert(transfer.generation() == 1);
    assert(transfer.advertises(40005));
    std::vector<std::uint8_t> request;
    assert(!transfer.beginRequest(999, request));
    assert(transfer.beginRequest(40005, request));
    assert(!transfer.beginRequest(13, request));
    assert(request.empty());
    // The first request remains outstanding even if another call failed.
    const std::array<std::uint8_t, 3> image{1, 2, 3};
    const auto response = responsePdu(
        rdp_server::clipboard::kResponseOk, image);
    const auto result = transfer.receiveResponse(response);
    assert(result.status == RemoteTransfer::ResponseStatus::Received);
    assert(result.formatId == 40005 && result.generation == 1);
    assert(result.payload.size() == 3 && result.payload[2] == 3);
    assert(transfer.beginRequest(13, request));
    assert(request == std::vector<std::uint8_t>({
        4, 0, 0, 0, 4, 0, 0, 0, 13, 0, 0, 0}));
    const auto failed = responsePdu(rdp_server::clipboard::kResponseFail);
    assert(transfer.receiveResponse(failed).status ==
           RemoteTransfer::ResponseStatus::RemoteFailure);
    assert(!transfer.hasOutstandingRequest());
}

void testOldResponseCannotBecomeNewPayload()
{
    RemoteTransfer transfer;
    std::vector<std::uint8_t> request;
    const std::array<std::uint32_t, 2> initial{13, 40005};
    assert(transfer.receiveFormatList(initial));
    assert(transfer.beginRequest(40005, request));
    const std::array<std::uint32_t, 2> newer{8, 13};
    assert(transfer.receiveFormatList(newer));
    assert(transfer.waitingForObsoleteResponse());
    assert(!transfer.beginRequest(13, request));
    assert(request.empty());
    const std::array<std::uint8_t, 2> obsoleteBytes{7, 9};
    const auto oldResponse = responsePdu(
        rdp_server::clipboard::kResponseOk, obsoleteBytes);
    const auto stale = transfer.receiveResponse(oldResponse);
    assert(stale.status ==
           RemoteTransfer::ResponseStatus::DiscardedPreviousGeneration);
    assert(stale.payload.empty());
    assert(!transfer.waitingForObsoleteResponse());
    assert(transfer.beginRequest(13, request));
    const std::array<std::uint8_t, 2> latestBytes{5, 6};
    const auto currentResponse = responsePdu(
        rdp_server::clipboard::kResponseOk, latestBytes);
    assert(transfer.receiveResponse(currentResponse).status ==
           RemoteTransfer::ResponseStatus::Received);
}

void testPoisonAndDisconnect()
{
    RemoteTransfer transfer;
    std::vector<std::uint8_t> request;
    const std::array<std::uint32_t, 1> formats{13};
    assert(transfer.receiveFormatList(formats));
    assert(transfer.beginRequest(13, request));
    transfer.abandonRequest();
    assert(!transfer.synchronized());
    assert(!transfer.beginRequest(13, request));
    transfer.resetAfterDisconnect();
    assert(transfer.synchronized());
    assert(!transfer.beginRequest(13, request));
    assert(transfer.receiveFormatList(formats));
    const auto unsolicited = responsePdu(
        rdp_server::clipboard::kResponseOk);
    assert(transfer.receiveResponse(unsolicited).status ==
           RemoteTransfer::ResponseStatus::ProtocolError);
    assert(!transfer.synchronized());
}

void testMalformedPacketsAndLists()
{
    RemoteTransfer transfer;
    const std::array<std::uint32_t, 2> duplicate{13, 13};
    assert(!transfer.receiveFormatList(duplicate));
    assert(!transfer.synchronized());
    transfer.resetAfterDisconnect();
    const std::array<std::uint32_t, 1> zero{0};
    assert(!transfer.receiveFormatList(zero));
    transfer.resetAfterDisconnect();

    std::array<std::uint32_t, RemoteTransfer::kMaximumFormats + 1> excessive{};
    for (std::size_t index = 0; index < excessive.size(); ++index)
    {
        excessive[index] = static_cast<std::uint32_t>(index + 1);
    }
    assert(!transfer.receiveFormatList(excessive));
    transfer.resetAfterDisconnect();
    const std::array<std::uint32_t, 1> formats{13};
    assert(transfer.receiveFormatList(formats));
    std::vector<std::uint8_t> request;
    assert(transfer.beginRequest(13, request));
    const std::array<std::uint8_t, 1> badPacket{0};
    assert(transfer.receiveResponse(badPacket).status ==
           RemoteTransfer::ResponseStatus::ProtocolError);
    assert(!transfer.synchronized());
}

void testFailedResponseWithPayloadMustReject()
{
    RemoteTransfer transfer;
    const std::array<std::uint32_t, 1> formats{8};
    assert(transfer.receiveFormatList(formats));
    std::vector<std::uint8_t> request;
    assert(transfer.beginRequest(8, request));
    const std::array<std::uint8_t, 1> invalid{42};
    const auto malformed = responsePdu(
        rdp_server::clipboard::kResponseFail, invalid);
    assert(transfer.receiveResponse(malformed).status ==
           RemoteTransfer::ResponseStatus::ProtocolError);
    assert(!transfer.synchronized());
}

// A malformed or replayed CLIPRDR Format Data Response must poison only its
// current channel. An actual disconnect is required before a new generation
// may accept data; length-confused responses must never become clipboard data.
void testMalformedResponseFramingFailsClosed()
{
    const std::array<std::uint32_t, 1> advertisedFormats{13};
    const std::array<std::uint8_t, 3> clipboardData{0x21, 0x34, 0x55};
    const auto validResponse = responsePdu(
        rdp_server::clipboard::kResponseOk, clipboardData);

    const auto checkMalformedResponse = [&](std::span<const std::uint8_t> malformed)
    {
        RemoteTransfer transfer;
        std::vector<std::uint8_t> request;
        assert(transfer.receiveFormatList(advertisedFormats));
        assert(transfer.beginRequest(13, request));
        const auto rejected = transfer.receiveResponse(malformed);
        assert(rejected.status == RemoteTransfer::ResponseStatus::ProtocolError);
        assert(rejected.payload.empty());
        assert(!transfer.synchronized());
        assert(!transfer.beginRequest(13, request));
        assert(request.empty());

        // A channel reset revokes prior offers and outstanding responses.
        transfer.resetAfterDisconnect();
        assert(transfer.synchronized());
        assert(!transfer.hasOutstandingRequest());
        assert(!transfer.advertises(13));
        assert(!transfer.beginRequest(13, request));
        assert(transfer.receiveFormatList(advertisedFormats));
        assert(transfer.beginRequest(13, request));
        const auto accepted = transfer.receiveResponse(validResponse);
        assert(accepted.status == RemoteTransfer::ResponseStatus::Received);
        assert(accepted.generation == 1 && accepted.formatId == 13);
        assert(accepted.payload.size() == clipboardData.size());
        assert(accepted.payload.data() == validResponse.data() + 8);
        assert(accepted.payload[0] == clipboardData[0]);
        assert(accepted.payload[2] == clipboardData[2]);
        assert(!transfer.hasOutstandingRequest());
    };

    // Every strict prefix (including zero, a partial header, and a missing
    // final payload byte) must reject, not wait on a completed-PDU API.
    for (std::size_t prefixLength = 0; prefixLength < validResponse.size();
         ++prefixLength)
    {
        checkMalformedResponse(std::span(validResponse).first(prefixLength));
    }

    auto malformed = validResponse;
    malformed[4] = 2; // Declared payload shorter than the supplied PDU.
    checkMalformedResponse(malformed);
    malformed = validResponse;
    malformed[4] = 4; // Declared payload longer than the supplied PDU.
    checkMalformedResponse(malformed);
    malformed = validResponse;
    malformed[4] = 0xff;
    malformed[5] = 0xff;
    malformed[6] = 0xff;
    malformed[7] = 0xff; // Hostile 32-bit declared payload length.
    checkMalformedResponse(malformed);
    malformed = validResponse;
    malformed[0] = rdp_server::clipboard::kFormatDataRequest;
    checkMalformedResponse(malformed); // Well-framed but wrong message type.
    malformed = validResponse;
    malformed[2] = 0x03; // Mutually exclusive OK and FAIL flags.
    checkMalformedResponse(malformed);
    malformed = validResponse;
    malformed[3] = 0x80; // Unknown high flag bit.
    checkMalformedResponse(malformed);

    RemoteTransfer transfer;
    std::vector<std::uint8_t> request;
    assert(transfer.receiveFormatList(advertisedFormats));
    assert(transfer.beginRequest(13, request));
    assert(transfer.receiveResponse(validResponse).status ==
           RemoteTransfer::ResponseStatus::Received);
    assert(!transfer.hasOutstandingRequest());
    assert(transfer.receiveResponse(validResponse).status ==
           RemoteTransfer::ResponseStatus::ProtocolError);
    assert(!transfer.synchronized()); // An unsolicited replay poisons the channel.
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
    std::span<const std::uint8_t> payload, std::uint16_t flags = 0)
{
    std::vector<std::uint8_t> wire;
    assert(encodePdu(rdp_server::clipboard::kFormatList,
                     flags, payload, wire));
    return wire;
}

void testLongFormatListGeneration()
{
    RemoteTransfer transfer;
    std::vector<std::uint8_t> payload;
    appendLongFormat(payload, 13, "");
    appendLongFormat(payload, 0xc001, "PNG");
    appendLongFormat(payload, 0xc002, "FileGroupDescriptorW");
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(payload)));
    assert(transfer.generation() == 1);
    assert(transfer.namedFormatId("PNG") == 0xc001);
    assert(transfer.namedFormatId("FileGroupDescriptorW") == 0xc002);
    assert(transfer.namedFormatId("unknown") == 0);
    std::vector<std::uint8_t> request;
    assert(transfer.beginRequest(transfer.namedFormatId("PNG"), request));

    // A replacement Format List must not relabel an ambiguous response.
    payload.clear();
    appendLongFormat(payload, 13, "");
    appendLongFormat(payload, 0xc010, "PNG");
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(payload)));
    assert(transfer.namedFormatId("PNG") == 0xc010);
    assert(transfer.namedFormatId("FileGroupDescriptorW") == 0);
    assert(!transfer.beginRequest(0xc010, request));
    const auto oldResponse = responsePdu(
        rdp_server::clipboard::kResponseOk,
        std::array<std::uint8_t, 2>{0xaa, 0xbb});
    assert(transfer.receiveResponse(oldResponse).status ==
           RemoteTransfer::ResponseStatus::DiscardedPreviousGeneration);
    assert(transfer.beginRequest(0xc010, request));
    assert(transfer.receiveResponse(responsePdu(
               rdp_server::clipboard::kResponseFail)).status ==
           RemoteTransfer::ResponseStatus::RemoteFailure);

    // A fresh empty list removes every previous offer and name.
    assert(transfer.receiveLongFormatListPdu(longFormatPdu({})));
    assert(transfer.namedFormatId("PNG") == 0);
    assert(!transfer.beginRequest(13, request));

    const auto expectMalformed = [](std::vector<std::uint8_t> wire) {
        RemoteTransfer candidate;
        assert(!candidate.receiveLongFormatListPdu(wire));
        assert(!candidate.synchronized());
        candidate.resetAfterDisconnect();
        assert(candidate.receiveLongFormatListPdu(longFormatPdu({})));
        assert(candidate.synchronized());
    };
    // PDU flags cannot contain the *capability* bit, CB_ASCII_NAMES,
    // response flags, or other unsupported bits.
    expectMalformed(longFormatPdu(payload, 2));
    expectMalformed(longFormatPdu(payload, 4));
    auto truncated = longFormatPdu(payload);
    truncated.pop_back();
    expectMalformed(truncated);

    std::vector<std::uint8_t> invalid;
    appendLongFormat(invalid, 0xc001, "PNG");
    invalid.pop_back(); // Unterminated / odd UTF-16LE.
    expectMalformed(longFormatPdu(invalid));
    invalid.clear();
    appendLongFormat(invalid, 0xc001, "PNG");
    invalid[4] = 0x00;
    invalid[5] = 0xd8; // Unpaired leading surrogate.
    expectMalformed(longFormatPdu(invalid));
    invalid.clear();
    appendLongFormat(invalid, 0xc001, "PNG");
    appendLongFormat(invalid, 0xc001, "FileGroupDescriptorW");
    expectMalformed(longFormatPdu(invalid)); // Duplicate wire ID.
    invalid.clear();
    appendLongFormat(invalid, 0xc001, "PNG");
    appendLongFormat(invalid, 0xc002, "PNG");
    expectMalformed(longFormatPdu(invalid)); // Ambiguous registered name.
    invalid.clear();
    appendLongFormat(invalid, 0xc001, std::string(257, 'X'));
    expectMalformed(longFormatPdu(invalid)); // Bounded name length.
    invalid.clear();
    for (std::size_t index = 0; index <= RemoteTransfer::kMaximumFormats;
         ++index)
    {
        appendLongFormat(invalid, static_cast<std::uint32_t>(index + 1), "");
    }
    expectMalformed(longFormatPdu(invalid));
}

void appendShortFormat(std::vector<std::uint8_t> &payload,
                       std::uint32_t formatId, std::string_view name,
                       bool asciiNames)
{
    for (unsigned shift = 0; shift < 32; shift += 8)
    {
        payload.push_back(static_cast<std::uint8_t>(formatId >> shift));
    }
    const std::size_t nameStart = payload.size();
    payload.resize(nameStart + 32U, 0);
    // The short-name format may truncate its fixed-size name field.
    const std::size_t characterLimit = asciiNames ? 32U : 16U;
    const std::size_t count = (std::min)(characterLimit, name.size());
    for (std::size_t index = 0; index < count; ++index)
    {
        const std::size_t byteOffset = nameStart +
                                       (asciiNames ? index : index * 2U);
        payload[byteOffset] = static_cast<std::uint8_t>(name[index]);
    }
}

std::vector<std::uint8_t> shortFormatPdu(
    std::span<const std::uint8_t> payload, bool asciiNames,
    std::uint16_t extraFlags = 0)
{
    std::vector<std::uint8_t> wire;
    assert(encodePdu(rdp_server::clipboard::kFormatList,
                     (asciiNames ? 4U : 0U) | extraFlags, payload, wire));
    return wire;
}

void testShortFormatListNegotiation()
{
    RemoteTransfer transfer;
    std::vector<std::uint8_t> payload;
    appendShortFormat(payload, 13, "", true);
    appendShortFormat(payload, 0xc101, "PNG", true);
    appendShortFormat(payload, 0xc102, "FileGroupDescriptorW", true);
    assert(transfer.receiveShortFormatListPdu(shortFormatPdu(payload, true)));
    assert(transfer.generation() == 1);
    assert(transfer.advertises(13));
    assert(transfer.namedFormatId("PNG") == 0xc101);
    assert(transfer.namedFormatId("FileGroupDescriptorW") == 0xc102);

    std::vector<std::uint8_t> request;
    assert(transfer.beginRequest(transfer.namedFormatId("PNG"), request));
    PduView parsedRequest{};
    assert(decodePdu(request, parsedRequest));
    assert(parsedRequest.type == rdp_server::clipboard::kFormatDataRequest);
    const std::array<std::uint8_t, 4> expectedFormat{1, 0xc1, 0, 0};
    assert(parsedRequest.payload.size() == expectedFormat.size());
    assert(std::equal(parsedRequest.payload.begin(), parsedRequest.payload.end(),
                      expectedFormat.begin()));

    // The next generation is short UTF-16LE, not ASCII. A twenty-code-unit
    // file descriptor name cannot be represented in sixteen code units.
    payload.clear();
    appendShortFormat(payload, 13, "", false);
    appendShortFormat(payload, 0xc201, "PNG", false);
    appendShortFormat(payload, 0xc202, "FileGroupDescriptorW", false);
    assert(transfer.receiveShortFormatListPdu(shortFormatPdu(payload, false)));
    assert(transfer.generation() == 2);
    assert(transfer.namedFormatId("PNG") == 0xc201);
    assert(transfer.namedFormatId("FileGroupDescriptorW") == 0);
    assert(transfer.waitingForObsoleteResponse());
    assert(!transfer.beginRequest(0xc201, request));
    const std::array<std::uint8_t, 2> obsolete{0xde, 0xad};
    assert(transfer.receiveResponse(responsePdu(
        rdp_server::clipboard::kResponseOk, obsolete)).status ==
        RemoteTransfer::ResponseStatus::DiscardedPreviousGeneration);
    assert(transfer.beginRequest(0xc201, request));
    assert(transfer.receiveResponse(responsePdu(
        rdp_server::clipboard::kResponseFail)).status ==
        RemoteTransfer::ResponseStatus::RemoteFailure);

    // Empty offers invalidate the previous generation's named formats.
    assert(transfer.receiveShortFormatListPdu(shortFormatPdu({}, true)));
    assert(transfer.namedFormatId("PNG") == 0);
    assert(!transfer.beginRequest(0xc201, request));

    const auto expectMalformed = [](std::vector<std::uint8_t> wire) {
        RemoteTransfer candidate;
        assert(!candidate.receiveShortFormatListPdu(wire));
        assert(!candidate.synchronized());
        candidate.resetAfterDisconnect();
        assert(candidate.receiveShortFormatListPdu(shortFormatPdu({}, false)));
        assert(candidate.synchronized());
    };
    expectMalformed(shortFormatPdu(payload, true, 1));
    expectMalformed(shortFormatPdu(payload, false, 2));
    expectMalformed(shortFormatPdu(std::array<std::uint8_t, 1>{1}, true));
    expectMalformed(shortFormatPdu(std::array<std::uint8_t, 37>{}, true));

    payload.clear();
    appendShortFormat(payload, 0xc101, "PNG", true);
    auto trailingGarbage = payload;
    trailingGarbage[8] = 'X'; // after the first name terminator
    expectMalformed(shortFormatPdu(trailingGarbage, true));
    payload.clear();
    appendShortFormat(payload, 0xc101, "PNG", false);
    trailingGarbage = payload;
    trailingGarbage[12] = 'X'; // nonzero padding after UTF-16 terminator
    expectMalformed(shortFormatPdu(trailingGarbage, false));

    payload.clear();
    appendShortFormat(payload, 0xc101, "PNG", false);
    auto unpairedSurrogate = payload;
    unpairedSurrogate[4] = 0;
    unpairedSurrogate[5] = 0xd8;
    expectMalformed(shortFormatPdu(unpairedSurrogate, false));
    unpairedSurrogate = payload;
    unpairedSurrogate[4] = 0;
    unpairedSurrogate[5] = 0xdc; // lone low surrogate
    expectMalformed(shortFormatPdu(unpairedSurrogate, false));

    payload.clear();
    appendShortFormat(payload, 0xc101, "PNG", true);
    appendShortFormat(payload, 0xc101, "Different", true);
    expectMalformed(shortFormatPdu(payload, true));
    payload.clear();
    appendShortFormat(payload, 0xc101, "PNG", true);
    appendShortFormat(payload, 0xc102, "PNG", true);
    expectMalformed(shortFormatPdu(payload, true));
    payload.clear();
    appendShortFormat(payload, 0, "PNG", true);
    expectMalformed(shortFormatPdu(payload, true));

    payload.clear();
    for (std::size_t index = 0; index <= RemoteTransfer::kMaximumFormats;
         ++index)
    {
        appendShortFormat(payload, static_cast<std::uint32_t>(index + 1),
                          "", true);
    }
    expectMalformed(shortFormatPdu(payload, true));
    // Proper surrogate pairs in unrelated registered names are valid.
    payload.clear();
    appendShortFormat(payload, 0xc203, "", false);
    payload[4] = 0x3d; payload[5] = 0xd8; // U+1F600 high surrogate
    payload[6] = 0x00; payload[7] = 0xde; // low surrogate
    RemoteTransfer surrogateName;
    assert(surrogateName.receiveShortFormatListPdu(shortFormatPdu(payload, false)));
    assert(surrogateName.advertises(0xc203));

    payload.clear();
    appendShortFormat(payload, 0xc101, std::string(32, 'X'), true);
    RemoteTransfer fullWidthName;
    assert(fullWidthName.receiveShortFormatListPdu(shortFormatPdu(payload, true)));
    assert(fullWidthName.namedFormatId("PNG") == 0);
    payload.clear();
    appendShortFormat(payload, 0xc201, std::string(16, 'X'), false);
    assert(fullWidthName.receiveShortFormatListPdu(shortFormatPdu(payload, false)));
    assert(fullWidthName.generation() == 2);
}
void testFormatListResponseNativeAcceptance()
{
    using namespace rdp_server::clipboard;
    RemoteTransfer transfer;
    std::array<std::uint8_t, 8> acknowledgment{};
    const std::array<std::uint8_t, 8> successWire{
        0x03, 0x00, 0x01, 0x00, 0, 0, 0, 0};
    const std::array<std::uint8_t, 8> failureWire{
        0x03, 0x00, 0x02, 0x00, 0, 0, 0, 0};

    // Complete, externally admitted long-name announcement. The name's
    // registered wire ID is not assumed globally stable.
    std::vector<std::uint8_t> payload;
    appendLongFormat(payload, 13, "");
    appendLongFormat(payload, 0xc001, "PNG");
    const auto longOffer = longFormatPdu(payload);
    assert(transfer.receiveFormatListWithResponse(
        longOffer, true, true, acknowledgment));
    assert(acknowledgment == successWire);
    assert(transfer.generation() == 1);
    assert(transfer.namedFormatId("PNG") == 0xc001);

    std::vector<std::uint8_t> request;
    assert(transfer.beginRequest(0xc001, request));
    const auto oldResponse = responsePdu(kResponseOk,
        std::array<std::uint8_t, 2>{0x89, 0x50});

    // The native adapter refuses the next valid offer: emit FAIL, advance
    // generation exactly once, clear names/IDs and quarantine old data.
    payload.clear();
    appendShortFormat(payload, 0xc002, "PNG", true);
    const auto deniedOffer = shortFormatPdu(payload, true);
    assert(!transfer.receiveFormatListWithResponse(
        deniedOffer, false, false, acknowledgment));
    assert(acknowledgment == failureWire);
    assert(transfer.synchronized());
    assert(transfer.generation() == 2);
    assert(!transfer.advertises(0xc002));
    assert(transfer.namedFormatId("PNG") == 0);
    assert(transfer.waitingForObsoleteResponse());
    assert(!transfer.beginRequest(0xc002, request));
    assert(request.empty());
    assert(transfer.receiveResponse(oldResponse).status ==
           RemoteTransfer::ResponseStatus::DiscardedPreviousGeneration);

    // A new accepted offer remains possible after native rejection.
    assert(transfer.receiveFormatListWithResponse(
        deniedOffer, false, true, acknowledgment));
    assert(acknowledgment == successWire);
    assert(transfer.generation() == 3);
    assert(transfer.namedFormatId("PNG") == 0xc002);
    assert(transfer.beginRequest(0xc002, request));
    assert(transfer.receiveResponse(responsePdu(kResponseFail)).status ==
           RemoteTransfer::ResponseStatus::RemoteFailure);

    // Empty clipboard is a successful replacement, not a parser error.
    assert(transfer.receiveFormatListWithResponse(
        shortFormatPdu({}, false), false, true, acknowledgment));
    assert(acknowledgment == successWire);
    assert(!transfer.advertises(13));
    assert(transfer.namedFormatId("PNG") == 0);

    // Malformed bytes, flags, wrong negotiation mode, and oversized lists
    // cannot generate CB_RESPONSE_OK or leave accessible old offers.
    auto invalid = deniedOffer;
    invalid.pop_back();
    assert(!transfer.receiveFormatListWithResponse(
        invalid, false, true, acknowledgment));
    assert(acknowledgment == failureWire);
    assert(!transfer.synchronized());
    assert(!transfer.receiveFormatListWithResponse(
        deniedOffer, false, true, acknowledgment));
    assert(acknowledgment == failureWire);

    transfer.resetAfterDisconnect();
    assert(!transfer.receiveFormatListWithResponse(
        deniedOffer, true, true, acknowledgment)); // short in long mode
    assert(acknowledgment == failureWire);
    transfer.resetAfterDisconnect();
    assert(!transfer.receiveFormatListWithResponse(
        longOffer, false, true, acknowledgment)); // long in short mode
    assert(acknowledgment == failureWire);

    transfer.resetAfterDisconnect();
    auto badFlags = shortFormatPdu(payload, true, kResponseOk);
    assert(!transfer.receiveFormatListWithResponse(
        badFlags, false, true, acknowledgment));
    assert(acknowledgment == failureWire);
    transfer.resetAfterDisconnect();
    payload.clear();
    for (std::size_t index = 0; index <= RemoteTransfer::kMaximumFormats;
         ++index)
    {
        appendShortFormat(payload, static_cast<std::uint32_t>(index + 1),
                          "", true);
    }
    assert(!transfer.receiveFormatListWithResponse(
        shortFormatPdu(payload, true), false, true, acknowledgment));
    assert(acknowledgment == failureWire);
}
// MS-RDPECLIP 2.2.2.1: capabilities are optional, bounded, and
// informational version must never override the negotiated feature flags.
void testCapabilitiesNegotiationAndFormatListGating()
{
    using namespace rdp_server::clipboard;
    const auto makeCapabilities = [](std::span<const std::uint8_t> payload,
                                     std::uint16_t flags = 0) {
        std::vector<std::uint8_t> result;
        assert(encodePdu(kClipCaps, flags, payload, result));
        return result;
    };
    // Published Microsoft example (section 4.1.3): version 2 and flags 0x0e.
    const std::array<std::uint8_t, 16> example{
        1, 0, 0, 0, 1, 0, 12, 0, 2, 0, 0, 0, 0x0e, 0, 0, 0};
    const auto exampleWire = makeCapabilities(example);
    RemoteTransfer transfer;
    std::array<std::uint8_t, 8> acknowledgment{};
    assert(transfer.negotiatedGeneralFlags() == 0);
    assert(transfer.receiveCapabilitiesPdu(exampleWire, 0x02));
    assert(transfer.negotiatedGeneralFlags() == 0x02);
    std::vector<std::uint8_t> longPayload;
    appendLongFormat(longPayload, 0xc001, "PNG");
    assert(transfer.receiveNegotiatedFormatListWithResponse(
        longFormatPdu(longPayload), true, acknowledgment));
    assert(acknowledgment[2] == 1);
    assert(transfer.namedFormatId("PNG") == 0xc001);
    assert(!transfer.receiveCapabilitiesPdu(exampleWire, 0x02));
    assert(!transfer.synchronized());
    transfer.resetAfterDisconnect();
    assert(transfer.negotiatedGeneralFlags() == 0);
    assert(!transfer.advertises(0xc001));

    // No capabilities means the mandatory short-format fallback.
    std::vector<std::uint8_t> shortPayload;
    appendShortFormat(shortPayload, 0xc002, "PNG", true);
    const auto shortWire = shortFormatPdu(shortPayload, true);
    assert(transfer.receiveNegotiatedFormatListWithResponse(
        shortWire, true, acknowledgment));
    assert(transfer.namedFormatId("PNG") == 0xc002);
    transfer.resetAfterDisconnect();
    assert(transfer.receiveCapabilitiesPdu(exampleWire, 0));
    assert(transfer.negotiatedGeneralFlags() == 0);
    assert(transfer.receiveNegotiatedFormatListWithResponse(
        shortWire, true, acknowledgment));
    transfer.resetAfterDisconnect();
    const std::array<std::uint8_t, 4> emptyPayload{0, 0, 0xff, 0xff};
    assert(transfer.receiveCapabilitiesPdu(makeCapabilities(emptyPayload), 0x3e));
    assert(transfer.negotiatedGeneralFlags() == 0);
    transfer.resetAfterDisconnect();

    // Unknown bounded sets are safely skipped; future version is informational.
    std::vector<std::uint8_t> extended(example.begin(), example.end());
    extended[0] = 2;
    extended[8] = 0x7f;
    extended[12] = 0xce; // Unknown flags, but only 0x0e is jointly supported.
    extended.insert(extended.end(), {0xaa, 0, 6, 0, 0x12, 0x34});
    assert(transfer.receiveCapabilitiesPdu(makeCapabilities(extended), 0x3e));
    assert(transfer.negotiatedGeneralFlags() == 0x0e);
    transfer.resetAfterDisconnect();

    const auto reject = [&](std::vector<std::uint8_t> candidate) {
        RemoteTransfer invalid;
        assert(!invalid.receiveCapabilitiesPdu(candidate, 0x3e));
        assert(!invalid.synchronized());
        assert(invalid.negotiatedGeneralFlags() == 0);
        assert(!invalid.receiveNegotiatedFormatListWithResponse(
            shortWire, true, acknowledgment));
        invalid.resetAfterDisconnect();
        assert(invalid.receiveCapabilitiesPdu(exampleWire, 0x02));
        assert(invalid.negotiatedGeneralFlags() == 0x02);
    };
    reject(makeCapabilities(example, 1)); // Header flags.
    auto truncated = exampleWire;
    truncated.pop_back();
    reject(truncated);
    auto malformed = example;
    malformed[0] = 0xff; malformed[1] = 0xff; // Excessive set count.
    reject(makeCapabilities(malformed));
    malformed = example;
    malformed[6] = 0; malformed[7] = 0; // Zero-length set.
    reject(makeCapabilities(malformed));
    malformed = example;
    malformed[6] = 11; // Incorrect General length.
    reject(makeCapabilities(malformed));
    malformed = example;
    malformed[6] = 13; // Length exceeds remaining input.
    reject(makeCapabilities(malformed));
    malformed = example;
    malformed[0] = 2; // Second set missing.
    reject(makeCapabilities(malformed));
    std::vector<std::uint8_t> duplicate(example.begin(), example.end());
    duplicate[0] = 2;
    duplicate.insert(duplicate.end(), example.begin() + 4, example.end());
    reject(makeCapabilities(duplicate)); // Duplicate General capability.
    duplicate.assign(example.begin(), example.end());
    duplicate.push_back(0); // Unadvertised tail.
    reject(makeCapabilities(duplicate));
    reject(makeCapabilities({})); // Missing count and padding.
}


// Cross-road OFFLINE fixture: the joined-channel gate is a necessary
// membership prerequisite, NOT R2 TLS/OS authorization or an R3 router.
// Only a complete parsed MCS request from the confirmed channel can be
// passed to the existing first-party CLIPRDR response coordinator.
void testMcsJoinedClipboardResponseTeardown()
{
    using namespace rdp_server::server::transport;
    const std::array<std::uint16_t, 1> allocatedChannels{1003};
    constexpr std::array<std::uint8_t, 12> joinWire{
        0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80,
        0x38, 0x00, 0x06, 0x03, 0xeb};
    const auto join = parseMcsChannelRequest(joinWire);
    assert(join && join.request.kind == McsChannelRequestKind::ChannelJoin);

    McsChannelJoinWriteGate gate;
    assert(gate.configure(1007, allocatedChannels));
    assert(gate.beginJoin(join.request) == McsJoinStartOutcome::ReplyPending);
    assert(!gate.channelJoinConfirmed(1003));

    const std::array<std::uint32_t, 1> offers{13};
    RemoteTransfer transfer;
    std::vector<std::uint8_t> outboundRequest;
    // Pre-seed an outstanding transfer to prove denial is due to MCS
    // membership, not because R8 happens to lack an outstanding request.
    assert(transfer.receiveFormatList(offers));
    assert(transfer.beginRequest(13, outboundRequest));
    const std::array<std::uint8_t, 3> payload{0x12, 0x34, 0x56};
    const auto cliprdrResponse = responsePdu(
        rdp_server::clipboard::kResponseOk, payload);

    // Microsoft MS-RDPBCGR/T.125 SendDataRequest, client 1007 and
    // channel 1003. The CLIPRDR PDU is a synthetic complete userData.
    // The 7-bit length is sufficient for this bounded response.
    assert(cliprdrResponse.size() < 128);
    std::vector<std::uint8_t> frame{
        0x03, 0x00, 0x00, 0x00, 0x02, 0xf0, 0x80,
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70,
        static_cast<std::uint8_t>(cliprdrResponse.size())};
    frame.insert(frame.end(), cliprdrResponse.begin(), cliprdrResponse.end());
    assert(frame.size() <= 255);
    frame[3] = static_cast<std::uint8_t>(frame.size());

    const auto parsed = parseMcsChannelRequest(frame);
    assert(parsed && parsed.request.kind == McsChannelRequestKind::SendDataRequest);
    assert(parsed.request.userData.size() == cliprdrResponse.size());
    assert(parsed.request.userData.data() == frame.data() + 14);
    assert(!gate.matchesJoinedInboundSendData(parsed.request));

    std::size_t deliveredCount = 0;
    // Test-only caller discipline, not a new state owner or a production
    // authorization implementation. R2 admission/stage checks remain required.
    const auto deliverIfJoined = [&](std::span<const std::uint8_t> completeTpkt)
    {
        const auto candidate = parseMcsChannelRequest(completeTpkt);
        if (!candidate || !gate.matchesJoinedInboundSendData(candidate.request))
            return false;
        const auto reply = transfer.receiveResponse(candidate.request.userData);
        if (reply.status != RemoteTransfer::ResponseStatus::Received)
            return false;
        assert(reply.generation == 1 && reply.formatId == 13);
        assert(reply.payload.size() == payload.size());
        assert(std::equal(reply.payload.begin(), reply.payload.end(),
                          payload.begin()));
        ++deliveredCount;
        return true;
    };

    // No clipboard state changes while join confirmation is pending.
    assert(!deliverIfJoined(frame));
    assert(transfer.hasOutstandingRequest());
    const auto confirmation = gate.pendingBytes();
    assert(!confirmation.empty());
    const auto receipt = gate.pendingReplySequence();
    const auto firstSlice = gate.pendingWriteSliceSequence();
    assert(gate.onReplyBytesWritten(receipt, firstSlice, 1) ==
           McsJoinWriteOutcome::Pending);
    assert(!deliverIfJoined(frame)); // Partial writer progress is not joined.
    const auto suffix = gate.pendingBytes();
    assert(suffix.size() == confirmation.size() - 1);
    assert(gate.onReplyBytesWritten(
               receipt, gate.pendingWriteSliceSequence(), suffix.size()) ==
           McsJoinWriteOutcome::Confirmed);
    assert(gate.channelJoinConfirmed(1003));

    // Validly parsed data on another channel or from another user still
    // cannot be delivered to the R8 request, even after one join succeeds.
    auto wrongChannel = frame;
    wrongChannel[11] = 0xec; // Channel 1004, not joined.
    assert(parseMcsChannelRequest(wrongChannel));
    assert(!deliverIfJoined(wrongChannel));
    auto wrongUser = frame;
    wrongUser[9] = 0x07; // User 1008, not the attached 1007.
    assert(parseMcsChannelRequest(wrongUser));
    assert(!deliverIfJoined(wrongUser));
    auto truncated = frame;
    truncated.pop_back(); // TPKT/PER declared lengths are now inconsistent.
    assert(!parseMcsChannelRequest(truncated));
    assert(!deliverIfJoined(truncated));
    assert(transfer.hasOutstandingRequest());
    assert(deliveredCount == 0);

    assert(deliverIfJoined(frame));
    assert(deliveredCount == 1);
    assert(!transfer.hasOutstandingRequest());

    // The actual session owner must close BOTH single-session components.
    // A queued pre-disconnect frame must not resurrect clipboard data.
    assert(transfer.beginRequest(13, outboundRequest));
    gate.close();
    transfer.resetAfterDisconnect();
    assert(!gate.channelJoinConfirmed(1003));
    assert(gate.pendingBytes().empty());
    assert(!deliverIfJoined(frame));
    assert(!transfer.hasOutstandingRequest());
    assert(!transfer.advertises(13));
    assert(deliveredCount == 1);

    // A fresh session has independent membership state: even identical
    // on-wire user/channel IDs never imply a completed fresh join.
    McsChannelJoinWriteGate nextSession;
    assert(nextSession.configure(1007, allocatedChannels));
    assert(!nextSession.matchesJoinedInboundSendData(parsed.request));
}

// Offline R3/R8 static-channel send bridge. A joined MCS channel is
// necessary but still not proof of NLA identity or OS session authorization.
void testFormatListResponseJoinedMcsEnvelope()
{
    using namespace rdp_server::server::transport;
    using namespace rdp_server::clipboard;
    RemoteTransfer transfer;
    McsChannelJoinWriteGate joinedChannels;
    const std::array<std::uint16_t, 2> assigned{1007, 1003};
    assert(joinedChannels.configure(1007, assigned));
    std::array<std::uint8_t, 8> response{};
    assert(transfer.receiveNegotiatedFormatListWithResponse(
        shortFormatPdu({}, false), true, response));
    const std::array<std::uint8_t, 8> success{
        0x03, 0, 0x01, 0, 0, 0, 0, 0};
    const std::array<std::uint8_t, 8> failure{
        0x03, 0, 0x02, 0, 0, 0, 0, 0};
    assert(response == success);

    std::array<std::uint8_t, 64> packet{};
    packet.fill(0xa5);
    const auto encode = [&](std::uint16_t channelId,
                            std::span<const std::uint8_t> pdu,
                            std::span<std::uint8_t> output)
        {
            return transfer.encodeJoinedFormatListResponse(
                joinedChannels, channelId, pdu, output);
        };
    assert(!encode(1003, failure, packet)); // Not generated by this owner.
    assert(!encode(1003, response, packet)); // Not joined yet.
    assert(!encode(999, response, packet)); // Unknown allocated channel.
    assert(std::all_of(packet.begin(), packet.end(),
                       [](std::uint8_t byte) { return byte == 0xa5; }));

    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(joinedChannels.beginJoin(join) ==
           McsJoinStartOutcome::ReplyPending);
    assert(!encode(1003, response, packet)); // Confirmation not yet written.
    const auto written = joinedChannels.onReplyBytesWritten(
        joinedChannels.pendingReplySequence(),
        joinedChannels.pendingWriteSliceSequence(), 15);
    assert(written == McsJoinWriteOutcome::Confirmed);

    const std::array<std::uint8_t, 30> golden{
        0x03, 0x00, 0x00, 0x1e, 0x02, 0xf0, 0x80, 0x68,
        0x00, 0x06, 0x03, 0xeb, 0x70, 0x10,
        0x08, 0, 0, 0, 0x03, 0, 0, 0,
        0x03, 0, 0x01, 0, 0, 0, 0, 0};
    const auto size = encode(1003, response, packet);
    assert(size && *size == golden.size());
    assert(std::equal(golden.begin(), golden.end(), packet.begin()));
    assert(std::all_of(packet.begin() + golden.size(), packet.end(),
                       [](std::uint8_t byte) { return byte == 0xa5; }));

    // Fail-closed validation must leave the caller's output unchanged.
    const auto mustReject = [&](std::span<const std::uint8_t> pdu) {
        packet.fill(0xa5);
        assert(!encode(1003, pdu, packet));
        assert(std::all_of(packet.begin(), packet.end(),
                           [](std::uint8_t byte) { return byte == 0xa5; }));
    };
    mustReject(std::span(response).first(7));
    auto invalid = response;
    invalid[0] = kFormatDataResponse; // Wrong clipboard message type.
    mustReject(invalid);
    invalid = response;
    invalid[2] = 3; // Mutually exclusive response flags.
    mustReject(invalid);
    invalid = response;
    invalid[3] = 0x80;
    mustReject(invalid);
    invalid = response;
    invalid[4] = 1; // No Format List Response payload allowed.
    mustReject(invalid);
    std::array<std::uint8_t, 9> extra{};
    std::copy(response.begin(), response.end(), extra.begin());
    mustReject(extra);

    packet.fill(0xa5);
    assert(!encode(1003, response, std::span(packet).first(29)));
    assert(std::all_of(packet.begin(), packet.end(),
                       [](std::uint8_t byte) { return byte == 0xa5; }));

    // A valid, native-rejected clipboard offer must still produce a
    // CB_RESPONSE_FAIL wrapped on this same confirmed static VC.
    assert(!transfer.receiveNegotiatedFormatListWithResponse(
        shortFormatPdu({}, false), false, response));
    assert(response == failure);
    packet.fill(0xa5);
    const auto failedSize = encode(1003, response, packet);
    assert(failedSize && *failedSize == golden.size());
    assert(packet[24] == kResponseFail && packet[25] == 0);
    transfer.resetAfterDisconnect();
    packet.fill(0xa5);
    assert(!encode(1003, response, packet)); // Stale across reconnect.
    joinedChannels.close();
    packet.fill(0xa5);
    assert(!encode(1003, response, packet));
    assert(std::all_of(packet.begin(), packet.end(),
                       [](std::uint8_t byte) { return byte == 0xa5; }));
}

// R9 bounded mutation corpus over a COMPLETE TPKT/X.224/T.125 PDU
// carrying a first-party CLIPRDR response. These are parser and joined
// membership prerequisites, NOT TLS identity or OS authorization.
void testMcsCliprdrLengthMutationDenials()
{
    using namespace rdp_server::server::transport;
    McsChannelJoinWriteGate channels;
    const std::array<std::uint16_t, 1> joinedIds{1003};
    assert(channels.configure(1007, joinedIds));

    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(channels.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    const auto confirmationLength = channels.pendingBytes().size();
    assert(confirmationLength != 0);
    assert(channels.onReplyBytesWritten(
               channels.pendingReplySequence(),
               channels.pendingWriteSliceSequence(), confirmationLength) ==
           McsJoinWriteOutcome::Confirmed);
    assert(channels.channelJoinConfirmed(1003));

    const std::array<std::uint8_t, 3> opaqueBytes{0x12, 0x34, 0x56};
    const auto clipboardPdu = responsePdu(
        rdp_server::clipboard::kResponseOk, opaqueBytes);
    assert(clipboardPdu.size() == 11);

    // Full single-PDU MCS framing; the CLIPRDR bytes start at offset 14.
    // Only the declared lengths are mutated below; neither parser should
    // observe a fragment as a complete frame.
    std::vector<std::uint8_t> frame{
        0x03, 0x00, 0x00, 0x00, 0x02, 0xf0, 0x80,
        0x64, 0x00, 0x06, 0x03, 0xeb, 0x70,
        static_cast<std::uint8_t>(clipboardPdu.size())};
    frame.insert(frame.end(), clipboardPdu.begin(), clipboardPdu.end());
    assert(frame.size() == 25);
    frame[3] = static_cast<std::uint8_t>(frame.size());

    const auto seed = parseMcsChannelRequest(frame);
    assert(seed && seed.request.kind == McsChannelRequestKind::SendDataRequest);
    assert(channels.matchesJoinedInboundSendData(seed.request));
    assert(seed.request.userData.data() == frame.data() + 14);
    assert(seed.request.userData.size() == clipboardPdu.size());

    // Every strict prefix and every incorrect one-byte TPKT length fails
    // at the outer parser, before R8 could observe any clipboard bytes.
    for (std::size_t length = 0; length < frame.size(); ++length)
    {
        assert(!parseMcsChannelRequest(
            std::span<const std::uint8_t>{frame.data(), length}));
    }
    for (unsigned declared = 0; declared <= 255U; ++declared)
    {
        if (declared == frame.size())
            continue;
        auto invalid = frame;
        invalid[3] = static_cast<std::uint8_t>(declared);
        assert(!parseMcsChannelRequest(invalid));
    }

    // The T.125 PER user-data length must agree with the complete frame
    // for both short and long determinant encodings.
    for (unsigned declared = 0; declared <= 255U; ++declared)
    {
        if (declared == clipboardPdu.size())
            continue;
        auto invalid = frame;
        invalid[13] = static_cast<std::uint8_t>(declared);
        assert(!parseMcsChannelRequest(invalid));
    }

    const auto membershipDenied = [&](std::vector<std::uint8_t> invalid) {
        const auto parsed = parseMcsChannelRequest(invalid);
        assert(!parsed || !channels.matchesJoinedInboundSendData(parsed.request));
    };
    auto invalid = frame;
    invalid[9] = 0x07;  // Client UserId 1008 instead of 1007.
    membershipDenied(invalid);
    invalid = frame;
    invalid[11] = 0xec; // Unjoined channel 1004.
    membershipDenied(invalid);
    invalid = frame;
    invalid[12] |= 0x01; // Nonzero T.125 choice padding.
    assert(!parseMcsChannelRequest(invalid));

    // A correct MCS envelope does NOT make the nested clipboard length
    // trustworthy. Each malformed CB_FORMAT_DATA_RESPONSE poisons a fresh
    // R8 coordinator without returning borrowed payload bytes.
    const std::array<std::uint32_t, 1> advertised{13};
    for (unsigned declared = 0; declared <= 255U; ++declared)
    {
        if (declared == opaqueBytes.size())
            continue;
        auto nested = frame;
        nested[18] = static_cast<std::uint8_t>(declared); // CLIPRDR dataLen[0].
        const auto parsed = parseMcsChannelRequest(nested);
        assert(parsed && channels.matchesJoinedInboundSendData(parsed.request));

        RemoteTransfer transfer;
        std::vector<std::uint8_t> request;
        assert(transfer.receiveFormatList(advertised));
        assert(transfer.beginRequest(13, request));
        const auto rejected = transfer.receiveResponse(parsed.request.userData);
        assert(rejected.status == RemoteTransfer::ResponseStatus::ProtocolError);
        assert(rejected.payload.empty());
        assert(!transfer.synchronized());
        assert(!transfer.beginRequest(13, request));
        assert(request.empty());

        // Only an actual disconnect reset clears the poisoned generation;
        // a response cannot be associated with a new request implicitly.
        transfer.resetAfterDisconnect();
        assert(!transfer.advertises(13));
        assert(!transfer.beginRequest(13, request));
        assert(transfer.receiveFormatList(advertised));
        assert(transfer.beginRequest(13, request));
        assert(transfer.receiveResponse(clipboardPdu).status ==
               RemoteTransfer::ResponseStatus::Received);
    }

    // All opaque one-byte content values are allowed; length checking
    // must not accidentally reject valid clipboard data.
    for (unsigned value = 0; value <= 255U; ++value)
    {
        auto valid = frame;
        valid.back() = static_cast<std::uint8_t>(value);
        const auto parsed = parseMcsChannelRequest(valid);
        assert(parsed && channels.matchesJoinedInboundSendData(parsed.request));
        RemoteTransfer transfer;
        std::vector<std::uint8_t> request;
        assert(transfer.receiveFormatList(advertised));
        assert(transfer.beginRequest(13, request));
        const auto result = transfer.receiveResponse(parsed.request.userData);
        assert(result.status == RemoteTransfer::ResponseStatus::Received);
        assert(result.payload.size() == opaqueBytes.size());
        assert(result.payload.data() == valid.data() + 14 + 8);
        assert(result.payload.back() == static_cast<std::uint8_t>(value));
    }

    channels.close();
    assert(!channels.matchesJoinedInboundSendData(seed.request));
}

// A T.125 SendDataRequest is not itself a clipboard PDU. Route only
// verified joined CLIPRDR traffic with one full uncompressed static VC header.
void testJoinedStaticChannelInboundGates()
{
    using namespace rdp_server::server::transport;
    using namespace rdp_server::clipboard;
    using Status = RemoteTransfer::JoinedReceiveStatus;

    const auto packet = [](std::span<const std::uint8_t> clipboard,
                           std::uint32_t channelFlags = 3U)
    {
        assert(clipboard.size() + 8U < 128U);
        std::vector<std::uint8_t> frame{
            3, 0, 0, 0, 2, 0xf0, 0x80,
            0x64, 0, 6, 3, 0xeb, 0x70,
            static_cast<std::uint8_t>(clipboard.size() + 8U),
            static_cast<std::uint8_t>(clipboard.size()), 0, 0, 0,
            static_cast<std::uint8_t>(channelFlags),
            static_cast<std::uint8_t>(channelFlags >> 8U),
            static_cast<std::uint8_t>(channelFlags >> 16U),
            static_cast<std::uint8_t>(channelFlags >> 24U),
        };
        frame.insert(frame.end(), clipboard.begin(), clipboard.end());
        frame[3] = static_cast<std::uint8_t>(frame.size());
        return frame;
    };
    const auto wrapPdu = [&](std::uint16_t type,
                             std::span<const std::uint8_t> payload = {})
    {
        std::vector<std::uint8_t> pdu;
        assert(encodePdu(type, 0, payload, pdu));
        return packet(pdu);
    };

    McsChannelJoinWriteGate gate;
    const std::array<std::uint16_t, 1> channels{1003};
    assert(gate.configure(1007, channels));
    RemoteTransfer transfer;
    // Client General capability: version 2, long names enabled.
    const std::array<std::uint8_t, 16> caps{
        1, 0, 0, 0, 1, 0, 12, 0, 2, 0, 0, 0, 2, 0, 0, 0};
    auto capFrame = wrapPdu(kClipCaps, caps);
    auto parsed = parseMcsChannelRequest(capFrame);
    assert(parsed);
    const auto receive = [&](const McsChannelRequest &request,
                             bool admitted = true,
                             std::uint16_t expectedChannel = 1003,
                             bool nativeAccepted = true)
    {
        return transfer.receiveJoinedStaticChannelPdu(
            gate, request, expectedChannel, admitted, 2, nativeAccepted);
    };
    // Before both external admission and completed join, no state is touched.
    assert(receive(parsed.request, false).status == Status::Denied);
    assert(receive(parsed.request).status == Status::Denied);
    assert(transfer.negotiatedGeneralFlags() == 0);
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(gate.onReplyBytesWritten(
        gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 15) ==
        McsJoinWriteOutcome::Confirmed);
    assert(receive(parsed.request, false).status == Status::Denied);
    assert(receive(parsed.request, true, 1004).status == Status::Denied);
    auto wrongUser = parsed.request;
    wrongUser.initiator = 1008;
    assert(receive(wrongUser).status == Status::Denied);
    auto segmented = parsed.request;
    segmented.segmentation = 1;
    assert(receive(segmented).status == Status::Denied);
    assert(transfer.synchronized());
    assert(receive(parsed.request).status == Status::CapabilitiesAccepted);
    assert(transfer.negotiatedGeneralFlags() == 2);

    std::vector<std::uint8_t> offer;
    appendLongFormat(offer, 13, "");
    appendLongFormat(offer, 0xc001, "PNG");
    auto offerFrame = wrapPdu(kFormatList, offer);
    auto offered = parseMcsChannelRequest(offerFrame);
    assert(offered);
    const auto accepted = receive(offered.request);
    assert(accepted.status == Status::FormatListAccepted);
    assert(accepted.acknowledgmentReady);
    assert(accepted.acknowledgment[2] == kResponseOk);
    assert(transfer.namedFormatId("PNG") == 0xc001);

    std::vector<std::uint8_t> requestBytes;
    assert(transfer.beginRequest(0xc001, requestBytes));
    const std::array<std::uint8_t, 3> png{0x89, 0x50, 0x4e};
    auto replyPdu = responsePdu(kResponseOk, png);
    auto responseFrame = packet(replyPdu, 0x13U); // SHOW_PROTOCOL is allowed.
    auto responseRequest = parseMcsChannelRequest(responseFrame);
    assert(responseRequest);
    const auto result = receive(responseRequest.request);
    assert(result.status == Status::DataReceived);
    assert(result.data.generation == 1 && result.data.formatId == 0xc001);
    assert(result.data.payload.size() == png.size());
    assert(result.data.payload.data() == responseFrame.data() + 30U);
    assert(std::equal(png.begin(), png.end(), result.data.payload.begin()));

    // Unsupported clipboard messages are ignored, never interpreted as data.
    auto unrecognized = wrapPdu(kMonitorReady);
    assert(receive(parseMcsChannelRequest(unrecognized).request).status ==
           Status::Ignored);

    // An adapter rejection is still a valid new generation and must
    // carry FAIL; format IDs are no longer eligible for requests.
    const auto rejected = receive(offered.request, true, 1003, false);
    assert(rejected.status == Status::FormatListDeclined);
    assert(rejected.acknowledgmentReady);
    assert(rejected.acknowledgment[2] == kResponseFail);
    assert(!transfer.advertises(0xc001));

    const auto malformed = [&](std::vector<std::uint8_t> frame)
    {
        RemoteTransfer candidate;
        const auto candidateRequest = parseMcsChannelRequest(frame);
        assert(candidateRequest);
        const auto invalid = candidate.receiveJoinedStaticChannelPdu(
            gate, candidateRequest.request, 1003, true, 2, true);
        assert(invalid.status == Status::ProtocolError);
        assert(!candidate.synchronized());
        candidate.resetAfterDisconnect();
        assert(candidate.synchronized());
    };
    auto badLength = capFrame;
    badLength[14] += 1; // VC totalLength differs from chunk length.
    malformed(badLength);
    auto badFlags = capFrame;
    badFlags[18] = 1; // FIRST only: incomplete chunk unsupported.
    malformed(badFlags);
    badFlags = capFrame;
    badFlags[18] = 0x03;
    badFlags[20] = 0x20; // CHANNEL_PACKET_COMPRESSED: no inflater.
    malformed(badFlags);
    auto raw = capFrame;
    raw.erase(raw.begin() + 14, raw.begin() + 22);
    raw[13] -= 8;
    raw[3] -= 8;
    malformed(raw); // Missing required CHANNEL_PDU_HEADER.

    // An old in-flight data response cannot become a new offer's bytes.
    transfer.resetAfterDisconnect();
    assert(transfer.receiveFormatList(std::array<std::uint32_t, 1>{13}));
    assert(transfer.beginRequest(13, requestBytes));
    assert(transfer.receiveFormatList(std::array<std::uint32_t, 1>{8}));
    assert(receive(responseRequest.request).status ==
           Status::ObsoleteDataDiscarded);
    assert(!transfer.hasOutstandingRequest());
    gate.close();
    assert(receive(parsed.request).status == Status::Denied);
}

// R8 M5 bounded eager retrieval: selection uses only current-format IDs,
// and the existing single outstanding CLIPRDR Format Data Request slot.
void testPrefetchUnicodePngDibFallbackSingleFlight()
{
    using namespace rdp_server::clipboard;
    using Kind = RemoteTransfer::PrefetchKind;
    using Result = RemoteTransfer::ResponseStatus;
    RemoteTransfer transfer;
    std::uint32_t selectedId = 77;
    std::vector<std::uint8_t> request{0xff};
    assert(!transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 0 && request.empty());

    std::vector<std::uint8_t> formats;
    appendLongFormat(formats, kFormatUnicodeText, "");
    appendLongFormat(formats, 0xc001, "PNG");
    appendLongFormat(formats, 17, "");
    appendLongFormat(formats, 8, "");
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(formats)));
    assert(transfer.beginNextPrefetch(Kind::UnicodeText, selectedId, request));
    assert(selectedId == kFormatUnicodeText);
    PduView parsed{};
    assert(decodePdu(request, parsed));
    const std::array<std::uint8_t, 4> textId{13, 0, 0, 0};
    assert(parsed.type == kFormatDataRequest && parsed.flags == 0);
    assert(std::equal(parsed.payload.begin(), parsed.payload.end(),
                      textId.begin(), textId.end()));

    // A pending text request blocks all image requests and explicit paste
    // requests. Failed speculative calls may not corrupt the wire request.
    assert(!transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 0 && request.empty());
    assert(!transfer.beginRequest(0xc001, request));
    const auto fail = responsePdu(kResponseFail);
    assert(transfer.receiveResponse(fail).status == Result::RemoteFailure);
    assert(!transfer.beginNextPrefetch(Kind::UnicodeText, selectedId, request));
    assert(selectedId == 0 && request.empty());

    assert(transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 0xc001);
    assert(decodePdu(request, parsed));
    const std::array<std::uint8_t, 4> pngId{1, 0xc0, 0, 0};
    assert(std::equal(parsed.payload.begin(), parsed.payload.end(),
                      pngId.begin(), pngId.end()));
    assert(transfer.receiveResponse(fail).status == Result::RemoteFailure);
    assert(transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 17);
    assert(transfer.receiveResponse(fail).status == Result::RemoteFailure);
    assert(transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 8);
    const std::array<std::uint8_t, 2> imageBytes{0xaa, 0xbb};
    const auto success = responsePdu(kResponseOk, imageBytes);
    const auto image = transfer.receiveResponse(success);
    assert(image.status == Result::Received && image.formatId == 8);
    assert(image.payload.size() == imageBytes.size());
    assert(!transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 0 && request.empty());

    // The same format ID may map to a new offer, but an obsolete reply
    // MUST drain before any request in the new generation begins.
    formats.clear();
    appendLongFormat(formats, 0xc010, "PNG");
    appendLongFormat(formats, 17, "");
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(formats)));
    assert(transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 0xc010);
    formats.clear();
    appendLongFormat(formats, 0xc020, "PNG");
    appendLongFormat(formats, 8, "");
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(formats)));
    assert(!transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 0 && request.empty());
    assert(transfer.waitingForObsoleteResponse());
    assert(transfer.receiveResponse(success).status ==
           Result::DiscardedPreviousGeneration);
    assert(transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 0xc020);
    assert(transfer.receiveResponse(fail).status == Result::RemoteFailure);
    assert(transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 8);
    assert(transfer.receiveResponse(fail).status == Result::RemoteFailure);
    assert(!transfer.beginNextPrefetch(Kind::Image, selectedId, request));

    // A registered name can use a numeric ID otherwise known as DIBV5.
    // Never retry a duplicate ID merely because it occupies two priorities.
    formats.clear();
    appendLongFormat(formats, 17, "PNG");
    appendLongFormat(formats, 8, "");
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(formats)));
    assert(transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 17);
    assert(transfer.receiveResponse(fail).status == Result::RemoteFailure);
    assert(transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 8);
    assert(transfer.receiveResponse(fail).status == Result::RemoteFailure);
    assert(!transfer.beginNextPrefetch(Kind::Image, selectedId, request));

    // Disconnect revokes advertised candidates and attempted history.
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(formats)));
    assert(transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    transfer.abandonRequest();
    assert(!transfer.synchronized());
    assert(!transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    transfer.resetAfterDisconnect();
    assert(transfer.synchronized());
    assert(!transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(formats)));
    assert(transfer.beginNextPrefetch(Kind::Image, selectedId, request));
    assert(selectedId == 17);
}

// R8 outbound CLIPRDR data requests are encoded atomically over R3's
// joined MCS envelope. They are NOT proof of TLS/NLA/OS authorization.
void testJoinedFormatDataRequestEnvelope()
{
    using namespace rdp_server::server::transport;
    using namespace rdp_server::clipboard;
    McsChannelJoinWriteGate gate;
    const std::array<std::uint16_t, 2> channels{1007, 1003};
    assert(gate.configure(1007, channels));
    RemoteTransfer transfer;
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 2>{13, 0xc001}));

    std::array<std::uint8_t, 64> bytes{};
    bytes.fill(0xa5);
    const auto prepare = [&](std::uint16_t channelId,
                             std::uint16_t expectedRole,
                             std::uint32_t formatId,
                             std::span<std::uint8_t> output)
    {
        return transfer.prepareJoinedFormatDataRequest(
            gate, channelId, expectedRole, formatId, output);
    };
    // A configured but unjoined channel cannot reserve the request slot.
    assert(!prepare(1003, 1003, 13, bytes));
    assert(!transfer.hasOutstandingRequest());
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(!prepare(1003, 1003, 13, bytes));
    assert(gate.onReplyBytesWritten(
        gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 15) ==
        McsJoinWriteOutcome::Confirmed);
    assert(!prepare(1003, 1004, 13, bytes));  // Wrong CLIPRDR role.
    assert(!prepare(1007, 1003, 13, bytes));  // Wrong joined channel.
    assert(!prepare(999, 999, 13, bytes));   // Unknown channel.
    assert(!prepare(1003, 1003, 8, bytes));  // Not advertised.
    assert(!prepare(1003, 1003, 13, std::span(bytes).first(33)));
    assert(!transfer.hasOutstandingRequest());
    assert(std::all_of(bytes.begin(), bytes.end(),
                       [](std::uint8_t b) { return b == 0xa5; }));

    const std::array<std::uint8_t, 34> golden{
        0x03, 0, 0, 0x22, 0x02, 0xf0, 0x80, 0x68,
        0, 6, 3, 0xeb, 0x70, 0x14,
        0x0c, 0, 0, 0, 0x03, 0, 0, 0,
        0x04, 0, 0, 0, 0x04, 0, 0, 0,
        0x0d, 0, 0, 0};
    const auto first = prepare(1003, 1003, 13, bytes);
    assert(first && first->bytes == golden.size() && first->generation == 1);
    assert(first->sequence != 0);
    assert(std::equal(golden.begin(), golden.end(), bytes.begin()));
    assert(std::all_of(bytes.begin() + golden.size(), bytes.end(),
                       [](std::uint8_t b) { return b == 0xa5; }));
    assert(transfer.hasOutstandingRequest());
    assert(transfer.joinedRequestMayWrite(first->sequence));
    bytes.fill(0xa5);
    assert(!prepare(1003, 1003, 0xc001, bytes)); // Exactly one flight.
    assert(std::all_of(bytes.begin(), bytes.end(),
                       [](std::uint8_t b) { return b == 0xa5; }));
    assert(transfer.cancelUnwrittenJoinedRequest(first->sequence));
    assert(!transfer.hasOutstandingRequest());
    assert(!transfer.recordJoinedRequestWritten(first->sequence, 1));
    const auto second = prepare(1003, 1003, 0xc001, bytes);
    assert(second && second->sequence > first->sequence);
    assert(!transfer.recordJoinedRequestWritten(first->sequence, 1));
    assert(!transfer.cancelUnwrittenJoinedRequest(first->sequence));
    assert(transfer.recordJoinedRequestWritten(second->sequence, 7));
    assert(transfer.joinedRequestMayWrite(second->sequence));
    assert(transfer.recordJoinedRequestWritten(second->sequence, second->bytes));
    assert(!transfer.joinedRequestMayWrite(second->sequence));
    const auto result = transfer.receiveResponse(
        responsePdu(kResponseOk, std::array<std::uint8_t, 2>{0x89, 0x50}));
    assert(result.status == RemoteTransfer::ResponseStatus::Received);
    assert(result.generation == 1 && result.formatId == 0xc001);
    assert(!transfer.hasOutstandingRequest());
    gate.close();
    bytes.fill(0xa5);
    assert(!prepare(1003, 1003, 13, bytes));
    assert(std::all_of(bytes.begin(), bytes.end(),
                       [](std::uint8_t b) { return b == 0xa5; }));
}

void testJoinedFormatDataRequestGenerationCancellation()
{
    using namespace rdp_server::server::transport;
    using namespace rdp_server::clipboard;
    const std::array<std::uint16_t, 1> channels{1003};
    McsChannelJoinWriteGate gate;
    assert(gate.configure(1007, channels));
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(gate.onReplyBytesWritten(
        gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 15) ==
        McsJoinWriteOutcome::Confirmed);
    std::array<std::uint8_t, 64> output{};
    const std::array<std::uint32_t, 1> initial{13};
    const std::array<std::uint32_t, 1> newer{8};
    const auto prepare = [&](RemoteTransfer &owner, std::uint32_t id)
    {
        return owner.prepareJoinedFormatDataRequest(
            gate, 1003, 1003, id, output);
    };
    const auto reply = responsePdu(kResponseOk, std::array<std::uint8_t, 1>{9});

    // A reoffer invalidates an UNSENT old packet; cancellation is safe.
    RemoteTransfer transfer;
    assert(transfer.receiveFormatList(initial));
    const auto first = prepare(transfer, 13);
    assert(first);
    assert(transfer.receiveFormatList(newer));
    assert(!transfer.joinedRequestMayWrite(first->sequence));
    assert(transfer.cancelUnwrittenJoinedRequest(first->sequence));
    assert(!transfer.hasOutstandingRequest());
    const auto second = prepare(transfer, 8);
    assert(second && second->sequence > first->sequence);
    assert(!transfer.recordJoinedRequestWritten(first->sequence, 2));
    assert(transfer.recordJoinedRequestWritten(second->sequence, second->bytes));
    assert(transfer.receiveResponse(reply).status ==
           RemoteTransfer::ResponseStatus::Received);

    // A fully delivered old request keeps its retired response identity.
    assert(transfer.receiveFormatList(initial));
    const auto third = prepare(transfer, 13);
    assert(third);
    assert(transfer.recordJoinedRequestWritten(third->sequence, third->bytes));
    assert(transfer.receiveFormatList(newer));
    assert(transfer.waitingForObsoleteResponse());
    assert(!prepare(transfer, 8));
    assert(transfer.receiveResponse(reply).status ==
           RemoteTransfer::ResponseStatus::DiscardedPreviousGeneration);
    assert(prepare(transfer, 8));

    // An uncertain partial write cannot safely free the request slot.
    RemoteTransfer partial;
    assert(partial.receiveFormatList(initial));
    const auto active = prepare(partial, 13);
    assert(active);
    assert(partial.recordJoinedRequestWritten(active->sequence, 1));
    assert(!partial.cancelUnwrittenJoinedRequest(active->sequence));
    assert(partial.abandonJoinedRequest(active->sequence));
    assert(!partial.synchronized());
    assert(!prepare(partial, 13));
    partial.resetAfterDisconnect();
    assert(!partial.recordJoinedRequestWritten(active->sequence, active->bytes));
    assert(partial.receiveFormatList(initial));
    const auto afterReconnect = prepare(partial, 13);
    assert(afterReconnect && afterReconnect->sequence > active->sequence);
    assert(!partial.recordJoinedRequestWritten(active->sequence, 1));
    assert(partial.recordJoinedRequestWritten(
        afterReconnect->sequence, afterReconnect->bytes));
    assert(partial.receiveResponse(reply).status ==
           RemoteTransfer::ResponseStatus::Received);

    RemoteTransfer tooEarly;
    assert(tooEarly.receiveFormatList(initial));
    const auto unsubmitted = prepare(tooEarly, 13);
    assert(unsubmitted);
    assert(tooEarly.receiveResponse(reply).status ==
           RemoteTransfer::ResponseStatus::ProtocolError);
    assert(!tooEarly.synchronized());
    tooEarly.resetAfterDisconnect();
    assert(tooEarly.receiveFormatList(initial));
    const auto invalidProgress = prepare(tooEarly, 13);
    assert(invalidProgress);
    assert(!tooEarly.recordJoinedRequestWritten(
        invalidProgress->sequence, invalidProgress->bytes + 1));
    assert(!tooEarly.synchronized());
}

// R8 file-list metadata stays bounded and generation scoped. The wire
// FILEDESCRIPTORW names are accepted only as safe leaf names; no whole file
// body is copied into this owner.
void testFileDescriptorMetadataValidation()
{
    using namespace rdp_server::clipboard;
    constexpr std::uint32_t kFileListFormatId = 0xc100U;
    constexpr std::size_t kDescriptorBytes = 592U;
    constexpr std::uint32_t kFdAttributes = 0x00000004U;
    constexpr std::uint32_t kFdFileSize = 0x00000040U;
    constexpr std::uint32_t kFileAttributeDirectory = 0x00000010U;
    constexpr std::uint32_t kFileAttributeNormal = 0x00000080U;
    constexpr std::uint32_t kFileFlags =
        kUseLongFormatNames | kStreamFileclipEnabled |
        kFileclipNoFilePaths | kHugeFileSupportEnabled;

    RemoteTransfer transfer;
    // The peer/local policy may offer locking, but R8 does not negotiate that
    // bit until lock/unlock write receipts exist.
    assert(transfer.receiveCapabilitiesPdu(capabilitiesPdu(0x3eU), 0x3eU));
    assert(transfer.negotiatedGeneralFlags() == kFileFlags);
    std::vector<std::uint8_t> formats;
    appendLongFormat(formats, kFileListFormatId, "FileGroupDescriptorW");
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(formats)));
    assert(transfer.fileStreamingAvailable());

    std::vector<std::uint8_t> request;
    assert(transfer.beginFileGroupDescriptorRequest(request));
    PduView requestView{};
    assert(decodePdu(request, requestView));
    assert(requestView.type == kFormatDataRequest);
    assert(requestView.payload.size() == 4U);

    std::vector<std::uint8_t> list(4U + 2U * kDescriptorBytes, 0);
    put32(list, 0, 2);
    auto first = std::span(list).subspan(4U, kDescriptorBytes);
    put32(first, 0, kFdAttributes | kFdFileSize);
    put32(first, 36U, kFileAttributeNormal);
    put64(first, 64U, (std::uint64_t{1} << 32U) + 17U);
    putFileName(first, u"alpha.txt");

    auto second = std::span(list).subspan(
        4U + kDescriptorBytes, kDescriptorBytes);
    put32(second, 0, kFdAttributes);
    put32(second, 36U, kFileAttributeDirectory);
    putFileName(second, u"folder");

    const auto listWire = responsePdu(kResponseOk, list);
    const auto response = transfer.receiveResponse(listWire);
    assert(response.status == RemoteTransfer::ResponseStatus::Received);
    assert(transfer.storeFileGroupDescriptors(response));
    assert(transfer.remoteFileCount() == 2U);

    const auto alpha = transfer.remoteFile(0);
    assert(alpha &&
           std::u16string_view{alpha->name.data(), alpha->name.size()} ==
               u"alpha.txt");
    assert(alpha->sizeKnown);
    assert(alpha->size == (std::uint64_t{1} << 32U) + 17U);
    assert(!alpha->directory);
    assert(alpha->attributes == kFileAttributeNormal);

    // Huge-file negotiation permits a nonzero high offset DWORD.
    const auto highRange = transfer.beginFileRangeRequest(
        0, std::uint64_t{1} << 32U, 1U, request);
    assert(highRange);
    PduView highRangeView{};
    assert(decodePdu(request, highRangeView));
    assert(highRangeView.payload[12] == 0U);
    assert(highRangeView.payload[16] == 1U);
    assert(transfer.cancelUnsentFileContentsRequest(highRange->sequence));

    const auto folder = transfer.remoteFile(1);
    assert(folder &&
           std::u16string_view{folder->name.data(), folder->name.size()} ==
               u"folder");
    assert(folder->directory);
    assert(!folder->sizeKnown);
    assert(!transfer.beginFileRangeRequest(1, 0, 1, request));

    // A path-bearing name is not retained as a local destination hint.
    assert(transfer.beginFileGroupDescriptorRequest(request));
    std::vector<std::uint8_t> badList(4U + kDescriptorBytes, 0);
    put32(badList, 0, 1);
    auto bad = std::span(badList).subspan(4U, kDescriptorBytes);
    put32(bad, 0, kFdFileSize);
    putFileName(bad, u"dir\\escape.txt");
    const auto badWire = responsePdu(kResponseOk, badList);
    const auto badResponse = transfer.receiveResponse(badWire);
    assert(!transfer.storeFileGroupDescriptors(badResponse));
    assert(transfer.remoteFileCount() == 2U);
    assert(transfer.synchronized());

    // Without huge-file capability a high file-size DWORD is rejected.
    RemoteTransfer bounded;
    constexpr std::uint32_t kSmallFileFlags =
        kUseLongFormatNames | kStreamFileclipEnabled | kFileclipNoFilePaths;
    assert(bounded.receiveCapabilitiesPdu(
        capabilitiesPdu(kSmallFileFlags), kSmallFileFlags));
    assert(bounded.receiveLongFormatListPdu(longFormatPdu(formats)));
    assert(bounded.beginFileGroupDescriptorRequest(request));
    std::vector<std::uint8_t> hugeList(4U + kDescriptorBytes, 0);
    put32(hugeList, 0, 1);
    auto huge = std::span(hugeList).subspan(4U, kDescriptorBytes);
    put32(huge, 0, kFdFileSize);
    put64(huge, 64U, std::uint64_t{1} << 32U);
    putFileName(huge, u"huge.bin");
    const auto hugeWire = responsePdu(kResponseOk, hugeList);
    const auto hugeResponse = bounded.receiveResponse(hugeWire);
    assert(!bounded.storeFileGroupDescriptors(hugeResponse));
    assert(bounded.remoteFileCount() == 0);
    assert(bounded.synchronized());
}

void testFileContentsSizeRangeStreaming()
{
    using namespace rdp_server::clipboard;
    using Status = RemoteTransfer::FileContentsStatus;
    constexpr std::uint32_t kFileListFormatId = 0xc101U;
    constexpr std::size_t kDescriptorBytes = 592U;
    constexpr std::uint32_t kFileFlags =
        kUseLongFormatNames | kStreamFileclipEnabled |
        kFileclipNoFilePaths | kHugeFileSupportEnabled;

    RemoteTransfer transfer;
    assert(transfer.receiveCapabilitiesPdu(
        capabilitiesPdu(kFileFlags), kFileFlags));
    std::vector<std::uint8_t> formats;
    appendLongFormat(formats, kFileListFormatId, "FileGroupDescriptorW");
    assert(transfer.receiveLongFormatListPdu(longFormatPdu(formats)));

    std::vector<std::uint8_t> request;
    assert(transfer.beginFileGroupDescriptorRequest(request));
    std::vector<std::uint8_t> list(4U + kDescriptorBytes, 0);
    put32(list, 0, 1);
    putFileName(std::span(list).subspan(4U, kDescriptorBytes), u"stream.bin");
    const auto listWire = responsePdu(kResponseOk, list);
    const auto listResponse = transfer.receiveResponse(listWire);
    assert(transfer.storeFileGroupDescriptors(listResponse));
    assert(!transfer.remoteFile(0)->sizeKnown);

    const auto sizeRequest = transfer.beginFileSizeRequest(0, request);
    assert(sizeRequest && transfer.hasOutstandingFileContentsRequest());
    std::vector<std::uint8_t> overlappingRequest;
    assert(!transfer.beginFileGroupDescriptorRequest(overlappingRequest));
    assert(overlappingRequest.empty());
    PduView requestView{};
    assert(decodePdu(request, requestView));
    assert(requestView.type == kFileContentsRequest);
    assert(requestView.flags == 0);
    assert(requestView.payload.size() == 24U);
    assert(requestView.payload[0] ==
           static_cast<std::uint8_t>(sizeRequest->streamId));
    assert(requestView.payload[8] == 1U);
    assert(requestView.payload[20] == 8U);

    std::array<std::uint8_t, 8> sizeBytes{};
    put64(sizeBytes, 0, 100000U);
    const auto sizeWire = fileContentsResponsePdu(
        kResponseOk, sizeRequest->streamId, sizeBytes);
    const auto sizeResult = transfer.receiveFileContentsResponse(sizeWire);
    assert(sizeResult.status == Status::ReceivedSize);
    assert(sizeResult.fileSize == 100000U);
    assert(!transfer.hasOutstandingFileContentsRequest());
    assert(transfer.remoteFile(0)->sizeKnown);
    assert(transfer.remoteFile(0)->size == 100000U);

    const auto rangeRequest = transfer.beginFileRangeRequest(
        0, 65530U, 16U, request);
    assert(rangeRequest);
    assert(decodePdu(request, requestView));
    assert(requestView.type == kFileContentsRequest);
    assert(requestView.payload[8] == 2U);
    assert(requestView.payload[12] == 0xfaU);
    assert(requestView.payload[13] == 0xffU);
    assert(requestView.payload[20] == 16U);

    const std::array<std::uint8_t, 8> chunk{
        1, 2, 3, 4, 5, 6, 7, 8};
    const auto rangeWire = fileContentsResponsePdu(
        kResponseOk, rangeRequest->streamId, chunk);
    const auto rangeResult = transfer.receiveFileContentsResponse(rangeWire);
    assert(rangeResult.status == Status::ReceivedRange);
    assert(rangeResult.offset == 65530U);
    assert(std::equal(rangeResult.bytes.begin(), rangeResult.bytes.end(),
                      chunk.begin(), chunk.end()));

    assert(!transfer.beginFileRangeRequest(
        0, 0, RemoteTransfer::kMaximumFileContentsChunkBytes + 1U, request));
    assert(!transfer.beginFileRangeRequest(0, 99999U, 2U, request));

    const auto cancelled = transfer.beginFileRangeRequest(0, 0, 32U, request);
    assert(cancelled);
    assert(!transfer.cancelUnsentFileContentsRequest(
        cancelled->sequence + 1U));
    assert(transfer.cancelUnsentFileContentsRequest(cancelled->sequence));
    assert(!transfer.hasOutstandingFileContentsRequest());

    // Replacement does not let a late stream response attach to new files.
    const auto obsolete = transfer.beginFileRangeRequest(0, 0, 4U, request);
    assert(obsolete);
    assert(transfer.receiveFormatList(
        std::array<std::uint32_t, 1>{kFormatUnicodeText}));
    const std::array<std::uint8_t, 4> oldBytes{9, 8, 7, 6};
    const auto obsoleteWire = fileContentsResponsePdu(
        kResponseOk, obsolete->streamId, oldBytes);
    const auto obsoleteResult =
        transfer.receiveFileContentsResponse(obsoleteWire);
    assert(obsoleteResult.status == Status::DiscardedPreviousGeneration);
    assert(transfer.remoteFileCount() == 0U);
    assert(transfer.synchronized());
}

void testJoinedFileContentsRequestEnvelopeAndWriteFences()
{
    using namespace rdp_server::clipboard;
    using namespace rdp_server::server::transport;
    using FileStatus = RemoteTransfer::FileContentsStatus;
    constexpr std::uint32_t kFileListFormatId = 0xc103U;
    constexpr std::size_t kDescriptorBytes = 592U;
    constexpr std::uint32_t kFdFileSize = 0x00000040U;
    constexpr std::uint32_t kFileFlags =
        kUseLongFormatNames | kStreamFileclipEnabled |
        kFileclipNoFilePaths | kHugeFileSupportEnabled;

    const std::array<std::uint16_t, 1> channels{1003};
    McsChannelJoinWriteGate gate;
    assert(gate.configure(1007, channels));
    McsChannelRequest join{};
    join.kind = McsChannelRequestKind::ChannelJoin;
    join.initiator = 1007;
    join.channelId = 1003;
    assert(gate.beginJoin(join) == McsJoinStartOutcome::ReplyPending);
    assert(gate.onReplyBytesWritten(
        gate.pendingReplySequence(), gate.pendingWriteSliceSequence(), 15) ==
        McsJoinWriteOutcome::Confirmed);

    const auto prepareOwner = [&](RemoteTransfer &owner) {
        assert(owner.receiveCapabilitiesPdu(
            capabilitiesPdu(kFileFlags), kFileFlags));
        std::vector<std::uint8_t> formats;
        appendLongFormat(formats, kFileListFormatId, "FileGroupDescriptorW");
        assert(owner.receiveLongFormatListPdu(longFormatPdu(formats)));

        std::vector<std::uint8_t> request;
        assert(owner.beginFileGroupDescriptorRequest(request));
        std::vector<std::uint8_t> list(4U + kDescriptorBytes, 0);
        put32(list, 0, 1);
        auto descriptor = std::span(list).subspan(4U, kDescriptorBytes);
        put32(descriptor, 0, kFdFileSize);
        put64(descriptor, 64U, 100000U);
        putFileName(descriptor, u"joined.bin");
        const auto listWire = responsePdu(kResponseOk, list);
        assert(owner.storeFileGroupDescriptors(
            owner.receiveResponse(listWire)));
    };

    std::array<std::uint8_t, 96> output{};
    output.fill(0xa5);
    RemoteTransfer owner;
    prepareOwner(owner);

    // Membership/role mismatch cannot reserve a stream or mutate output.
    assert(!owner.prepareJoinedFileSizeRequest(
        gate, 1003, 1004, 0, output));
    assert(!owner.hasOutstandingFileContentsRequest());
    assert(std::all_of(output.begin(), output.end(),
                       [](std::uint8_t byte) { return byte == 0xa5; }));

    const auto size = owner.prepareJoinedFileSizeRequest(
        gate, 1003, 1003, 0, output);
    assert(size);
    assert(size->bytes == 54U);
    assert(size->request.sequence != 0);
    assert(size->request.streamId ==
           static_cast<std::uint32_t>(size->request.sequence));
    assert(size->request.kind == RemoteTransfer::FileContentsKind::Size);
    assert(size->request.requestedBytes == 8U);
    assert(owner.joinedFileContentsRequestMayWrite(size->request.sequence));

    const std::array<std::uint8_t, 14> envelope{
        0x03, 0x00, 0x00, 0x36, 0x02, 0xf0, 0x80,
        0x68, 0x00, 0x06, 0x03, 0xeb, 0x70, 0x28};
    assert(std::equal(envelope.begin(), envelope.end(), output.begin()));
    PduView clipboardRequest{};
    assert(decodePdu(
        std::span<const std::uint8_t>{output}.subspan(22U, 32U),
        clipboardRequest));
    assert(clipboardRequest.type == kFileContentsRequest);
    assert(clipboardRequest.payload.size() == 24U);
    assert(clipboardRequest.payload[0] ==
           static_cast<std::uint8_t>(size->request.streamId));
    assert(clipboardRequest.payload[8] == 1U);
    assert(clipboardRequest.payload[20] == 8U);

    assert(!owner.recordJoinedFileContentsRequestWritten(
        size->request.sequence + 1U, 1U));
    assert(owner.recordJoinedFileContentsRequestWritten(
        size->request.sequence, 7U));
    assert(owner.joinedFileContentsRequestMayWrite(size->request.sequence));
    assert(!owner.cancelUnwrittenJoinedFileContentsRequest(
        size->request.sequence));
    assert(owner.recordJoinedFileContentsRequestWritten(
        size->request.sequence, size->bytes));
    assert(!owner.joinedFileContentsRequestMayWrite(size->request.sequence));

    std::array<std::uint8_t, 8> fileSize{};
    put64(fileSize, 0, 100000U);
    const auto sizeResponse = fileContentsResponsePdu(
        kResponseOk, size->request.streamId, fileSize);
    assert(owner.receiveFileContentsResponse(sizeResponse).status ==
           FileStatus::ReceivedSize);

    // An entirely unwritten framed request can be revoked without ambiguity.
    output.fill(0xa5);
    const auto cancelled = owner.prepareJoinedFileRangeRequest(
        gate, 1003, 1003, 0, 16U, 32U, output);
    assert(cancelled);
    assert(!owner.cancelUnsentFileContentsRequest(
        cancelled->request.sequence));
    assert(owner.cancelUnwrittenJoinedFileContentsRequest(
        cancelled->request.sequence));
    assert(!owner.hasOutstandingFileContentsRequest());

    // Replacement revokes write permission before the first byte.
    const auto obsoleteUnsent = owner.prepareJoinedFileRangeRequest(
        gate, 1003, 1003, 0, 0, 4U, output);
    assert(obsoleteUnsent);
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{kFormatUnicodeText}));
    assert(!owner.joinedFileContentsRequestMayWrite(
        obsoleteUnsent->request.sequence));
    assert(owner.cancelUnwrittenJoinedFileContentsRequest(
        obsoleteUnsent->request.sequence));

    // A fully delivered old-generation frame keeps its stream identity and
    // drains its eventual response as obsolete.
    RemoteTransfer delivered;
    prepareOwner(delivered);
    const auto old = delivered.prepareJoinedFileRangeRequest(
        gate, 1003, 1003, 0, 8U, 4U, output);
    assert(old);
    assert(delivered.recordJoinedFileContentsRequestWritten(
        old->request.sequence, old->bytes));
    assert(delivered.receiveFormatList(
        std::array<std::uint32_t, 1>{kFormatUnicodeText}));
    const std::array<std::uint8_t, 4> oldBytes{1, 2, 3, 4};
    const auto oldResponse = fileContentsResponsePdu(
        kResponseOk, old->request.streamId, oldBytes);
    assert(delivered.receiveFileContentsResponse(oldResponse).status ==
           FileStatus::DiscardedPreviousGeneration);
    assert(delivered.synchronized());

    // Partial/unknown delivery can never release the stream for reuse.
    RemoteTransfer partial;
    prepareOwner(partial);
    const auto active = partial.prepareJoinedFileRangeRequest(
        gate, 1003, 1003, 0, 0, 4U, output);
    assert(active);
    assert(partial.recordJoinedFileContentsRequestWritten(
        active->request.sequence, 1U));
    assert(!partial.cancelUnwrittenJoinedFileContentsRequest(
        active->request.sequence));
    assert(partial.abandonJoinedFileContentsRequest(
        active->request.sequence));
    assert(!partial.synchronized());
    partial.resetAfterDisconnect();
    assert(!partial.recordJoinedFileContentsRequestWritten(
        active->request.sequence, active->bytes));

    // A response before the framed request is fully submitted is terminal.
    RemoteTransfer early;
    prepareOwner(early);
    const auto tooEarly = early.prepareJoinedFileRangeRequest(
        gate, 1003, 1003, 0, 0, 4U, output);
    assert(tooEarly);
    const auto earlyResponse = fileContentsResponsePdu(
        kResponseOk, tooEarly->request.streamId, oldBytes);
    assert(early.receiveFileContentsResponse(earlyResponse).status ==
           FileStatus::ProtocolError);
    assert(!early.synchronized());
}

void testFileContentsResponseRejections()
{
    using namespace rdp_server::clipboard;
    using Status = RemoteTransfer::FileContentsStatus;
    constexpr std::uint32_t kFileListFormatId = 0xc102U;
    constexpr std::size_t kDescriptorBytes = 592U;
    constexpr std::uint32_t kFdFileSize = 0x00000040U;
    constexpr std::uint32_t kFlags =
        kUseLongFormatNames | kStreamFileclipEnabled | kFileclipNoFilePaths;

    const auto prepare = [&]() {
        RemoteTransfer owner;
        assert(owner.receiveCapabilitiesPdu(capabilitiesPdu(kFlags), kFlags));
        std::vector<std::uint8_t> formats;
        appendLongFormat(formats, kFileListFormatId, "FileGroupDescriptorW");
        assert(owner.receiveLongFormatListPdu(longFormatPdu(formats)));
        std::vector<std::uint8_t> request;
        assert(owner.beginFileGroupDescriptorRequest(request));
        std::vector<std::uint8_t> list(4U + kDescriptorBytes, 0);
        put32(list, 0, 1);
        auto descriptor = std::span(list).subspan(4U, kDescriptorBytes);
        put32(descriptor, 0, kFdFileSize);
        put64(descriptor, 64U, 32U);
        putFileName(descriptor, u"small.bin");
        const auto wire = responsePdu(kResponseOk, list);
        assert(owner.storeFileGroupDescriptors(owner.receiveResponse(wire)));
        return owner;
    };

    {
        auto owner = prepare();
        std::vector<std::uint8_t> request;
        const auto pending = owner.beginFileRangeRequest(0, 0, 4, request);
        assert(pending);
        const std::array<std::uint8_t, 1> data{1};
        const auto wrong = fileContentsResponsePdu(
            kResponseOk, pending->streamId + 1U, data);
        assert(owner.receiveFileContentsResponse(wrong).status ==
               Status::ProtocolError);
        assert(!owner.synchronized());
    }
    {
        auto owner = prepare();
        std::vector<std::uint8_t> request;
        const auto pending = owner.beginFileRangeRequest(0, 0, 4, request);
        assert(pending);
        const std::array<std::uint8_t, 5> tooMuch{1, 2, 3, 4, 5};
        const auto oversized = fileContentsResponsePdu(
            kResponseOk, pending->streamId, tooMuch);
        assert(owner.receiveFileContentsResponse(oversized).status ==
               Status::ProtocolError);
        assert(!owner.synchronized());
    }
    {
        auto owner = prepare();
        std::vector<std::uint8_t> request;
        const auto pending = owner.beginFileSizeRequest(0, request);
        assert(pending);
        std::array<std::uint8_t, 8> huge{};
        put64(huge, 0, std::uint64_t{1} << 32U);
        const auto response = fileContentsResponsePdu(
            kResponseOk, pending->streamId, huge);
        assert(owner.receiveFileContentsResponse(response).status ==
               Status::ProtocolError);
        assert(!owner.synchronized());
    }
}

// R8: a raw, framed data response is not a native text-paste offer until
// its UTF-16LE is verified and copied for the current clipboard generation.
void testVerifiedUnicodeTextReadiness()
{
    using namespace rdp_server::clipboard;
    RemoteTransfer owner;
    std::vector<std::uint8_t> request;
    assert(!owner.verifiedUnicodeText());
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 2>{kFormatUnicodeText, 8}));
    const auto receiveText = [&](std::span<const std::uint8_t> wire)
    {
        assert(owner.beginRequest(kFormatUnicodeText, request));
        const auto complete = responsePdu(kResponseOk, wire);
        const auto response = owner.receiveResponse(complete);
        assert(response.status == RemoteTransfer::ResponseStatus::Received);
        return owner.storeVerifiedUnicodeText(response);
    };

    const std::array<std::uint8_t, 12> smile{
        'A', 0, '\r', 0, '\n', 0, 0x3d, 0xd8, 0, 0xde, 0, 0};
    assert(receiveText(smile));
    assert(owner.verifiedUnicodeText() ==
           std::optional<std::string_view>{"A\n\xf0\x9f\x98\x80"});
    assert(!owner.hasOutstandingRequest());
    // The completed PDU buffer is dead, yet the owned snapshot remains.
    assert(*owner.verifiedUnicodeText() == "A\n\xf0\x9f\x98\x80");

    const std::array<std::array<std::uint8_t, 4>, 4> malformed{{
        {{'A', 0, 'B', 0}},     // Missing NUL.
        {{0, 0, 0, 0}},         // Repeated NUL.
        {{0x3d, 0xd8, 0, 0}},   // Isolated high surrogate.
        {{0, 0xdc, 0, 0}},      // Isolated low surrogate.
    }};
    for (const auto &wire : malformed)
    {
        assert(!receiveText(wire));
        assert(!owner.verifiedUnicodeText());
        assert(owner.synchronized()); // Payload failure, not wire framing.
    }
    const std::array<std::uint8_t, 3> odd{'A', 0, 0};
    assert(!receiveText(odd));
    const std::array<std::uint8_t, 6> interior{'A', 0, 0, 0, 0, 0};
    assert(!receiveText(interior));
    const std::array<std::uint8_t, 6> mismatched{
        0x3d, 0xd8, 'B', 0, 0, 0};
    assert(!receiveText(mismatched));
    std::vector<std::uint8_t> excessive(1024U * 1024U + 2U);
    assert(!receiveText(excessive));
    assert(owner.synchronized());

    const std::array<std::uint8_t, 2> empty{0, 0};
    assert(receiveText(empty));
    assert(owner.verifiedUnicodeText()->empty());
    assert(!receiveText({}));
    assert(!owner.verifiedUnicodeText());

    assert(receiveText(smile));
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{kFormatUnicodeText}));
    assert(!owner.verifiedUnicodeText()); // Reoffer invalidates cached data.
    assert(receiveText(smile));
    owner.resetAfterDisconnect();
    assert(!owner.verifiedUnicodeText());
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{kFormatUnicodeText}));
    assert(receiveText(smile));
    assert(owner.beginRequest(kFormatUnicodeText, request));
    const std::array<std::uint8_t, 1> badPdu{0};
    assert(owner.receiveResponse(badPdu).status ==
           RemoteTransfer::ResponseStatus::ProtocolError);
    assert(!owner.verifiedUnicodeText()); // Poison hides prior readiness.
    owner.resetAfterDisconnect();
    assert(!owner.verifiedUnicodeText());
}


// R8: cache only structurally valid, bounded current-generation image bytes.
// Keep PNG compressed and DIB packed; native conversion/publication is later.
void testVerifiedImageReadiness()
{
    using namespace rdp_server::clipboard;
    using ImageFormat = RemoteTransfer::VerifiedImageFormat;
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
    const auto put16 = [](std::vector<std::uint8_t> &bytes,
                          std::size_t offset, std::uint16_t value) {
        bytes[offset] = static_cast<std::uint8_t>(value);
        bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
    };
    const auto put32 = [](std::vector<std::uint8_t> &bytes,
                          std::size_t offset, std::uint32_t value) {
        for (unsigned shift = 0; shift < 32; shift += 8)
        {
            bytes[offset + shift / 8U] =
                static_cast<std::uint8_t>(value >> shift);
        }
    };
    const auto makeDib = [&](std::uint32_t headerBytes) {
        std::vector<std::uint8_t> dib(headerBytes + 4U, 0);
        put32(dib, 0, headerBytes);
        put32(dib, 4, 1);
        put32(dib, 8, 1);
        put16(dib, 12, 1);
        put16(dib, 14, 32);
        put32(dib, 16, 0); // BI_RGB.
        put32(dib, 20, 4);
        dib[headerBytes] = 0x11;
        dib[headerBytes + 1U] = 0x22;
        dib[headerBytes + 2U] = 0x33;
        dib[headerBytes + 3U] = 0xff;
        return dib;
    };

    RemoteTransfer owner;
    std::vector<std::uint8_t> formats;
    appendLongFormat(formats, 0xc001, "PNG");
    appendLongFormat(formats, 17, "");
    appendLongFormat(formats, 8, "");
    assert(owner.receiveLongFormatListPdu(longFormatPdu(formats)));
    assert(!owner.verifiedImage());
    std::vector<std::uint8_t> request;
    const std::uint8_t *lastBorrowedPayload = nullptr;
    const auto receiveAndStore = [&](std::uint32_t formatId,
                                     std::span<const std::uint8_t> payload) {
        assert(owner.beginRequest(formatId, request));
        const auto complete = responsePdu(kResponseOk, payload);
        const auto response = owner.receiveResponse(complete);
        assert(response.status == RemoteTransfer::ResponseStatus::Received);
        lastBorrowedPayload = response.payload.data();
        return owner.storeVerifiedImage(response);
    };

    assert(receiveAndStore(0xc001, kValidPng));
    auto ready = owner.verifiedImage();
    assert(ready && ready->format == ImageFormat::Png);
    assert(ready->generation == 1 && ready->sourceFormatId == 0xc001);
    assert(std::equal(ready->bytes.begin(), ready->bytes.end(),
                      kValidPng.begin(), kValidPng.end()));
    assert(ready->bytes.data() != lastBorrowedPayload);

    auto corruptPng = std::vector<std::uint8_t>(
        kValidPng.begin(), kValidPng.end());
    corruptPng[48] ^= 0x01U;
    assert(!receiveAndStore(0xc001, corruptPng));
    assert(owner.synchronized());
    // A rejected candidate cannot replace an already verified same-generation
    // snapshot. Generation replacement below remains authoritative.
    ready = owner.verifiedImage();
    assert(ready && ready->format == ImageFormat::Png);

    const auto dibV5 = makeDib(124);
    assert(receiveAndStore(17, dibV5));
    ready = owner.verifiedImage();
    assert(ready && ready->format == ImageFormat::DibV5 &&
           ready->sourceFormatId == 17 && ready->bytes.size() == dibV5.size());

    const auto dib = makeDib(40);
    assert(validateDib(dib));
    // CF_DIBV5 requires BITMAPV5HEADER; a valid BITMAPINFOHEADER is not V5.
    assert(!receiveAndStore(17, dib));
    assert(owner.verifiedImage()->format == ImageFormat::DibV5);
    assert(receiveAndStore(8, dib));
    assert(owner.verifiedImage()->format == ImageFormat::Dib);

    // A tiny compressed payload with dimensions above the prospective
    // 256-MiB 32-bpp working-set bound is structurally a DIB but not ready.
    std::vector<std::uint8_t> oversizedDecode(41, 0);
    put32(oversizedDecode, 0, 40);
    put32(oversizedDecode, 4, 8193);
    put32(oversizedDecode, 8, 8192);
    put16(oversizedDecode, 12, 1);
    put16(oversizedDecode, 14, 0);
    put32(oversizedDecode, 16, 5); // BI_PNG.
    put32(oversizedDecode, 20, 1);
    assert(validateDib(oversizedDecode));
    assert(!receiveAndStore(8, oversizedDecode));
    assert(owner.verifiedImage()->format == ImageFormat::Dib);

    // A new clipboard generation invalidates owned image readiness, and an
    // old response is drained rather than republished for that generation.
    assert(owner.beginRequest(8, request));
    assert(owner.receiveFormatList(std::array<std::uint32_t, 1>{8}));
    assert(!owner.verifiedImage());
    const auto obsoleteWire = responsePdu(kResponseOk, dib);
    const auto obsolete = owner.receiveResponse(obsoleteWire);
    assert(obsolete.status ==
           RemoteTransfer::ResponseStatus::DiscardedPreviousGeneration);
    assert(!owner.storeVerifiedImage(obsolete));
    assert(!owner.verifiedImage());

    // Registered PNG IDs are not globally fixed: name resolution wins even
    // if this generation assigns PNG the numeric CF_DIBV5 value 17.
    RemoteTransfer collision;
    formats.clear();
    appendLongFormat(formats, 17, "PNG");
    appendLongFormat(formats, 8, "");
    assert(collision.receiveLongFormatListPdu(longFormatPdu(formats)));
    assert(collision.beginRequest(17, request));
    const auto collisionWire = responsePdu(kResponseOk, kValidPng);
    const auto collisionResponse = collision.receiveResponse(collisionWire);
    assert(collision.storeVerifiedImage(collisionResponse));
    const auto collisionReady = collision.verifiedImage();
    assert(collisionReady && collisionReady->format == ImageFormat::Png &&
           collisionReady->sourceFormatId == 17);

    collision.resetAfterDisconnect();
    assert(!collision.verifiedImage());
    assert(collision.receiveFormatList(std::array<std::uint32_t, 1>{8}));
    assert(collision.beginRequest(8, request));
    const auto validDibWire = responsePdu(kResponseOk, dib);
    const auto validDibResponse = collision.receiveResponse(validDibWire);
    assert(collision.storeVerifiedImage(validDibResponse));
    assert(collision.beginRequest(8, request));
    collision.abandonRequest();
    assert(!collision.synchronized());
    assert(!collision.verifiedImage());
}


void testNonblockingPasteReadiness()
{
    using namespace rdp_server::clipboard;
    using Clock = RemoteTransfer::PasteClock;
    using Kind = RemoteTransfer::PasteKind;
    using Status = RemoteTransfer::PasteStatus;
    const Clock::time_point start{std::chrono::seconds{1}};
    const auto deadline = start + std::chrono::milliseconds{100};

    RemoteTransfer owner;
    assert(!owner.beginPasteRequest(Kind::UnicodeText, start, deadline));
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 3>{kFormatUnicodeText, 17, 8}));
    assert(!owner.beginPasteRequest(Kind::UnicodeText, deadline, deadline));
    assert(!owner.beginPasteRequest(
        Kind::UnicodeText, deadline, deadline - std::chrono::milliseconds{1}));

    // A live paste can register while one speculative image request is
    // already in flight. That unavoidable response must drain first.
    std::uint32_t selectedFormatId = 0;
    std::vector<std::uint8_t> request;
    assert(owner.beginNextPrefetch(
        RemoteTransfer::PrefetchKind::Image, selectedFormatId, request));
    assert(selectedFormatId == 17);
    const auto textReceipt =
        owner.beginPasteRequest(Kind::UnicodeText, start, deadline);
    assert(textReceipt && textReceipt->sequence != 0 &&
           textReceipt->generation == owner.generation());
    assert(owner.hasPendingPasteRequest());
    assert(owner.pollPasteRequest(
               textReceipt->sequence, start + std::chrono::milliseconds{1})
               .status == Status::Pending);

    const auto failedPrefetch = responsePdu(kResponseFail);
    assert(owner.receiveResponse(failedPrefetch).status ==
           RemoteTransfer::ResponseStatus::RemoteFailure);

    // With the paste still pending, speculative fallback to DIB is withheld.
    selectedFormatId = 999;
    request.assign(3, 0xff);
    assert(!owner.beginNextPrefetch(
        RemoteTransfer::PrefetchKind::Image, selectedFormatId, request));
    assert(selectedFormatId == 0 && request.empty());

    // The same paste receipt becomes ready only after verified current-
    // generation text arrives; no sleep or synchronous wait is involved.
    assert(owner.beginRequest(kFormatUnicodeText, request));
    const std::array<std::uint8_t, 6> textWire{'O', 0, 'K', 0, 0, 0};
    const auto textPdu = responsePdu(kResponseOk, textWire);
    const auto textResponse = owner.receiveResponse(textPdu);
    assert(textResponse.status == RemoteTransfer::ResponseStatus::Received);
    assert(owner.storeVerifiedUnicodeText(textResponse));
    const auto readyText = owner.pollPasteRequest(
        textReceipt->sequence, start + std::chrono::milliseconds{2});
    assert(readyText.status == Status::ReadyUnicodeText);
    assert(readyText.sequence == textReceipt->sequence);
    assert(readyText.generation == textReceipt->generation);
    assert(readyText.text == "OK");
    assert(!readyText.image);
    assert(!owner.hasPendingPasteRequest());
    assert(owner.pollPasteRequest(
               textReceipt->sequence, start + std::chrono::milliseconds{3})
               .status == Status::InvalidSequence);

    // Already-verified image data completes a newly registered native request
    // immediately, but still under the receipt/deadline contract.
    assert(owner.receiveFormatList(std::array<std::uint32_t, 1>{8}));
    std::array<std::uint8_t, 44> dib{};
    dib[0] = 40;  // BITMAPINFOHEADER
    dib[4] = 1;   // width
    dib[8] = 1;   // height
    dib[12] = 1;  // planes
    dib[14] = 32; // bits per pixel
    dib[20] = 4;  // image bytes
    dib[40] = 0x11;
    dib[41] = 0x22;
    dib[42] = 0x33;
    dib[43] = 0xff;
    assert(owner.beginRequest(8, request));
    const auto imagePdu = responsePdu(kResponseOk, dib);
    const auto imageResponse = owner.receiveResponse(imagePdu);
    assert(owner.storeVerifiedImage(imageResponse));
    const auto imageStart = start + std::chrono::milliseconds{10};
    const auto imageReceipt = owner.beginPasteRequest(
        Kind::Image, imageStart, imageStart + std::chrono::milliseconds{50});
    assert(imageReceipt);
    const auto readyImage = owner.pollPasteRequest(
        imageReceipt->sequence, imageStart + std::chrono::milliseconds{1});
    assert(readyImage.status == Status::ReadyImage && readyImage.image);
    assert(readyImage.image->format ==
           RemoteTransfer::VerifiedImageFormat::Dib);
    assert(readyImage.image->sourceFormatId == 8);
    assert(std::equal(readyImage.image->bytes.begin(),
                      readyImage.image->bytes.end(),
                      dib.begin(), dib.end()));

    // Deadline expiry and native owner loss reject only the waiting paste,
    // not the synchronized CLIPRDR transfer state.
    const auto timeoutStart = start + std::chrono::milliseconds{20};
    const auto timeoutReceipt = owner.beginPasteRequest(
        Kind::Image, timeoutStart,
        timeoutStart + std::chrono::milliseconds{10});
    assert(timeoutReceipt);
    const auto timedOut = owner.pollPasteRequest(
        timeoutReceipt->sequence,
        timeoutStart + std::chrono::milliseconds{10});
    assert(timedOut.status == Status::TimedOut);
    assert(owner.synchronized());

    const auto ownerLossStart = start + std::chrono::milliseconds{40};
    const auto ownerLossReceipt = owner.beginPasteRequest(
        Kind::Image, ownerLossStart,
        ownerLossStart + std::chrono::milliseconds{20});
    assert(ownerLossReceipt);
    assert(!owner.cancelPasteRequestForOwnerLoss(
        ownerLossReceipt->sequence + 1));
    assert(owner.cancelPasteRequestForOwnerLoss(ownerLossReceipt->sequence));
    assert(!owner.hasPendingPasteRequest());
    const auto ownerLost = owner.pollPasteRequest(
        ownerLossReceipt->sequence,
        ownerLossStart + std::chrono::milliseconds{1});
    assert(ownerLost.status == Status::OwnerLost);
    assert(owner.synchronized());

    // A valid replacement terminalizes the old generation's same native
    // request without poisoning it.
    const auto replaceStart = start + std::chrono::milliseconds{60};
    const auto replacedReceipt = owner.beginPasteRequest(
        Kind::Image, replaceStart,
        replaceStart + std::chrono::milliseconds{20});
    assert(replacedReceipt);
    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{kFormatUnicodeText}));
    const auto replaced = owner.pollPasteRequest(
        replacedReceipt->sequence,
        replaceStart + std::chrono::milliseconds{1});
    assert(replaced.status == Status::ClipboardReplaced);
    assert(replaced.generation == replacedReceipt->generation);
    assert(owner.synchronized());

    // Disconnect rejects a waiting request but keeps the monotonic receipt
    // observable once; reconnect must never reuse its sequence.
    const auto disconnectStart = start + std::chrono::milliseconds{80};
    const auto disconnectedReceipt = owner.beginPasteRequest(
        Kind::UnicodeText, disconnectStart,
        disconnectStart + std::chrono::milliseconds{20});
    assert(disconnectedReceipt);
    owner.resetAfterDisconnect();
    assert(!owner.hasPendingPasteRequest());
    const auto disconnected = owner.pollPasteRequest(
        disconnectedReceipt->sequence,
        disconnectStart + std::chrono::milliseconds{1});
    assert(disconnected.status == Status::Disconnected);
    assert(owner.synchronized());

    assert(owner.receiveFormatList(
        std::array<std::uint32_t, 1>{kFormatUnicodeText}));
    const auto reconnectStart = start + std::chrono::milliseconds{120};
    const auto reconnectReceipt = owner.beginPasteRequest(
        Kind::UnicodeText, reconnectStart,
        reconnectStart + std::chrono::milliseconds{20});
    assert(reconnectReceipt &&
           reconnectReceipt->sequence > disconnectedReceipt->sequence);

    // Ambiguous channel/request failure rejects the waiting native request as
    // a channel error. A genuine disconnect is still required for wire reuse.
    assert(owner.beginRequest(kFormatUnicodeText, request));
    owner.abandonRequest();
    const auto channelError = owner.pollPasteRequest(
        reconnectReceipt->sequence,
        reconnectStart + std::chrono::milliseconds{1});
    assert(channelError.status == Status::ChannelError);
    assert(!owner.synchronized());
    owner.resetAfterDisconnect();
    assert(owner.synchronized());
}

} // namespace

int main(int argumentCount, char **arguments)
{
    if (argumentCount == 2)
    {
        const std::string_view caseName{arguments[1]};
        if (caseName == "mcs-cliprdr-length-mutation-denials")
        {
            testMcsCliprdrLengthMutationDenials();
            return 0;
        }
        if (caseName == "mcs-joined-response-teardown")
        {
            testMcsJoinedClipboardResponseTeardown();
            return 0;
        }
        if (caseName == "file-descriptor-metadata-validation")
        {
            testFileDescriptorMetadataValidation();
            return 0;
        }
        if (caseName == "file-contents-size-range-streaming")
        {
            testFileContentsSizeRangeStreaming();
            return 0;
        }
        if (caseName == "file-contents-response-rejections")
        {
            testFileContentsResponseRejections();
            return 0;
        }
        if (caseName == "file-contents-joined-mcs-envelope")
        {
            testJoinedFileContentsRequestEnvelopeAndWriteFences();
            return 0;
        }
        if (caseName == "verified-unicode-text-readiness")
        {
            testVerifiedUnicodeTextReadiness();
            return 0;
        }
        if (caseName == "verified-image-readiness")
        {
            testVerifiedImageReadiness();
            return 0;
        }
        if (caseName == "nonblocking-paste-readiness")
        {
            testNonblockingPasteReadiness();
            return 0;
        }
        if (caseName == "format-data-request-joined-mcs-envelope")
        {
            testJoinedFormatDataRequestEnvelope();
            return 0;
        }
        if (caseName == "format-data-request-generation-cancellation")
        {
            testJoinedFormatDataRequestGenerationCancellation();
            return 0;
        }
        if (caseName == "prefetch-unicode-png-dib-single-flight")
        {
            testPrefetchUnicodePngDibFallbackSingleFlight();
            return 0;
        }
        if (caseName == "joined-static-channel-inbound-gates")
        {
            testJoinedStaticChannelInboundGates();
            return 0;
        }
        if (caseName == "format-list-response-joined-mcs-envelope")
        {
            testFormatListResponseJoinedMcsEnvelope();
            return 0;
        }
        if (caseName == "capabilities-negotiation-format-gating")
        {
            testCapabilitiesNegotiationAndFormatListGating();
            return 0;
        }
        if (caseName == "long-format-list-generation")
        {
            testLongFormatListGeneration();
            return 0;
        }
        if (caseName == "short-format-list-negotiation")
        {
            testShortFormatListNegotiation();
            return 0;
        }
        if (caseName == "format-list-response-native-acceptance")
        {
            testFormatListResponseNativeAcceptance();
            return 0;
        }
    }
    if (argumentCount == 2 &&
        std::string_view(arguments[1]) == "framing-rejections")
    {
        testMalformedResponseFramingFailsClosed();
        return 0;
    }
    if (argumentCount != 1)
    {
        return 2;
    }
    testBasicRequestAndFailure();
    testOldResponseCannotBecomeNewPayload();
    testPoisonAndDisconnect();
    testMalformedPacketsAndLists();
    testFailedResponseWithPayloadMustReject();
}
