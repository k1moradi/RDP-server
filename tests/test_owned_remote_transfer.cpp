// SPDX-License-Identifier: GPL-3.0-or-later
#include "clipboard/clipboard_protocol.h"
#include "clipboard/remote_transfer.h"

#include <array>
// Release builds set NDEBUG. Keep all correctness checks live under -O3.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
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
} // namespace

int main(int argumentCount, char **arguments)
{
    if (argumentCount == 2)
    {
        const std::string_view caseName{arguments[1]};
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
