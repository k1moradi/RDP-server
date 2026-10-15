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
} // namespace

int main(int argumentCount, char **arguments)
{
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
