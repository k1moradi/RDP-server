// SPDX-License-Identifier: GPL-3.0-or-later
// Bounded libFuzzer entry point for first-party MCS and CLIPRDR parsers.
// This is offline syntax/state testing only; it cannot grant R2/R3 admission.

#include "clipboard/clipboard_protocol.h"
#include "clipboard/remote_transfer.h"
#include "transport/mcs_channel_connection.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data,
                                       std::size_t size)
{
    constexpr std::size_t kMaximumFuzzInputBytes = 4096;
    if (size > kMaximumFuzzInputBytes)
    {
        return 0;
    }

    const std::span<const std::uint8_t> bytes{data, size};
    using rdp_server::server::clipboard::RemoteTransfer;
    using namespace rdp_server::server::transport;

    const auto mcs = parseMcsChannelRequest(bytes);

    rdp_server::clipboard::PduView clipboardPdu{};
    [[maybe_unused]] const bool clipboardDecoded =
        rdp_server::clipboard::decodePdu(bytes, clipboardPdu);

    // Drive each CLIPRDR parser on a fresh owner so one fail-closed mutation
    // cannot mask coverage in another parser during the same fuzz iteration.
    RemoteTransfer capabilities;
    [[maybe_unused]] const bool capabilitiesAccepted =
        capabilities.receiveCapabilitiesPdu(
            bytes, RemoteTransfer::kSupportedGeneralFlags);

    RemoteTransfer longFormats;
    [[maybe_unused]] const bool longFormatsAccepted =
        longFormats.receiveLongFormatListPdu(bytes);

    RemoteTransfer shortFormats;
    [[maybe_unused]] const bool shortFormatsAccepted =
        shortFormats.receiveShortFormatListPdu(bytes);

    const std::array<std::uint32_t, 3> advertisedFormats{
        rdp_server::clipboard::kFormatUnicodeText, 8U, 17U};
    RemoteTransfer response;
    std::vector<std::uint8_t> request;
    if (response.receiveFormatList(advertisedFormats) &&
        response.beginRequest(rdp_server::clipboard::kFormatUnicodeText,
                              request))
    {
        [[maybe_unused]] const auto result = response.receiveResponse(bytes);
    }

    // If the raw bytes are a complete MCS SendDataRequest, re-run the nested
    // CLIPRDR response parser on its zero-copy payload. Seed corpus entries
    // include one valid TPKT/MCS/CLIPRDR envelope to reach this path quickly.
    if (mcs &&
        mcs.request.kind == McsChannelRequestKind::SendDataRequest)
    {
        rdp_server::clipboard::PduView nestedPdu{};
        [[maybe_unused]] const bool nestedDecoded =
            rdp_server::clipboard::decodePdu(
                mcs.request.userData, nestedPdu);

        RemoteTransfer nestedResponse;
        std::vector<std::uint8_t> nestedRequest;
        if (nestedResponse.receiveFormatList(advertisedFormats) &&
            nestedResponse.beginRequest(
                rdp_server::clipboard::kFormatUnicodeText,
                nestedRequest))
        {
            [[maybe_unused]] const auto result =
                nestedResponse.receiveResponse(mcs.request.userData);
        }
    }

    // Exercise bounded fragment/reset ownership without permitting the fuzzer
    // to request large allocations. No nullptr arithmetic is attempted.
    if (size != 0)
    {
        rdp_server::clipboard::ChunkReassembler reassembler;
        std::vector<std::uint8_t> complete;
        const std::size_t split =
            static_cast<std::size_t>(data[0]) % (size + 1U);
        std::size_t advertisedTotal = size;
        if (size >= 2)
        {
            advertisedTotal =
                ((static_cast<std::size_t>(data[0]) << 8U) |
                 static_cast<std::size_t>(data[1])) %
                8193U;
        }

        [[maybe_unused]] const bool firstAccepted =
            reassembler.append(data, split, advertisedTotal, true,
                               split == size, complete);
        if (split < size)
        {
            [[maybe_unused]] const bool finalAccepted =
                reassembler.append(data + split, size - split,
                                   advertisedTotal, false, true, complete);
        }
        reassembler.reset();
    }

    return 0;
}
