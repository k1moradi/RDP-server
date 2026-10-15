// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace rdp_server::server::clipboard
{

// A source-owned, single-session CLIPRDR response coordinator.
// The channel transports one Format Data Request at a time: responses have
// no wire request ID. A new Format List cannot make an in-flight response
// belong to a new generation. All methods are session-event-loop confined;
// callers must not access this object concurrently.
class RemoteTransfer final
{
public:
    static constexpr std::size_t kMaximumFormats = 64;

    enum class ResponseStatus : std::uint8_t
    {
        Received,
        RemoteFailure,
        DiscardedPreviousGeneration,
        ProtocolError,
    };

    struct Response
    {
        ResponseStatus status{ResponseStatus::ProtocolError};
        std::uint64_t generation{};
        std::uint32_t formatId{};
        // Borrowed from the caller's immutable PDU input. Consume or copy
        // immediately, before the supplied PDU buffer is released.
        std::span<const std::uint8_t> payload{};
    };

    // A valid new list supersedes earlier offers. Invalid or overflowing
    // lists poison this channel; only resetAfterDisconnect() permits reuse.
    [[nodiscard]] bool receiveFormatList(
        std::span<const std::uint32_t> advertisedFormatIds) noexcept;

    // Consume a complete CB_FORMAT_LIST only after both peers negotiate
    // CB_USE_LONG_FORMAT_NAMES. No borrowed names survive this call.
    // Malformed wire input closes this coordinator until disconnect.
    [[nodiscard]] bool receiveLongFormatListPdu(
        std::span<const std::uint8_t> completePdu) noexcept;

    // Consume the fallback fixed-width (36-byte/format) representation only
    // when CB_USE_LONG_FORMAT_NAMES was not negotiated by both endpoints.
    // CB_ASCII_NAMES selects 32 single-byte characters, otherwise 16 UTF-16LE
    // code units. A full name field may be truncated without a terminator.
    [[nodiscard]] bool receiveShortFormatListPdu(
        std::span<const std::uint8_t> completePdu) noexcept;

    // Process an authorized, complete Format List using the R3-negotiated
    // name layout, then encode its eight-byte MS-RDPECLIP response. The
    // native adapter must have accepted the new offer before the caller
    // passes nativeOfferAccepted=true; if acceptance is asynchronous, defer
    // this call until completion. A rejected offer advances the generation
    // but advertises nothing, so old data cannot be requested accidentally.
    // A failed parse poisons the session until actual disconnect. A negative
    // reply must only be transmitted through R3's admitted CLIPRDR channel.
    // The caller owns transport/send completion; this method does no I/O.
    [[nodiscard]] bool receiveFormatListWithResponse(
        std::span<const std::uint8_t> completePdu,
        bool negotiatedLongFormatNames, bool nativeOfferAccepted,
        std::array<std::uint8_t, 8> &response) noexcept;

    // Known registered format names are resolved from this generation's offer.
    [[nodiscard]] std::uint32_t namedFormatId(std::string_view name) const noexcept;

    // Encode a CLIPRDR Format Data Request only for the current generation.
    // On success, output owns a complete PDU; on rejection output is empty.
    // Call only after the previous request has completed or been retired.
    [[nodiscard]] bool beginRequest(
        std::uint32_t formatId, std::vector<std::uint8_t> &output) noexcept;

    // Exactly one response is consumed for each outstanding request. A
    // response to a retired generation is drained, never reassigned.
    [[nodiscard]] Response receiveResponse(
        std::span<const std::uint8_t> completePdu) noexcept;

    // A lost, timed-out or ambiguous response cannot be correlated with
    // subsequent traffic. Fail closed until an actual channel disconnect.
    void abandonRequest() noexcept;
    void resetAfterDisconnect() noexcept;

    [[nodiscard]] bool synchronized() const noexcept;
    [[nodiscard]] bool hasOutstandingRequest() const noexcept;
    [[nodiscard]] bool waitingForObsoleteResponse() const noexcept;
    [[nodiscard]] std::uint64_t generation() const noexcept;
    [[nodiscard]] bool advertises(std::uint32_t formatId) const noexcept;

private:
    struct PendingRequest
    {
        std::uint64_t generation{};
        std::uint32_t formatId{};
    };

    std::array<std::uint32_t, kMaximumFormats> advertisedFormats_{};
    std::size_t advertisedCount_{};
    std::uint32_t pngFormatId_{};
    std::uint32_t fileGroupDescriptorFormatId_{};
    std::uint64_t generation_{};
    PendingRequest pending_{};
    bool pendingValid_{};
    bool poisoned_{};
};

} // namespace rdp_server::server::clipboard
