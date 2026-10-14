// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
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
    std::uint64_t generation_{};
    PendingRequest pending_{};
    bool pendingValid_{};
    bool poisoned_{};
};

} // namespace rdp_server::server::clipboard
