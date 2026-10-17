// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::rdp
{

// MS-RDPEGFX 2.2.2.13: this parser only decodes an already reassembled,
// authorized RDPGFX command. The R3 channel owner controls admission and
// fragmentation; the R4 graphics scheduler owns outstanding frame IDs.
inline constexpr std::uint16_t kGfxFrameAcknowledgeCommand = 0x000D;
inline constexpr std::size_t kGfxFrameAcknowledgePduBytes = 20U;
inline constexpr std::uint32_t kGfxSuspendFrameAcknowledgement = 0xFFFFFFFFU;

struct GfxFrameAcknowledgement final
{
    std::uint32_t queueDepth{};
    std::uint32_t frameId{};
    std::uint32_t totalFramesDecoded{};

    friend bool operator==(const GfxFrameAcknowledgement &,
                           const GfxFrameAcknowledgement &) = default;

    // Suspension requires the graphics owner to clear its unacknowledged
    // frame set; this value is NOT a count of queued bytes.
    [[nodiscard]] bool acknowledgementsSuspended() const noexcept
    {
        return queueDepth == kGfxSuspendFrameAcknowledgement;
    }
};

// Returns false for malformed/truncated/coalesced PDUs; output remains
// unchanged on failure. Semantic ACK correlation and lifecycle transitions
// belong to the sole graphics owner, not to this stateless wire parser.
[[nodiscard]] bool parseGfxFrameAcknowledge(
    std::span<const std::byte> pdu,
    GfxFrameAcknowledgement &output) noexcept;

// The sole R4 graphics owner embeds one of these per active RDPGFX channel.
// This is ACK bookkeeping, NOT a competing frame scheduler or R3 DVC router.
// All methods run on that owner's event loop; channelGeneration is supplied
// by R3 provenance, not by untrusted on-wire frame IDs. Never reuse a
// generation for a different channel instance.
enum class GfxFrameAckWindowResult : std::uint8_t
{
    InvalidPdu,
    StaleGeneration,
    Acknowledged,
    Unmatched,
    Suspended,
};

class GfxFrameAckWindow final
{
public:
    static constexpr std::size_t kMaximumPendingFrames = 64U;

    // A zero generation deactivates the owner. Resize/reconnect must reset
    // this window using a different nonzero generation before accepting ACKs.
    void reset(std::uint64_t channelGeneration) noexcept;

    // Call ONLY once START_FRAME through END_FRAME is successfully submitted.
    // A full pending set denies publication; callers must defer the frame.
    // Suspended mode never waits for client ACKs and does not record IDs.
    // Check the ONE authoritative ACK window before dispatching an
    // already-encoded frame to R3. Reject duplicate and full IDs early.
    [[nodiscard]] bool canRecordFrame(
        std::uint64_t channelGeneration, std::uint32_t frameId) const noexcept;
    [[nodiscard]] bool noteFrameSent(std::uint64_t channelGeneration,
                                     std::uint32_t frameId) noexcept;

    // Consume a complete, already reassembled PDU from R3's authorized
    // channel, with its trusted channel generation. Invalid and stale PDUs
    // never mutate this window. An unmatched valid ACK is not cumulative.
    [[nodiscard]] GfxFrameAckWindowResult onFrameAcknowledge(
        std::uint64_t channelGeneration,
        std::span<const std::byte> pdu) noexcept;

    [[nodiscard]] std::size_t outstandingFrames() const noexcept
    {
        return pendingCount_;
    }
    [[nodiscard]] bool expectingAcknowledgements() const noexcept
    {
        return expectingAcknowledgements_;
    }
    // Zero means backlog is unknown, not zero queued bytes.
    [[nodiscard]] std::uint32_t clientQueueDepthBytes() const noexcept
    {
        return clientQueueDepthBytes_;
    }
    // Raw latest FRAME_ACKNOWLEDGE.totalFramesDecoded. Zero is a valid
    // observation, so availability is independent from the value.
    [[nodiscard]] bool clientTotalFramesDecodedAvailable() const noexcept
    {
        return clientTotalFramesDecodedAvailable_;
    }
    [[nodiscard]] std::uint32_t clientTotalFramesDecoded() const noexcept
    {
        return clientTotalFramesDecoded_;
    }

private:
    std::array<std::uint32_t, kMaximumPendingFrames> pendingFrames_{};
    std::uint64_t channelGeneration_{};
    std::size_t pendingCount_{};
    std::uint32_t clientQueueDepthBytes_{};
    std::uint32_t clientTotalFramesDecoded_{};
    bool expectingAcknowledgements_{};
    bool clientTotalFramesDecodedAvailable_{};
};

} // namespace rdp_server::rdp
