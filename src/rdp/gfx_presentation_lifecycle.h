// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "gfx_avc420_capabilities.h"
#include "gfx_avc420_picture.h"
#include "gfx_frame_acknowledge.h"
#include "gfx_surface_lifecycle.h"

namespace rdp_server::rdp
{

// R4-side graphics presentation sequencing, NOT an R3 channel or session.
// Only R3's authenticated, admitted graphics-channel owner may call open().
// A channel token is not independently verified by this offline component.
// It exposes no transport, encoder, scheduler, or way to publish live pixels.
enum class GfxPresentationStage : std::uint8_t
{
    Inactive,
    AwaitCapabilities,
    ConfirmReady,
    ConfirmInFlight,
    SurfaceUnconfigured,
    CreateReady,
    CreateInFlight,
    MapReady,
    MapInFlight,
    Mapped,
    DeleteReady,
    DeleteInFlight,
    Rejected,
};

enum class GfxPresentationCommand : std::uint8_t
{
    Confirm,
    Create,
    Map,
    Delete,
};

// A receipt belongs to exactly one R3 outbound *full-PDU delivery*.
// Partial write progress is tracked by R3; a partial receipt cannot advance
// R4 state. Never create a receipt from wire-controlled fields.
struct GfxPresentationReceipt final
{
    std::uint64_t generation{};
    std::uint64_t serial{};
    GfxPresentationCommand command{};
    std::size_t bytes{};

    friend bool operator==(const GfxPresentationReceipt &,
                           const GfxPresentationReceipt &) = default;
};

// R3-owned full START_FRAME..END_FRAME send completion, never an
// encoder result or partial transport-write progress.
struct GfxFrameDeliveryReceipt final
{
    std::uint64_t generation{};
    std::uint64_t serial{};
    std::uint32_t frameId{};
    std::size_t bytes{};
    friend bool operator==(const GfxFrameDeliveryReceipt &,
                           const GfxFrameDeliveryReceipt &) = default;
};

class GfxPresentationLifecycle final
{
public:
    // R3 calls only after authenticated session + graphics DVC admission.
    // New channel generations MUST be unique and monotonically increasing.
    [[nodiscard]] bool open(std::uint64_t authorizedGeneration) noexcept;
    // Closing/resetting invalidates every pending output receipt and ACK.
    void disconnect() noexcept;

    [[nodiscard]] bool acceptCapabilities(
        std::uint64_t generation,
        std::span<const std::byte> advertisement) noexcept;
    // Configure exactly one AVC420-compatible even-size surface per mapping.
    // surfaceId spans the full MS-RDPEGFX u16 domain, including zero; stage_
    // carries configured/unconfigured state and must not be inferred from ID.
    [[nodiscard]] bool configureSurface(
        std::uint64_t generation, std::uint16_t surfaceId,
        PixelSize geometry, std::uint32_t originX = 0,
        std::uint32_t originY = 0) noexcept;
    // Serialize one eligible command into caller-owned output. The source
    // buffer and outbound lifetime belong to R3; never mark delivery here.
    [[nodiscard]] bool prepareCommand(
        std::uint64_t generation, std::span<std::byte> output,
        GfxPresentationReceipt &receipt) noexcept;
    // R3 calls only after the complete corresponding DVC PDU is delivered.
    [[nodiscard]] bool completeCommand(
        const GfxPresentationReceipt &receipt,
        std::size_t deliveredBytes) noexcept;
    // Requires a mapped surface; DELETE must be completed before reuse.
    [[nodiscard]] bool requestSurfaceDelete(std::uint64_t generation) noexcept;

    [[nodiscard]] bool canSubmitFrame(std::uint64_t generation) const noexcept;
    // Also preflight the actual frame ID and receipt serial before stateful
    // encoding. Uses the one authoritative ACK window; it reserves nothing.
    // The R4 event-thread owner must serialize this check with publication.
    [[nodiscard]] bool canReserveFrame(
        std::uint64_t generation, std::uint32_t frameId) const noexcept;
    // Reserve exactly one outbound complete frame at a time; no ACK yet.
    [[nodiscard]] bool beginFrameDelivery(
        std::uint64_t generation, std::uint32_t frameId,
        std::size_t frameBytes, GfxFrameDeliveryReceipt &receipt) noexcept;
    // Serialize one already-encoded AVC420 picture for THIS mapped surface,
    // and reserve the existing full-frame delivery receipt. No transport,
    // x264 encoding, session authorization or ACK publication occurs here.
    // On rejection neither caller output nor receipt/state is changed.
    [[nodiscard]] bool prepareAvc420Picture(
        std::uint64_t generation, const GfxAvc420Picture &picture,
        std::span<std::byte> output, GfxFrameDeliveryReceipt &receipt) noexcept;
    // R3 MUST call only after the whole matching frame has been sent.
    [[nodiscard]] bool completeFrameDelivery(
        const GfxFrameDeliveryReceipt &receipt,
        std::size_t deliveredBytes) noexcept;
    // Terminal/partial send failure revokes the generation and surface.
    [[nodiscard]] bool abortFrameDelivery(
        const GfxFrameDeliveryReceipt &receipt) noexcept;
    // Only accept ACKs on R3's admitted generation with mapped surface.
    [[nodiscard]] bool onFrameAcknowledge(
        std::uint64_t generation, std::span<const std::byte> pdu,
        GfxFrameAckWindowResult &result) noexcept;

    [[nodiscard]] GfxPresentationStage stage() const noexcept { return stage_; }
    [[nodiscard]] std::size_t outstandingFrames() const noexcept
    {
        return acknowledgements_.outstandingFrames();
    }
    [[nodiscard]] std::uint16_t surfaceId() const noexcept { return surfaceId_; }

private:
    [[nodiscard]] bool active(std::uint64_t generation) const noexcept;

    GfxPresentationStage stage_{GfxPresentationStage::Inactive};
    GfxFrameAckWindow acknowledgements_{};
    std::array<std::byte, 20> confirmation_{};
    std::uint64_t generation_{};
    std::uint64_t latestGeneration_{};
    std::uint64_t lastSerial_{};
    GfxPresentationReceipt pending_{};
    GfxFrameDeliveryReceipt pendingFrame_{};
    std::uint16_t surfaceId_{};
    PixelSize geometry_{};
    std::uint32_t originX_{};
    std::uint32_t originY_{};
};

} // namespace rdp_server::rdp
