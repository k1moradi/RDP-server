// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::rdp
{

// MS-RDPEGFX 2.2.2.18/19. The returned confirmation is a complete graphics
// command PDU; R3 owns any DVC fragmentation and the channel lifetime.
enum class GfxAvc420NegotiationStatus
{
    Accepted,
    MalformedAdvertisement,
    UnsupportedCapability,
};

struct GfxAvc420NegotiationResult final
{
    GfxAvc420NegotiationStatus status{
        GfxAvc420NegotiationStatus::MalformedAdvertisement};
    std::array<std::byte, 20> confirmation{};
    std::size_t confirmationBytes{};

    [[nodiscard]] bool accepted() const noexcept
    {
        return status == GfxAvc420NegotiationStatus::Accepted;
    }
};

// Parses exactly one complete CAPS_ADVERTISE command (not a DVC fragment).
// Stateless and allocation-free; safe to invoke from the R3 session thread.
// The only supported profile is MS-RDPEGFX version 8.1 with explicit AVC420.
// A caller MUST NOT transmit graphics before confirmation is delivered.
[[nodiscard]] GfxAvc420NegotiationResult
negotiateGfxAvc420(std::span<const std::byte> advertisement) noexcept;

} // namespace rdp_server::rdp
