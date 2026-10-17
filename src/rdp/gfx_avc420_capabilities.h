// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::rdp
{

inline constexpr std::uint32_t kGfxCapabilityVersion8 = 0x00080004U;
inline constexpr std::uint32_t kGfxCapabilityVersion81 = 0x00080105U;

enum class GfxCapabilityNegotiationStatus
{
    Accepted,
    MalformedAdvertisement,
    UnsupportedCapability,
};

// Keep the historical R4 AVC420 status name source-compatible.
using GfxAvc420NegotiationStatus = GfxCapabilityNegotiationStatus;

// MS-RDPEGFX CAPS_ADVERTISE/CAPS_CONFIRM selection for the profiles R4 can
// actually implement. ClearCodec is mandatory for the Graphics Pipeline
// Extension and is available for every accepted profile. AVC420 is optional
// and true only when the selected VERSION81 set explicitly enables it.
struct GfxCapabilityNegotiationResult final
{
    GfxCapabilityNegotiationStatus status{
        GfxCapabilityNegotiationStatus::MalformedAdvertisement};
    std::array<std::byte, 20> confirmation{};
    std::size_t confirmationBytes{};
    std::uint32_t selectedVersion{};
    std::uint32_t selectedFlags{};
    bool avc420Enabled{};

    [[nodiscard]] bool accepted() const noexcept
    {
        return status == GfxCapabilityNegotiationStatus::Accepted;
    }
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
// R4 currently supports VERSION8 and VERSION81. The highest supported
// advertised set is confirmed; newer sets are not inferred as supported.
// A caller MUST NOT transmit graphics before confirmation is delivered.
[[nodiscard]] GfxCapabilityNegotiationResult
negotiateGfxCapabilities(
    std::span<const std::byte> advertisement) noexcept;

// Historical AVC420-only query retained for the existing encoder path. It
// succeeds only when generic negotiation selects VERSION81 with the explicit
// AVC420_ENABLED flag. ClearCodec-only capability sets remain unsupported here.
[[nodiscard]] GfxAvc420NegotiationResult
negotiateGfxAvc420(
    std::span<const std::byte> advertisement) noexcept;

} // namespace rdp_server::rdp
