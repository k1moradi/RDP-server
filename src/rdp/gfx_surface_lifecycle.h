// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../core/geometry.h"

namespace rdp_server::rdp
{

// One fully reassembled RDPGFX command per call. These stateless builders
// never authorize an RDPGFX channel, create client-side state, or schedule
// frames. The R4 graphics owner must confirm capabilities and send CREATE,
// MAP, and DELETE in order through the channel authorized by R3.
struct GfxCreateSurfaceCommand final
{
    std::uint16_t surfaceId{};
    PixelSize geometry{};
};

struct GfxMapSurfaceToOutputCommand final
{
    std::uint16_t surfaceId{};
    std::uint32_t outputOriginX{};
    std::uint32_t outputOriginY{};
};

// MS-RDPEGFX 2.2.2.9: 8-byte header + 7-byte surface description.
// This first AVC420 path creates XRGB8888 client surfaces only.
// Return the exact written byte count, or zero without modifying output on
// invalid dimensions or insufficient capacity. Tail bytes remain unchanged.
[[nodiscard]] std::size_t buildGfxCreateSurfaceCommand(
    const GfxCreateSurfaceCommand &command,
    std::span<std::byte> output) noexcept;

// MS-RDPEGFX 2.2.2.15: 8-byte header + 12-byte mapping.
[[nodiscard]] std::size_t buildGfxMapSurfaceToOutputCommand(
    const GfxMapSurfaceToOutputCommand &command,
    std::span<std::byte> output) noexcept;

// MS-RDPEGFX 2.2.2.10: 8-byte header + 2-byte surface ID.
[[nodiscard]] std::size_t buildGfxDeleteSurfaceCommand(
    std::uint16_t surfaceId, std::span<std::byte> output) noexcept;

} // namespace rdp_server::rdp
