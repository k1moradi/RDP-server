// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../core/geometry.h"
#include "../core/rectangle.h"

namespace rdp_server::rdp
{

// MS-RDPEGFX 2.2.4.4.2. Each RFX_AVC420_METABLOCK region has one
// 2-byte quantization/quality entry. Reserved qp bit MUST be zero.
// Quantization is encoder-owned; these bytes do not validate the picture.
struct GfxAvc420QuantQuality final
{
    std::uint8_t qp{};       // 0..51 (6 bits), with no progressive flag.
    std::uint8_t quality{};  // 0..100
};

struct GfxAvc420Picture final
{
    std::uint16_t surfaceId{};
    std::uint32_t frameId{};
    // Coded picture size, multiple of 16 in each dimension. Regions are
    // actual visible rectangles cropped from that coded picture.
    PixelSize codedGeometry{};
    std::span<const Rectangle> regions{};
    std::span<const GfxAvc420QuantQuality> quantQualities{};
    // Borrowed x264 H.264 Annex-B picture; not encoded by this helper.
    std::span<const std::byte> annexBPicture{};
    // Actual visible RDPGFX surface, distinct from 16-aligned H.264
    // codedGeometry. Both zero defaults to codedGeometry (legacy API).
    PixelSize visibleGeometry{};
};

inline constexpr std::size_t kGfxMaximumAnnexBPictureBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kGfxMaximumAvc420Regions = 4096U;

// Encodes START_FRAME + WIRE_TO_SURFACE_1(AVC420) + END_FRAME with
// one real caller-supplied Annex-B bitstream, without allocating.
// Return 0 for malformed geometry, regions, quant values, invalid
// Annex-B prefix, length overflow or insufficient output capacity.
// Failure leaves output and its suffix untouched. The caller must
// provide one genuine x264 picture and R3 must authorize and transmit
// the whole sequence. This is not an H.264 decoder or session owner.
// Align an actual surface up to 16-pixel H.264 macroblocks without
// allowing a coded dimension beyond the 16-bit RDPGFX coordinate range.
[[nodiscard]] PixelSize gfxAvc420CodedGeometry(PixelSize visible) noexcept;

[[nodiscard]] std::size_t gfxAvc420PictureBytes(
    std::size_t regionCount, std::size_t annexBBytes) noexcept;

// Validate all deterministic AVC420 envelope metadata without inspecting an
// encoded bitstream. R4 uses this before stateful encode so malformed
// surface/frame/geometry/region/quant fields cannot advance codec references.
[[nodiscard]] bool gfxAvc420PictureMetadataValid(
    const GfxAvc420Picture &picture) noexcept;

[[nodiscard]] std::size_t buildGfxAvc420Picture(
    const GfxAvc420Picture &picture, std::span<std::byte> output) noexcept;

} // namespace rdp_server::rdp
