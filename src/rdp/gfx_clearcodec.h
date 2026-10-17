// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "../core/framebuffer_view.h"

namespace rdp_server::rdp
{

// One full-surface ClearCodec fallback frame. FramebufferView is borrowed only
// while buildGfxClearCodecFrame() runs. Pixels are top-left row-major
// B,G,R,ignored-alpha with caller-supplied pitch; no native memory is retained.
struct GfxClearCodecFrameRequest final
{
    std::uint16_t surfaceId{};
    std::uint32_t frameId{};
    FramebufferView framebuffer{};
};

// Size of START_FRAME + WIRE_TO_SURFACE_1(ClearCodec) + END_FRAME using the
// mandatory ClearCodec residual layer only. Returns zero for invalid layout,
// unrepresentable protocol lengths or dimensions outside ClearCodec's u16 range.
[[nodiscard]] std::size_t gfxClearCodecFrameBytes(
    const GfxClearCodecFrameRequest &request) noexcept;

// Encode an allocation-free, lossless ClearCodec residual stream. Each source
// pixel is emitted as one legal RGB run of length one; bands, subcodecs and
// glyph caches are intentionally unused. sequenceNumber belongs to the
// presentation lifecycle and advances only after complete delivery.
// Source/output overlap is rejected before mutation.
[[nodiscard]] std::size_t buildGfxClearCodecFrame(
    const GfxClearCodecFrameRequest &request,
    std::uint8_t sequenceNumber,
    std::span<std::byte> output) noexcept;

} // namespace rdp_server::rdp
