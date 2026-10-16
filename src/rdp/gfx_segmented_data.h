// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <span>

namespace rdp_server::rdp
{

// MS-RDPEGFX 2.2.5.1/.2/.3. RDP8 bulk decompression produces at most
// 65,535 uncompressed bytes per standard segment. We intentionally emit
// uncompressed RDP8 segments (type 0x04, PACKET_COMPRESSED clear) first;
// compression can be added without changing the graphics-message owner.
inline constexpr std::size_t kGfxRdp8MaximumRawSegmentBytes = 65'535U;

// Number of bytes needed to wrap one or more complete server-to-client
// RDPGFX messages in one RDP_SEGMENTED_DATA structure. Returns zero for
// an empty/too-large payload or an unrepresentable segment count.
[[nodiscard]] std::size_t gfxSegmentedDataBytes(
    std::size_t graphicsBytes) noexcept;

// Wrap an opaque sequence of already-complete RDPGFX messages in one
// RDP_SEGMENTED_DATA structure using uncompressed RDP8 bulk segments.
// <=65,535 bytes uses SINGLE; larger payloads use MULTIPART. Failure is
// atomic. Exact in-place expansion (payload.data()==output.data()) is
// supported; other partially overlapping spans are rejected.
// R3 still owns the authoritative DRDYNVC channel and its fragmentation.
[[nodiscard]] std::size_t buildGfxSegmentedData(
    std::span<const std::byte> graphicsMessages,
    std::span<std::byte> output) noexcept;

} // namespace rdp_server::rdp
