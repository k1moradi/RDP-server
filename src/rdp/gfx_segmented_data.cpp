// SPDX-License-Identifier: GPL-3.0-or-later
#include "gfx_segmented_data.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace rdp_server::rdp
{
namespace
{
constexpr std::byte kSingle{0xE0};
constexpr std::byte kMultipart{0xE1};
constexpr std::byte kRdp8Uncompressed{0x04};
constexpr std::size_t kMultipartHeaderBytes = 7U;
constexpr std::size_t kSegmentHeaderBytes = 5U; // uint32 size + RDP8 header

void write16(std::span<std::byte> out, std::size_t at,
             std::uint16_t value) noexcept
{
    out[at] = static_cast<std::byte>(value);
    out[at + 1U] = static_cast<std::byte>(value >> 8U);
}
void write32(std::span<std::byte> out, std::size_t at,
             std::uint32_t value) noexcept
{
    write16(out, at, static_cast<std::uint16_t>(value));
    write16(out, at + 2U, static_cast<std::uint16_t>(value >> 16U));
}
[[nodiscard]] std::size_t segmentCount(std::size_t bytes) noexcept
{
    // Avoid add-before-divide ceil arithmetic: a protocol-sized payload may
    // equal SIZE_MAX on supported 32-bit builds.
    return bytes / kGfxRdp8MaximumRawSegmentBytes +
           (bytes % kGfxRdp8MaximumRawSegmentBytes != 0U ? 1U : 0U);
}
[[nodiscard]] bool partiallyOverlaps(std::span<const std::byte> input,
                                     std::span<std::byte> output) noexcept
{
    if (input.empty() || output.empty() || input.data() == output.data())
        return false;
    const auto in = reinterpret_cast<std::uintptr_t>(input.data());
    const auto out = reinterpret_cast<std::uintptr_t>(output.data());
    if (input.size() > std::numeric_limits<std::uintptr_t>::max() - in ||
        output.size() > std::numeric_limits<std::uintptr_t>::max() - out)
        return true;
    return in < out + output.size() && out < in + input.size();
}
} // namespace

std::size_t gfxSegmentedDataBytes(std::size_t graphicsBytes) noexcept
{
    if (graphicsBytes == 0 ||
        graphicsBytes > std::numeric_limits<std::uint32_t>::max())
        return 0;
    if (graphicsBytes <= kGfxRdp8MaximumRawSegmentBytes)
        return graphicsBytes + 2U; // SINGLE descriptor + RDP8 header.
    const std::size_t count = segmentCount(graphicsBytes);
    if (count > std::numeric_limits<std::uint16_t>::max())
        return 0;
    constexpr std::size_t maximumSize =
        std::numeric_limits<std::size_t>::max();
    if (graphicsBytes > maximumSize - kMultipartHeaderBytes)
        return 0;
    const std::size_t remainingBytes =
        maximumSize - kMultipartHeaderBytes - graphicsBytes;
    if (count > remainingBytes / kSegmentHeaderBytes)
        return 0;
    return kMultipartHeaderBytes + graphicsBytes +
           count * kSegmentHeaderBytes;
}

std::size_t buildGfxSegmentedData(
    std::span<const std::byte> graphicsMessages,
    std::span<std::byte> output) noexcept
{
    const std::size_t required = gfxSegmentedDataBytes(graphicsMessages.size());
    if (required == 0 || output.size() < required ||
        partiallyOverlaps(graphicsMessages, output))
        return 0;

    if (graphicsMessages.size() <= kGfxRdp8MaximumRawSegmentBytes)
    {
        std::memmove(output.data() + 2U, graphicsMessages.data(),
                     graphicsMessages.size());
        output[0] = kSingle;
        output[1] = kRdp8Uncompressed;
        return required;
    }

    const std::size_t count = segmentCount(graphicsMessages.size());
    // Copy from the final segment toward the first so exact in-place
    // expansion never overwrites source bytes that have not moved yet.
    for (std::size_t index = count; index-- > 0;)
    {
        const std::size_t sourceAt = index * kGfxRdp8MaximumRawSegmentBytes;
        const std::size_t chunk = std::min(
            kGfxRdp8MaximumRawSegmentBytes,
            graphicsMessages.size() - sourceAt);
        const std::size_t destHeader = kMultipartHeaderBytes +
            index * (kSegmentHeaderBytes + kGfxRdp8MaximumRawSegmentBytes);
        std::memmove(output.data() + destHeader + kSegmentHeaderBytes,
                     graphicsMessages.data() + sourceAt, chunk);
        write32(output, destHeader, static_cast<std::uint32_t>(chunk + 1U));
        output[destHeader + 4U] = kRdp8Uncompressed;
    }
    output[0] = kMultipart;
    write16(output, 1U, static_cast<std::uint16_t>(count));
    write32(output, 3U, static_cast<std::uint32_t>(graphicsMessages.size()));
    return required;
}

} // namespace rdp_server::rdp
