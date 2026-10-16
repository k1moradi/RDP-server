// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp/gfx_segmented_data.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

using namespace rdp_server::rdp;

namespace
{
std::uint16_t u16(std::span<const std::byte> b, std::size_t p)
{
    return static_cast<std::uint16_t>(std::to_integer<unsigned>(b[p]) |
        (std::to_integer<unsigned>(b[p + 1U]) << 8U));
}
std::uint32_t u32(std::span<const std::byte> b, std::size_t p)
{
    return static_cast<std::uint32_t>(u16(b, p)) |
           (static_cast<std::uint32_t>(u16(b, p + 2U)) << 16U);
}
void single()
{
    constexpr std::array<std::byte, 8> gfx{
        std::byte{0x0B}, {}, {}, {}, std::byte{8}, {}, {}, {}};
    std::array<std::byte, 16> out{}; out.fill(std::byte{0xA5});
    assert(gfxSegmentedDataBytes(gfx.size()) == 10);
    assert(buildGfxSegmentedData(gfx, out) == 10);
    assert(out[0] == std::byte{0xE0});
    assert(out[1] == std::byte{0x04});
    for (std::size_t i = 0; i < gfx.size(); ++i)
        assert(out[i + 2U] == gfx[i]);
    for (std::size_t i = 10; i < out.size(); ++i)
        assert(out[i] == std::byte{0xA5});

    std::array<std::byte, 16> same{}; same.fill(std::byte{0xCC});
    for (std::size_t i = 0; i < gfx.size(); ++i) same[i] = gfx[i];
    const auto in = std::span<const std::byte>(same).first(gfx.size());
    assert(buildGfxSegmentedData(in, same) == 10);
    assert(same[0] == std::byte{0xE0} && same[1] == std::byte{0x04});
    for (std::size_t i = 0; i < gfx.size(); ++i)
        assert(same[i + 2U] == gfx[i]);
}
void multipart()
{
    const std::size_t raw = kGfxRdp8MaximumRawSegmentBytes * 2U + 17U;
    std::vector<std::byte> input(raw);
    for (std::size_t i = 0; i < raw; ++i)
        input[i] = static_cast<std::byte>((i * 37U + 11U) & 0xFFU);
    const std::size_t required = gfxSegmentedDataBytes(raw);
    assert(required == 7U + raw + 3U * 5U);
    std::vector<std::byte> out(required + 9U, std::byte{0xA5});
    assert(buildGfxSegmentedData(input, out) == required);
    assert(out[0] == std::byte{0xE1});
    assert(u16(out, 1) == 3);
    assert(u32(out, 3) == raw);
    std::size_t sourceAt = 0, at = 7;
    for (std::size_t segment = 0; segment < 3; ++segment)
    {
        const std::size_t chunk = std::min(
            kGfxRdp8MaximumRawSegmentBytes, raw - sourceAt);
        assert(u32(out, at) == chunk + 1U);
        assert(out[at + 4U] == std::byte{0x04});
        for (std::size_t i = 0; i < chunk; ++i)
            assert(out[at + 5U + i] == input[sourceAt + i]);
        sourceAt += chunk;
        at += 5U + chunk;
    }
    assert(sourceAt == raw && at == required);
    for (std::size_t i = required; i < out.size(); ++i)
        assert(out[i] == std::byte{0xA5});
}
void denialsAndInPlaceMultipart()
{
    assert(gfxSegmentedDataBytes(0) == 0);
    if constexpr (sizeof(std::size_t) > sizeof(std::uint32_t))
        assert(gfxSegmentedDataBytes(
            static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()) + 1U) == 0);
    constexpr std::array<std::byte, 12> small{
        std::byte{1},std::byte{2},std::byte{3},std::byte{4},
        std::byte{5},std::byte{6},std::byte{7},std::byte{8},
        std::byte{9},std::byte{10},std::byte{11},std::byte{12}};
    std::array<std::byte, 32> out{}; out.fill(std::byte{0xDD});
    assert(buildGfxSegmentedData({}, out) == 0);
    for (auto b : out) assert(b == std::byte{0xDD});
    assert(buildGfxSegmentedData(small,
        std::span<std::byte>(out).first(13)) == 0);
    for (auto b : out) assert(b == std::byte{0xDD});
    for (std::size_t i = 0; i < small.size(); ++i) out[i] = small[i];
    auto before = out;
    assert(buildGfxSegmentedData(
        std::span<const std::byte>(out).first(small.size()),
        std::span<std::byte>(out).subspan(1)) == 0);
    assert(out == before);

    const std::size_t raw = kGfxRdp8MaximumRawSegmentBytes + 3U;
    const std::size_t required = gfxSegmentedDataBytes(raw);
    std::vector<std::byte> storage(required + 5U, std::byte{0xA5});
    std::vector<std::byte> expected(raw);
    for (std::size_t i = 0; i < raw; ++i)
    {
        expected[i] = static_cast<std::byte>((i * 13U + 9U) & 0xFFU);
        storage[i] = expected[i];
    }
    const auto input = std::span<const std::byte>(storage).first(raw);
    assert(buildGfxSegmentedData(input, storage) == required);
    assert(storage[0] == std::byte{0xE1} && u16(storage,1) == 2);
    std::size_t at = 7, src = 0;
    for (std::size_t s = 0; s < 2; ++s)
    {
        const std::size_t chunk = std::min(kGfxRdp8MaximumRawSegmentBytes,
                                           raw - src);
        assert(u32(storage,at) == chunk + 1U);
        assert(storage[at+4U] == std::byte{0x04});
        for (std::size_t i=0;i<chunk;++i)
            assert(storage[at+5U+i] == expected[src+i]);
        at += 5U + chunk; src += chunk;
    }
}
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    const std::string_view mode{argv[1]};
    if (mode == "segmented-data-single") { single(); return 0; }
    if (mode == "segmented-data-multipart") { multipart(); return 0; }
    if (mode == "segmented-data-denials-inplace") { denialsAndInPlaceMultipart(); return 0; }
    return 2;
}
