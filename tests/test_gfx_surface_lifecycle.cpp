// SPDX-License-Identifier: GPL-3.0-or-later

#include "rdp/gfx_surface_lifecycle.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <initializer_list>
#include <span>
#include <string_view>

namespace
{
using rdp_server::rdp::GfxCreateSurfaceCommand;
using rdp_server::rdp::GfxMapSurfaceToOutputCommand;
using rdp_server::rdp::buildGfxCreateSurfaceCommand;
using rdp_server::rdp::buildGfxDeleteSurfaceCommand;
using rdp_server::rdp::buildGfxMapSurfaceToOutputCommand;

constexpr std::byte kCanary{0xA5};

template <std::size_t Capacity>
void expectUnmodified(const std::array<std::byte, Capacity> &output)
{
    for (const std::byte value : output)
    {
        assert(value == kCanary);
    }
}

void testWire()
{
    std::array<std::byte, 24> output{};
    output.fill(kCanary);
    assert(buildGfxCreateSurfaceCommand({0x1234, {1920, 1080}}, output) == 15);
    constexpr std::array<std::byte, 15> expectedCreate{
        std::byte{0x09}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x0F}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x34}, std::byte{0x12}, std::byte{0x80}, std::byte{0x07},
        std::byte{0x38}, std::byte{0x04}, std::byte{0x20}};
    for (std::size_t index = 0; index < expectedCreate.size(); ++index)
    {
        assert(output[index] == expectedCreate[index]);
    }
    for (std::size_t index = expectedCreate.size(); index < output.size(); ++index)
    {
        assert(output[index] == kCanary);
    }

    output.fill(kCanary);
    assert(buildGfxMapSurfaceToOutputCommand(
               {0x1234, 0x11223344, 0x55667788}, output) == 20);
    constexpr std::array<std::byte, 20> expectedMap{
        std::byte{0x0F}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x14}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x34}, std::byte{0x12}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x44}, std::byte{0x33}, std::byte{0x22}, std::byte{0x11},
        std::byte{0x88}, std::byte{0x77}, std::byte{0x66}, std::byte{0x55}};
    for (std::size_t index = 0; index < expectedMap.size(); ++index)
    {
        assert(output[index] == expectedMap[index]);
    }
    for (std::size_t index = expectedMap.size(); index < output.size(); ++index)
    {
        assert(output[index] == kCanary);
    }

    output.fill(kCanary);
    assert(buildGfxDeleteSurfaceCommand(0x1234, output) == 10);
    constexpr std::array<std::byte, 10> expectedDelete{
        std::byte{0x0A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x0A}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x34}, std::byte{0x12}};
    for (std::size_t index = 0; index < expectedDelete.size(); ++index)
    {
        assert(output[index] == expectedDelete[index]);
    }
    for (std::size_t index = expectedDelete.size(); index < output.size(); ++index)
    {
        assert(output[index] == kCanary);
    }

    // Geometry limits are 16-bit on the wire; largest legal dimensions and
    // surface IDs remain representable, even before codec-specific alignment.
    output.fill(kCanary);
    assert(buildGfxCreateSurfaceCommand(
               {std::numeric_limits<std::uint16_t>::max(), {65535, 65535}},
               output) == 15);
    assert(output[8] == std::byte{0xFF});
    assert(output[10] == std::byte{0xFF});
    assert(output[12] == std::byte{0xFF});
}


void testZeroSurfaceIdWire()
{
    std::array<std::byte, 24> output{};

    output.fill(kCanary);
    assert(buildGfxCreateSurfaceCommand({0, {640, 480}}, output) == 15);
    assert(output[8] == std::byte{} && output[9] == std::byte{});

    output.fill(kCanary);
    assert(buildGfxMapSurfaceToOutputCommand({0, 11, 13}, output) == 20);
    assert(output[8] == std::byte{} && output[9] == std::byte{});

    output.fill(kCanary);
    assert(buildGfxDeleteSurfaceCommand(0, output) == 10);
    assert(output[8] == std::byte{} && output[9] == std::byte{});
}

void testRejections()
{
    std::array<std::byte, 24> output{};
    for (const PixelSize invalidGeometry : {
             PixelSize{0, 1080}, PixelSize{1920, 0},
             PixelSize{65536, 1080}, PixelSize{1920, 65536},
             PixelSize{std::numeric_limits<std::uint32_t>::max(), 2}})
    {
        output.fill(kCanary);
        assert(buildGfxCreateSurfaceCommand({1, invalidGeometry}, output) == 0);
        expectUnmodified(output);
    }

    // Even one-byte-short buffers must be atomic: no partial PDU writes.
    for (std::size_t capacity = 0; capacity < 15; ++capacity)
    {
        output.fill(kCanary);
        assert(buildGfxCreateSurfaceCommand(
                   {1, {1920, 1080}}, std::span<std::byte>{output}.first(capacity)) == 0);
        expectUnmodified(output);
    }
    for (std::size_t capacity = 0; capacity < 20; ++capacity)
    {
        output.fill(kCanary);
        assert(buildGfxMapSurfaceToOutputCommand(
                   {1, 0, 0}, std::span<std::byte>{output}.first(capacity)) == 0);
        expectUnmodified(output);
    }
    for (std::size_t capacity = 0; capacity < 10; ++capacity)
    {
        output.fill(kCanary);
        assert(buildGfxDeleteSurfaceCommand(1, std::span<std::byte>{output}.first(capacity)) == 0);
        expectUnmodified(output);
    }
    output.fill(kCanary);
    assert(buildGfxCreateSurfaceCommand({1, {1920, 1080}}, {}) == 0);
    assert(buildGfxMapSurfaceToOutputCommand({1, 0, 0}, {}) == 0);
    assert(buildGfxDeleteSurfaceCommand(1, {}) == 0);
    expectUnmodified(output);
}
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        return 1;
    }
    const std::string_view behavior{argv[1]};
    if (behavior == "surface-lifecycle-wire")
    {
        testWire();
        return 0;
    }
    if (behavior == "surface-zero-id-wire")
    {
        testZeroSurfaceIdWire();
        return 0;
    }
    if (behavior == "surface-lifecycle-rejections")
    {
        testRejections();
        return 0;
    }
    return 1;
}
