// SPDX-License-Identifier: GPL-3.0-or-later

#include "gfx_surface_lifecycle.h"

#include <limits>

namespace rdp_server::rdp
{
namespace
{
constexpr std::uint16_t kCreateSurfaceCommand = 0x0009;
constexpr std::uint16_t kDeleteSurfaceCommand = 0x000A;
constexpr std::uint16_t kMapSurfaceToOutputCommand = 0x000F;
constexpr std::uint8_t kXrgb8888PixelFormat = 0x20;
constexpr std::size_t kCreateSurfaceBytes = 15;
constexpr std::size_t kDeleteSurfaceBytes = 10;
constexpr std::size_t kMapSurfaceToOutputBytes = 20;

// Only called after output.size() was checked against the complete PDU.
void writeU16(std::span<std::byte> output, std::size_t offset,
              std::uint16_t value) noexcept
{
    output[offset] = static_cast<std::byte>(value);
    output[offset + 1U] = static_cast<std::byte>(value >> 8U);
}

void writeU32(std::span<std::byte> output, std::size_t offset,
              std::uint32_t value) noexcept
{
    writeU16(output, offset, static_cast<std::uint16_t>(value));
    writeU16(output, offset + 2U, static_cast<std::uint16_t>(value >> 16U));
}

void writeHeader(std::span<std::byte> output,
                 std::uint16_t commandId,
                 std::uint32_t commandBytes) noexcept
{
    writeU16(output, 0U, commandId);
    writeU16(output, 2U, 0U); // RDPGFX_HEADER.flags MUST be zero.
    writeU32(output, 4U, commandBytes);
}
} // namespace

std::size_t buildGfxCreateSurfaceCommand(
    const GfxCreateSurfaceCommand &command,
    std::span<std::byte> output) noexcept
{
    if (output.size() < kCreateSurfaceBytes ||
        command.geometry.widthPixels == 0 ||
        command.geometry.heightPixels == 0 ||
        command.geometry.widthPixels > std::numeric_limits<std::uint16_t>::max() ||
        command.geometry.heightPixels > std::numeric_limits<std::uint16_t>::max())
    {
        return 0;
    }

    writeHeader(output, kCreateSurfaceCommand, kCreateSurfaceBytes);
    writeU16(output, 8U, command.surfaceId);
    writeU16(output, 10U,
             static_cast<std::uint16_t>(command.geometry.widthPixels));
    writeU16(output, 12U,
             static_cast<std::uint16_t>(command.geometry.heightPixels));
    output[14U] = static_cast<std::byte>(kXrgb8888PixelFormat);
    return kCreateSurfaceBytes;
}

std::size_t buildGfxMapSurfaceToOutputCommand(
    const GfxMapSurfaceToOutputCommand &command,
    std::span<std::byte> output) noexcept
{
    if (output.size() < kMapSurfaceToOutputBytes)
    {
        return 0;
    }

    writeHeader(output, kMapSurfaceToOutputCommand, kMapSurfaceToOutputBytes);
    writeU16(output, 8U, command.surfaceId);
    writeU16(output, 10U, 0U); // Reserved MUST be zero.
    writeU32(output, 12U, command.outputOriginX);
    writeU32(output, 16U, command.outputOriginY);
    return kMapSurfaceToOutputBytes;
}

std::size_t buildGfxDeleteSurfaceCommand(
    std::uint16_t surfaceId, std::span<std::byte> output) noexcept
{
    if (output.size() < kDeleteSurfaceBytes)
    {
        return 0;
    }

    writeHeader(output, kDeleteSurfaceCommand, kDeleteSurfaceBytes);
    writeU16(output, 8U, surfaceId);
    return kDeleteSurfaceBytes;
}

} // namespace rdp_server::rdp
