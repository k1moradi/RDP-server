// SPDX-License-Identifier: GPL-3.0-or-later

#include "gfx_avc420_capabilities.h"

#include <cstddef>
#include <cstdint>

namespace rdp_server::rdp
{
namespace
{
// MS-RDPEGFX 2.2.1.5, 2.2.1.6, 2.2.3.2, and 2.2.2.18/19.
constexpr std::uint16_t kCapsAdvertiseCommand = 0x0012;
constexpr std::uint16_t kCapsConfirmCommand = 0x0013;
constexpr std::uint32_t kCapVersion81 = 0x00080105;
constexpr std::uint32_t kAvc420Enabled = 0x00000010;
constexpr std::uint32_t kVersion81KnownFlags = 0x00000013;
constexpr std::size_t kGraphicsHeaderBytes = 8;
constexpr std::size_t kCapabilityHeaderBytes = 8;
constexpr std::size_t kCapabilityFlagsBytes = 4;
constexpr std::size_t kAdvertiseHeaderBytes = kGraphicsHeaderBytes + 2;
constexpr std::size_t kMaximumCapsAdvertisementBytes = 64 * 1024;

[[nodiscard]] std::uint16_t readU16(std::span<const std::byte> input,
                                    std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>(
        std::to_integer<std::uint8_t>(input[offset]) |
        (std::uint16_t{std::to_integer<std::uint8_t>(input[offset + 1])} << 8));
}

[[nodiscard]] std::uint32_t readU32(std::span<const std::byte> input,
                                    std::size_t offset) noexcept
{
    return static_cast<std::uint32_t>(readU16(input, offset)) |
           (static_cast<std::uint32_t>(readU16(input, offset + 2)) << 16);
}

void writeU16(std::span<std::byte> output, std::size_t offset,
              std::uint16_t value) noexcept
{
    output[offset] = static_cast<std::byte>(value);
    output[offset + 1] = static_cast<std::byte>(value >> 8);
}

void writeU32(std::span<std::byte> output, std::size_t offset,
              std::uint32_t value) noexcept
{
    writeU16(output, offset, static_cast<std::uint16_t>(value));
    writeU16(output, offset + 2, static_cast<std::uint16_t>(value >> 16));
}
} // namespace

GfxAvc420NegotiationResult
negotiateGfxAvc420(std::span<const std::byte> advertisement) noexcept
{
    GfxAvc420NegotiationResult result{};
    if (advertisement.size() < kAdvertiseHeaderBytes ||
        advertisement.size() > kMaximumCapsAdvertisementBytes ||
        readU16(advertisement, 0) != kCapsAdvertiseCommand ||
        readU16(advertisement, 2) != 0 ||
        readU32(advertisement, 4) != advertisement.size())
    {
        return result;
    }

    const std::size_t capabilityCount = readU16(advertisement, 8);
    std::size_t offset = kAdvertiseHeaderBytes;
    if (capabilityCount > (advertisement.size() - offset) /
                              kCapabilityHeaderBytes)
    {
        return result;
    }

    bool version81Seen = false;
    bool avc420Supported = false;
    std::uint32_t confirmedFlags = 0;
    for (std::size_t capability = 0; capability < capabilityCount; ++capability)
    {
        // A preceding variable-length capability may consume bytes reserved
        // for subsequent headers. Check each header before reading it.
        // offset is always <= size after the preceding dataLength check.
        if (advertisement.size() - offset < kCapabilityHeaderBytes)
        {
            return result;
        }
        const std::uint32_t version = readU32(advertisement, offset);
        const std::uint32_t dataLength = readU32(advertisement, offset + 4);
        offset += kCapabilityHeaderBytes;
        // Subtraction after proving offset <= size avoids malicious-length
        // overflow and any out-of-bounds span access.
        if (dataLength > advertisement.size() - offset)
        {
            return result;
        }

        if (version == kCapVersion81)
        {
            if (version81Seen || dataLength != kCapabilityFlagsBytes)
            {
                return result;
            }
            version81Seen = true;
            const std::uint32_t advertisedFlags = readU32(advertisement, offset);
            // Unknown flags cannot be echoed or treated as supported. Newer
            // capability versions are intentionally not inferred as AVC420.
            if ((advertisedFlags & ~kVersion81KnownFlags) == 0 &&
                (advertisedFlags & kAvc420Enabled) != 0)
            {
                avc420Supported = true;
                confirmedFlags = advertisedFlags;
            }
        }
        offset += dataLength;
    }
    if (offset != advertisement.size())
    {
        return result;
    }
    if (!avc420Supported)
    {
        result.status = GfxAvc420NegotiationStatus::UnsupportedCapability;
        return result;
    }

    // The 20-byte CAPS_CONFIRM contains exactly one 12-byte CAPSET_VERSION81.
    // No codec other than explicitly negotiated AVC420 is enabled here.
    std::span<std::byte> confirmation{result.confirmation};
    writeU16(confirmation, 0, kCapsConfirmCommand);
    writeU16(confirmation, 2, 0);
    writeU32(confirmation, 4, static_cast<std::uint32_t>(confirmation.size()));
    writeU32(confirmation, 8, kCapVersion81);
    writeU32(confirmation, 12, kCapabilityFlagsBytes);
    writeU32(confirmation, 16, confirmedFlags);
    result.confirmationBytes = confirmation.size();
    result.status = GfxAvc420NegotiationStatus::Accepted;
    return result;
}

} // namespace rdp_server::rdp
