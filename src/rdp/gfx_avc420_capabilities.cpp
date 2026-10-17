// SPDX-License-Identifier: GPL-3.0-or-later

#include "gfx_avc420_capabilities.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace rdp_server::rdp
{
namespace
{
// MS-RDPEGFX 2.2.1.5/.6, 2.2.2.18/.19 and 2.2.3.1/.2.
constexpr std::uint16_t kCapsAdvertiseCommand = 0x0012U;
constexpr std::uint16_t kCapsConfirmCommand = 0x0013U;
constexpr std::uint32_t kAvc420Enabled = 0x00000010U;
constexpr std::uint32_t kVersion8KnownFlags = 0x00000003U;
constexpr std::uint32_t kVersion81KnownFlags = 0x00000013U;
constexpr std::size_t kGraphicsHeaderBytes = 8U;
constexpr std::size_t kCapabilityHeaderBytes = 8U;
constexpr std::size_t kCapabilityFlagsBytes = 4U;
constexpr std::size_t kAdvertiseHeaderBytes =
    kGraphicsHeaderBytes + 2U;
constexpr std::size_t kMaximumCapsAdvertisementBytes =
    64U * 1024U;

struct CapabilityCandidate final
{
    bool seen{};
    bool supported{};
    std::uint32_t flags{};
};

[[nodiscard]] std::uint16_t readU16(
    std::span<const std::byte> input,
    std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>(
        std::to_integer<std::uint8_t>(input[offset]) |
        (std::uint16_t{
             std::to_integer<std::uint8_t>(
                 input[offset + 1U])}
         << 8U));
}

[[nodiscard]] std::uint32_t readU32(
    std::span<const std::byte> input,
    std::size_t offset) noexcept
{
    return static_cast<std::uint32_t>(
               readU16(input, offset)) |
           (static_cast<std::uint32_t>(
                readU16(input, offset + 2U))
            << 16U);
}

void writeU16(
    std::span<std::byte> output,
    std::size_t offset,
    std::uint16_t value) noexcept
{
    output[offset] = static_cast<std::byte>(value);
    output[offset + 1U] =
        static_cast<std::byte>(value >> 8U);
}

void writeU32(
    std::span<std::byte> output,
    std::size_t offset,
    std::uint32_t value) noexcept
{
    writeU16(
        output, offset,
        static_cast<std::uint16_t>(value));
    writeU16(
        output, offset + 2U,
        static_cast<std::uint16_t>(value >> 16U));
}

[[nodiscard]] bool updateCandidate(
    CapabilityCandidate &candidate,
    std::uint32_t dataLength,
    std::uint32_t flags,
    std::uint32_t knownFlags) noexcept
{
    if (candidate.seen ||
        dataLength != kCapabilityFlagsBytes)
    {
        return false;
    }

    candidate.seen = true;
    // A known version with unknown flags is not a profile R4 can confirm.
    // Preserve parsing so a lower supported advertised version can win.
    if ((flags & ~knownFlags) == 0U)
    {
        candidate.supported = true;
        candidate.flags = flags;
    }
    return true;
}
} // namespace

GfxCapabilityNegotiationResult
negotiateGfxCapabilities(
    std::span<const std::byte> advertisement) noexcept
{
    GfxCapabilityNegotiationResult result{};
    if (advertisement.size() < kAdvertiseHeaderBytes ||
        advertisement.size() >
            kMaximumCapsAdvertisementBytes ||
        readU16(advertisement, 0U) !=
            kCapsAdvertiseCommand ||
        readU16(advertisement, 2U) != 0U ||
        readU32(advertisement, 4U) !=
            advertisement.size())
    {
        return result;
    }

    const std::size_t capabilityCount =
        readU16(advertisement, 8U);
    std::size_t offset = kAdvertiseHeaderBytes;
    if (capabilityCount >
        (advertisement.size() - offset) /
            kCapabilityHeaderBytes)
    {
        return result;
    }

    CapabilityCandidate version8{};
    CapabilityCandidate version81{};

    for (std::size_t capability = 0;
         capability < capabilityCount;
         ++capability)
    {
        if (advertisement.size() - offset <
            kCapabilityHeaderBytes)
        {
            return result;
        }

        const std::uint32_t version =
            readU32(advertisement, offset);
        const std::uint32_t dataLength =
            readU32(advertisement, offset + 4U);
        offset += kCapabilityHeaderBytes;
        if (dataLength >
            advertisement.size() - offset)
        {
            return result;
        }

        if (version == kGfxCapabilityVersion8 ||
            version == kGfxCapabilityVersion81)
        {
            if (dataLength != kCapabilityFlagsBytes)
                return result;

            const std::uint32_t flags =
                readU32(advertisement, offset);
            const bool valid =
                version == kGfxCapabilityVersion81
                    ? updateCandidate(
                          version81, dataLength, flags,
                          kVersion81KnownFlags)
                    : updateCandidate(
                          version8, dataLength, flags,
                          kVersion8KnownFlags);
            if (!valid)
                return result;
        }
        offset += dataLength;
    }

    if (offset != advertisement.size())
        return result;

    const CapabilityCandidate *selected = nullptr;
    if (version81.supported)
    {
        selected = &version81;
        result.selectedVersion =
            kGfxCapabilityVersion81;
    }
    else if (version8.supported)
    {
        selected = &version8;
        result.selectedVersion =
            kGfxCapabilityVersion8;
    }
    else
    {
        result.status =
            GfxCapabilityNegotiationStatus::
                UnsupportedCapability;
        return result;
    }

    result.selectedFlags = selected->flags;
    result.avc420Enabled =
        result.selectedVersion ==
            kGfxCapabilityVersion81 &&
        (selected->flags & kAvc420Enabled) != 0U;

    std::span<std::byte> confirmation{
        result.confirmation};
    writeU16(
        confirmation, 0U, kCapsConfirmCommand);
    writeU16(confirmation, 2U, 0U);
    writeU32(
        confirmation, 4U,
        static_cast<std::uint32_t>(
            confirmation.size()));
    writeU32(
        confirmation, 8U,
        result.selectedVersion);
    writeU32(
        confirmation, 12U,
        kCapabilityFlagsBytes);
    writeU32(
        confirmation, 16U,
        result.selectedFlags);

    result.confirmationBytes =
        confirmation.size();
    result.status =
        GfxCapabilityNegotiationStatus::Accepted;
    return result;
}

GfxAvc420NegotiationResult
negotiateGfxAvc420(
    std::span<const std::byte> advertisement) noexcept
{
    const auto generic =
        negotiateGfxCapabilities(advertisement);

    GfxAvc420NegotiationResult result{};
    result.status = generic.status;
    if (!generic.accepted())
        return result;

    if (!generic.avc420Enabled)
    {
        result.status =
            GfxAvc420NegotiationStatus::
                UnsupportedCapability;
        return result;
    }

    std::copy(
        generic.confirmation.begin(),
        generic.confirmation.end(),
        result.confirmation.begin());
    result.confirmationBytes =
        generic.confirmationBytes;
    result.status =
        GfxAvc420NegotiationStatus::Accepted;
    return result;
}

} // namespace rdp_server::rdp
