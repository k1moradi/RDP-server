// SPDX-License-Identifier: GPL-3.0-or-later

#include "rdp/gfx_avc420_capabilities.h"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string_view>
#include <vector>

namespace
{
using rdp_server::rdp::GfxAvc420NegotiationStatus;
using rdp_server::rdp::negotiateGfxAvc420;

struct TestCapability final
{
    std::uint32_t version{};
    std::uint32_t flags{};
};

void appendU16(std::vector<std::byte> &bytes, std::uint16_t value)
{
    bytes.emplace_back(static_cast<std::byte>(value));
    bytes.emplace_back(static_cast<std::byte>(value >> 8));
}

void appendU32(std::vector<std::byte> &bytes, std::uint32_t value)
{
    appendU16(bytes, static_cast<std::uint16_t>(value));
    appendU16(bytes, static_cast<std::uint16_t>(value >> 16));
}

void overwriteU32(std::vector<std::byte> &bytes, std::size_t offset,
                  std::uint32_t value)
{
    for (std::size_t index = 0; index < 4; ++index)
    {
        bytes[offset + index] = static_cast<std::byte>(value >> (8 * index));
    }
}

[[nodiscard]] std::vector<std::byte>
makeAdvertisement(std::initializer_list<TestCapability> capabilities)
{
    std::vector<std::byte> bytes;
    bytes.reserve(10 + capabilities.size() * 12);
    appendU16(bytes, 0x0012);
    appendU16(bytes, 0);
    appendU32(bytes, 0); // Patched with the final RDPGFX_HEADER length.
    appendU16(bytes, static_cast<std::uint16_t>(capabilities.size()));
    for (const TestCapability capability : capabilities)
    {
        appendU32(bytes, capability.version);
        appendU32(bytes, 4);
        appendU32(bytes, capability.flags);
    }
    overwriteU32(bytes, 4, static_cast<std::uint32_t>(bytes.size()));
    return bytes;
}

void testSelection()
{
    auto advertisement = makeAdvertisement({
        {0x00080004, 0},      // Version 8 has no AVC420 capability.
        {0x000A0002, 0x20},   // Version 10 explicitly disables AVC.
        {0x00080105, 0x13},   // Version 8.1 explicitly enables AVC420.
        {0xDEADBEEF, 0xFF},   // Unknown future capability is ignored.
    });
    // Unknown capability data is not necessarily four bytes. Verify that
    // the declared length is honored without interpreting that payload.
    constexpr std::size_t unknownCapabilityLengthOffset = 10 + 3 * 12 + 4;
    overwriteU32(advertisement, unknownCapabilityLengthOffset, 8);
    advertisement.insert(advertisement.end(), 4, std::byte{0xA5});
    overwriteU32(advertisement, 4,
                 static_cast<std::uint32_t>(advertisement.size()));
    const auto selected = negotiateGfxAvc420(advertisement);
    assert(selected.accepted());
    assert(selected.confirmationBytes == 20);
    const std::array<std::byte, 20> expected{
        std::byte{0x13}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{20}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0x05}, std::byte{0x01}, std::byte{0x08}, std::byte{0},
        std::byte{4}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0x13}, std::byte{0}, std::byte{0}, std::byte{0},
    };
    assert(selected.confirmation == expected);

    // No cached state survives calls; supported optional flags are retained.
    const auto minimal = negotiateGfxAvc420(
        makeAdvertisement({{0x00080105, 0x10}}));
    assert(minimal.accepted());
    assert(minimal.confirmation[16] == std::byte{0x10});
    assert(negotiateGfxAvc420(advertisement).confirmation == expected);
}

void testHighestSupportedSelection()
{
    // MS-RDPEGFX 3.2.5.19 requires CAPS_CONFIRM to select the highest
    // capability set the server actually supports, not simply the highest
    // version advertised by the client. R4 currently implements only 8.1
    // AVC420, so newer published/future sets must never be reflected.
    constexpr std::uint32_t version81 = 0x00080105;
    constexpr std::uint32_t version107 = 0x000A0701;
    constexpr std::uint32_t unknownFutureVersion = 0x000B0300;

    const auto expected = negotiateGfxAvc420(
        makeAdvertisement({{version81, 0x13}}));
    assert(expected.accepted());
    assert(expected.confirmationBytes == 20);

    for (const auto &advertisement : {
             makeAdvertisement({{version107, 0x20},
                                {version81, 0x13},
                                {unknownFutureVersion, 0xFFFFFFFF}}),
             makeAdvertisement({{unknownFutureVersion, 0},
                                {version81, 0x13},
                                {version107, 0x20}}),
             makeAdvertisement({{version81, 0x13},
                                {version107, 0x20},
                                {unknownFutureVersion, 0xFFFFFFFF}}),
         })
    {
        const auto selected = negotiateGfxAvc420(advertisement);
        assert(selected.status == GfxAvc420NegotiationStatus::Accepted);
        assert(selected.confirmationBytes == expected.confirmationBytes);
        assert(selected.confirmation == expected.confirmation);
    }

    for (const auto &advertisement : {
             makeAdvertisement({{version107, 0x20}}),
             makeAdvertisement({{unknownFutureVersion, 0xFFFFFFFF}}),
             makeAdvertisement({{version107, 0x20},
                                {unknownFutureVersion, 0xFFFFFFFF}}),
         })
    {
        const auto unsupported = negotiateGfxAvc420(advertisement);
        assert(unsupported.status ==
               GfxAvc420NegotiationStatus::UnsupportedCapability);
        assert(unsupported.confirmationBytes == 0);
    }
}

void testRejections()
{
    const auto valid = makeAdvertisement({{0x00080105, 0x10}});
    for (std::size_t truncatedBytes = 0; truncatedBytes < valid.size();
         ++truncatedBytes)
    {
        const auto invalid = negotiateGfxAvc420(
            std::span<const std::byte>{valid.data(), truncatedBytes});
        assert(invalid.status ==
               GfxAvc420NegotiationStatus::MalformedAdvertisement);
        assert(invalid.confirmationBytes == 0);
    }

    const auto malformed = [&](std::size_t offset, std::uint32_t value) {
        auto bytes = valid;
        overwriteU32(bytes, offset, value);
        const auto rejected = negotiateGfxAvc420(bytes);
        assert(rejected.status ==
               GfxAvc420NegotiationStatus::MalformedAdvertisement);
        assert(rejected.confirmationBytes == 0);
    };
    malformed(4, 21);            // Declared size larger than received size.
    malformed(4, 0xFFFFFFFF);    // Excessively large declared length.
    malformed(14, 0xFFFFFFFF);   // Overflow-sized capability data.
    malformed(14, 3);            // Version 8.1 requires four flag bytes.
    malformed(14, 5);

    auto invalid = valid;
    invalid[0] = std::byte{0x13};  // Wrong PDU command.
    assert(!negotiateGfxAvc420(invalid).accepted());
    invalid = valid;
    invalid[2] = std::byte{1};     // Nonzero RDPGFX_HEADER flags.
    assert(!negotiateGfxAvc420(invalid).accepted());
    invalid = valid;
    invalid[8] = std::byte{2};     // Missing second capability header.
    assert(!negotiateGfxAvc420(invalid).accepted());
    invalid = valid;
    invalid.emplace_back(std::byte{0}); // Unclaimed trailing byte.
    overwriteU32(invalid, 4, static_cast<std::uint32_t>(invalid.size()));
    assert(!negotiateGfxAvc420(invalid).accepted());
    invalid = makeAdvertisement({{0x00080105, 0x10},
                                 {0x00080105, 0x10}});
    assert(!negotiateGfxAvc420(invalid).accepted()); // Duplicate v8.1.
    invalid = makeAdvertisement({});
    invalid.emplace_back(std::byte{0});
    overwriteU32(invalid, 4, static_cast<std::uint32_t>(invalid.size()));
    assert(!negotiateGfxAvc420(invalid).accepted()); // Unclaimed bytes.

    for (const auto &unsupported : {
             makeAdvertisement({}),
             makeAdvertisement({{0x00080004, 0}}),
             makeAdvertisement({{0x000A0002, 0}}),
             makeAdvertisement({{0x00080105, 0}}),
             makeAdvertisement({{0x00080105, 0x20}}),
             makeAdvertisement({{0x00080105, 0x10010}}),
         })
    {
        const auto result = negotiateGfxAvc420(unsupported);
        assert(result.status == GfxAvc420NegotiationStatus::UnsupportedCapability);
        assert(result.confirmationBytes == 0);
    }

    // Bounded resource policy even if a malicious peer correctly declares
    // a much larger graphics PDU.
    auto oversized = valid;
    oversized.resize(65 * 1024, std::byte{0});
    overwriteU32(oversized, 4, static_cast<std::uint32_t>(oversized.size()));
    assert(negotiateGfxAvc420(oversized).status ==
           GfxAvc420NegotiationStatus::MalformedAdvertisement);
}
void testHeaderBounds()
{
    // The first element may consume part or all of the next declared
    // element's header. Revalidate remaining header bytes on EACH entry,
    // not only against the initial capsSetCount minimum size.
    for (const std::uint32_t consumingLength : {10U, 16U})
    {
        auto overlapping = makeAdvertisement({{0xDEADBEEF, 0},
                                              {0x00080105, 0x10}});
        overwriteU32(overlapping, 14, consumingLength);
        const auto rejected = negotiateGfxAvc420(overlapping);
        assert(rejected.status ==
               GfxAvc420NegotiationStatus::MalformedAdvertisement);
        assert(rejected.confirmationBytes == 0);
    }

}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        return 1;
    }
    const std::string_view behavior{argv[1]};
    if (behavior == "avc420-capabilities-selection")
    {
        testSelection();
        return 0;
    }
    if (behavior == "avc420-capabilities-highest-supported-selection")
    {
        testHighestSupportedSelection();
        return 0;
    }
    if (behavior == "avc420-capabilities-rejections")
    {
        testRejections();
        return 0;
    }
    if (behavior == "avc420-capabilities-header-bounds")
    {
        testHeaderBounds();
        return 0;
    }
    return 1;
}
