// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/transport/mcs_channel_connection.h"
#include "server/transport/rdp_demand_active_profile.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

using namespace rdp_server::server::transport;

namespace
{
[[nodiscard]] std::uint16_t readLe16(
    std::span<const std::uint8_t> bytes, std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(
               static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U);
}

[[nodiscard]] std::uint32_t readLe32(
    std::span<const std::uint8_t> bytes, std::size_t offset) noexcept
{
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}

[[nodiscard]] RdpDemandActiveProfilePolicy basePolicy() noexcept
{
    return {1280U, 720U, RdpDemandActivePlatform::LinuxX11,
            RdpDemandActiveFeature::None};
}

void testExactWire()
{
    RdpDemandActiveProfileProvider provider;
    const auto profile = provider.prepare(1U, basePolicy());
    assert(profile && provider.owns(*profile));

    std::array<std::uint8_t, 174> encoded{};
    const auto size = encodeRdpDemandActivePdu(
        profile->shareId(), profile->sessionId(), profile->sourceDescriptor(),
        profile->capabilityCount(), profile->capabilitySets(), encoded);
    assert(size && *size == encoded.size());

    constexpr std::array<std::uint8_t, 174> expected{{
        0xae,0x00,0x11,0x00,0xea,0x03,0xea,0x03,0x01,0x00,0x04,0x00,0x98,0x00,0x52,0x44,
        0x50,0x00,0x04,0x00,0x00,0x00,0x09,0x00,0x08,0x00,0xea,0x03,0x00,0x00,0x01,0x00,
        0x18,0x00,0x04,0x00,0x07,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x1c,0x00,0x20,0x00,0x01,0x00,0x01,0x00,
        0x01,0x00,0x00,0x05,0xd0,0x02,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,
        0x00,0x00,0x03,0x00,0x58,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x14,0x00,0x00,0x00,
        0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    }};
    assert(encoded == expected);
}

void testFieldConsistency()
{
    RdpDemandActiveProfileProvider provider;
    const auto profile = provider.prepare(41U, basePolicy());
    assert(profile);
    assert(profile->sessionId() == 0U);
    assert(profile->sessionGeneration() == 41U);
    assert(profile->sourceDescriptor().size() == 4U);
    assert(profile->sourceDescriptor()[0] == 'R');
    assert(profile->sourceDescriptor()[3] == 0U);

    std::array<std::uint8_t, 512> encoded{};
    const auto size = encodeRdpDemandActivePdu(
        profile->shareId(), profile->sessionId(), profile->sourceDescriptor(),
        profile->capabilityCount(), profile->capabilitySets(), encoded);
    assert(size);
    const auto parsed = parseRdpActivePdu(std::span(encoded).first(*size));
    assert(parsed);
    assert(parsed.value.shareId == profile->shareId());
    assert(parsed.value.sessionId == 0U);
    assert(parsed.value.capabilityCount == profile->capabilityCount());
    assert(parsed.value.capabilitySets.size() == profile->capabilitySets().size());
}

void testPolicyVariants()
{
    RdpDemandActiveProfileProvider base;
    const auto baseProfile = base.prepare(1U, basePolicy());
    assert(baseProfile && baseProfile->capabilityCount() == 4U);
    assert(baseProfile->capabilitySets().size() == 148U);

    auto inputPolicy = basePolicy();
    inputPolicy.features = RdpDemandActiveFeature::SlowPathInput;
    RdpDemandActiveProfileProvider input;
    const auto inputProfile = input.prepare(2U, inputPolicy);
    assert(inputProfile && inputProfile->capabilityCount() == 5U);
    assert(inputProfile->capabilitySets().size() == 236U);
    const auto inputCaps = inputProfile->capabilitySets();
    assert(readLe16(inputCaps, 148U) == 13U);
    assert(readLe16(inputCaps, 152U) == 0x0015U);
    assert((readLe16(inputCaps, 152U) & 0x0028U) == 0U);

    auto dvcPolicy = basePolicy();
    dvcPolicy.features = RdpDemandActiveFeature::DynamicVirtualChannels;
    RdpDemandActiveProfileProvider dvc;
    const auto dvcProfile = dvc.prepare(3U, dvcPolicy);
    assert(dvcProfile && dvcProfile->capabilityCount() == 5U);
    assert(dvcProfile->capabilitySets().size() == 160U);
    const auto dvcCaps = dvcProfile->capabilitySets();
    assert(readLe16(dvcCaps, 148U) == 20U);
    assert(readLe32(dvcCaps, 152U) == 0U);
    assert(readLe32(dvcCaps, 156U) == 1600U);

    auto macPolicy = basePolicy();
    macPolicy.platform = RdpDemandActivePlatform::MacOS;
    RdpDemandActiveProfileProvider mac;
    const auto macProfile = mac.prepare(4U, macPolicy);
    assert(macProfile && macProfile->capabilityCount() == 4U);
    const auto macCapabilities = macProfile->capabilitySets();
    // General Capability Set: OSMAJORTYPE_OSX / OSMINORTYPE_UNSPECIFIED.
    assert(readLe16(macCapabilities, 12U) == 6U);
    assert(readLe16(macCapabilities, 14U) == 0U);

    auto bothPolicy = basePolicy();
    bothPolicy.features = RdpDemandActiveFeature::SlowPathInput |
                          RdpDemandActiveFeature::DynamicVirtualChannels;
    RdpDemandActiveProfileProvider both;
    const auto bothProfile = both.prepare(5U, bothPolicy);
    assert(bothProfile && bothProfile->capabilityCount() == 6U);
    assert(bothProfile->capabilitySets().size() ==
           kMaximumRdpDemandActiveCapabilityBytes);
}

void testCountLengthAgreement()
{
    auto policy = basePolicy();
    policy.features = RdpDemandActiveFeature::SlowPathInput |
                      RdpDemandActiveFeature::DynamicVirtualChannels;
    RdpDemandActiveProfileProvider provider;
    const auto profile = provider.prepare(9U, policy);
    assert(profile);

    std::size_t offset = 0U;
    std::uint16_t count = 0U;
    const auto capabilities = profile->capabilitySets();
    while (offset < capabilities.size())
    {
        assert(capabilities.size() - offset >= 4U);
        const std::size_t length = readLe16(capabilities, offset + 2U);
        assert(length >= 4U && length <= capabilities.size() - offset);
        offset += length;
        ++count;
    }
    assert(offset == capabilities.size());
    assert(count == profile->capabilityCount());
}

void testStaleAndUnsupportedDenials()
{
    RdpDemandActiveProfileProvider provider;
    auto policy = basePolicy();
    const auto first = provider.prepare(77U, policy);
    assert(first && provider.owns(*first));
    const auto firstShareId = first->shareId();

    assert(!provider.prepare(77U, policy));
    provider.close();
    assert(!provider.owns(*first));
    assert(!provider.prepare(76U, policy));

    const auto replacement = provider.prepare(78U, policy);
    assert(replacement && provider.owns(*replacement));
    assert(replacement->shareId() != firstShareId);
    assert(!provider.owns(*first));

    RdpDemandActiveProfileProvider unsupported;
    policy.features = static_cast<RdpDemandActiveFeature>(0x80000000U);
    assert(!unsupported.prepare(1U, policy));
    policy = basePolicy();
    policy.platform = static_cast<RdpDemandActivePlatform>(0xffU);
    assert(!unsupported.prepare(1U, policy));
    policy = basePolicy();
    policy.desktopWidth = 0U;
    assert(!unsupported.prepare(1U, policy));
}

void testImmutableLifetime()
{
    RdpDemandActiveProfileProvider provider;
    RdpDemandActiveProfileView view;
    std::array<std::uint8_t, kMaximumRdpDemandActiveCapabilityBytes> snapshot{};
    std::size_t snapshotBytes = 0U;
    {
        auto temporaryPolicy = basePolicy();
        temporaryPolicy.features = RdpDemandActiveFeature::SlowPathInput;
        const auto prepared = provider.prepare(123U, temporaryPolicy);
        assert(prepared);
        view = *prepared;
        snapshotBytes = view.capabilitySets().size();
        std::copy(view.capabilitySets().begin(), view.capabilitySets().end(),
                  snapshot.begin());
        temporaryPolicy.desktopWidth = 1U;
        temporaryPolicy.features = RdpDemandActiveFeature::None;
    }
    assert(provider.owns(view));
    assert(view.sessionGeneration() == 123U);
    assert(view.capabilitySets().size() == snapshotBytes);
    assert(std::equal(view.capabilitySets().begin(), view.capabilitySets().end(),
                      snapshot.begin()));
}

struct TestCase
{
    std::string_view name;
    void (*run)();
};

constexpr std::array<TestCase, 6> tests{{
    {"exact-wire", &testExactWire},
    {"field-consistency", &testFieldConsistency},
    {"policy-variants", &testPolicyVariants},
    {"count-length-agreement", &testCountLengthAgreement},
    {"stale-unsupported-denials", &testStaleAndUnsupportedDenials},
    {"immutable-lifetime", &testImmutableLifetime},
}};
} // namespace

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    const std::string_view requested{argv[1]};
    const auto found = std::find_if(
        tests.begin(), tests.end(),
        [requested](const TestCase &test) { return test.name == requested; });
    if (found == tests.end())
        return 2;
    found->run();
    return 0;
}
