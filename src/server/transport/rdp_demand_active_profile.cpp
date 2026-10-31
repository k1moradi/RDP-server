// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp_demand_active_profile.h"

#include <algorithm>
#include <atomic>
#include <limits>

namespace rdp_server::server::transport
{
namespace
{
std::atomic<std::uint64_t> nextShareId{0x000103eaULL};

[[nodiscard]] std::optional<std::uint32_t> allocateShareId() noexcept
{
    auto value = nextShareId.load(std::memory_order_relaxed);
    while (value != 0U &&
           value <= static_cast<std::uint64_t>(
                        std::numeric_limits<std::uint32_t>::max()))
    {
        if (nextShareId.compare_exchange_weak(
                value, value + 1U,
                std::memory_order_relaxed, std::memory_order_relaxed))
            return static_cast<std::uint32_t>(value);
    }
    return std::nullopt;
}

void writeLe16(std::span<std::uint8_t> bytes,
               std::size_t offset,
               std::uint16_t value) noexcept
{
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}

void writeLe32(std::span<std::uint8_t> bytes,
               std::size_t offset,
               std::uint32_t value) noexcept
{
    writeLe16(bytes, offset, static_cast<std::uint16_t>(value));
    writeLe16(bytes, offset + 2U, static_cast<std::uint16_t>(value >> 16U));
}

[[nodiscard]] bool appendCapabilityHeader(
    std::span<std::uint8_t> output,
    std::size_t &offset,
    std::uint16_t type,
    std::uint16_t length) noexcept
{
    if (length < 4U || offset > output.size() ||
        length > output.size() - offset)
        return false;
    writeLe16(output, offset, type);
    writeLe16(output, offset + 2U, length);
    return true;
}

[[nodiscard]] bool appendCanonicalCapabilities(
    const RdpDemandActiveProfilePolicy &policy,
    std::span<std::uint8_t> output,
    std::size_t &bytesWritten,
    std::uint16_t &capabilityCount) noexcept
{
    constexpr std::uint32_t kSlowPathInput =
        static_cast<std::uint32_t>(RdpDemandActiveFeature::SlowPathInput);
    constexpr std::uint32_t kDynamicVirtualChannels =
        static_cast<std::uint32_t>(RdpDemandActiveFeature::DynamicVirtualChannels);
    constexpr std::uint32_t kSupportedFeatures =
        kSlowPathInput | kDynamicVirtualChannels;
    const auto featureBits = static_cast<std::uint32_t>(policy.features);
    std::uint16_t osMajorType = 0U;
    std::uint16_t osMinorType = 0U;
    switch (policy.platform)
    {
    case RdpDemandActivePlatform::LinuxX11:
        osMajorType = 4U; // OSMAJORTYPE_UNIX
        osMinorType = 7U; // OSMINORTYPE_NATIVE_XSERVER
        break;
    case RdpDemandActivePlatform::MacOS:
        osMajorType = 6U; // OSMAJORTYPE_OSX
        osMinorType = 0U; // OSMINORTYPE_UNSPECIFIED
        break;
    default:
        return false;
    }
    if (policy.desktopWidth == 0U || policy.desktopHeight == 0U ||
        (featureBits & ~kSupportedFeatures) != 0U)
        return false;

    std::fill(output.begin(), output.end(), std::uint8_t{0});
    std::size_t offset = 0U;
    std::uint16_t count = 0U;
    const auto append = [&](std::uint16_t type,
                            std::uint16_t length) noexcept -> bool
    {
        if (!appendCapabilityHeader(output, offset, type, length))
            return false;
        ++count;
        return true;
    };

    // MS-RDPBCGR 2.2.7.2.4: server nodeID SHOULD be server channel 1002.
    if (!append(9U, 8U))
        return false;
    writeLe16(output, offset + 4U, 1002U);
    offset += 8U;

    // MS-RDPBCGR 2.2.7.1.1. Advertise only the actual server platform plus
    // protocol version. No fast-path, reconnect, compression or refresh flags.
    if (!append(1U, 24U))
        return false;
    writeLe16(output, offset + 4U, osMajorType);
    writeLe16(output, offset + 6U, osMinorType);
    writeLe16(output, offset + 8U, 0x0200U);
    offset += 24U;

    // 2.2.7.1.2. Bitmap compression and multiple rectangles are mandatory
    // protocol fields; no resize, lossy drawing flags or cache claim is made.
    if (!append(2U, 28U))
        return false;
    writeLe16(output, offset + 4U, 32U);
    writeLe16(output, offset + 6U, 1U);
    writeLe16(output, offset + 8U, 1U);
    writeLe16(output, offset + 10U, 1U);
    writeLe16(output, offset + 12U, policy.desktopWidth);
    writeLe16(output, offset + 14U, policy.desktopHeight);
    writeLe16(output, offset + 20U, 1U); // bitmapCompressionFlag
    writeLe16(output, offset + 24U, 1U); // multipleRectangleSupport
    offset += 28U;

    // 2.2.7.1.3. NEGOTIATEORDERSUPPORT is mandatory when this set is sent.
    // All orderSupport bytes remain zero because R3/R4 do not publish GDI
    // primary drawing orders; graphics uses the separately negotiated DVC.
    if (!append(3U, 88U))
        return false;
    writeLe16(output, offset + 24U, 1U);  // desktopSaveXGranularity
    writeLe16(output, offset + 26U, 20U); // desktopSaveYGranularity
    writeLe16(output, offset + 30U, 1U);  // maximumOrderLevel
    writeLe16(output, offset + 34U, 0x0002U); // NEGOTIATEORDERSUPPORT
    offset += 88U;

    if ((featureBits & kSlowPathInput) != 0U)
    {
        // 2.2.7.1.6. Slow-path scancode, MouseX and Unicode are implemented.
        // Deliberately omit both fast-path flags and newer unsupported events.
        if (!append(13U, 88U))
            return false;
        writeLe16(output, offset + 4U, 0x0015U);
        offset += 88U;
    }

    if ((featureBits & kDynamicVirtualChannels) != 0U)
    {
        // 2.2.7.1.10. Compression is unsupported. Use the conservative
        // mandatory-compatible 1600-byte chunk bound already owned by R3.
        if (!append(20U, 12U))
            return false;
        writeLe32(output, offset + 4U, 0U);
        writeLe32(output, offset + 8U, 1600U);
        offset += 12U;
    }

    bytesWritten = offset;
    capabilityCount = count;
    return offset != 0U && count >= 4U;
}
} // namespace

std::optional<RdpDemandActiveProfileView>
RdpDemandActiveProfileProvider::prepare(
    std::uint64_t sessionGeneration,
    const RdpDemandActiveProfilePolicy &policy) noexcept
{
    if (profileReady_ || sessionGeneration == 0U ||
        sessionGeneration <= lastSessionGeneration_ ||
        nextProfileGeneration_ == 0U)
        return std::nullopt;

    std::size_t capabilityBytes = 0U;
    std::uint16_t capabilityCount = 0U;
    if (!appendCanonicalCapabilities(
            policy, capabilitySets_, capabilityBytes, capabilityCount))
        return std::nullopt;

    const auto shareId = allocateShareId();
    if (!shareId)
        return std::nullopt;

    sessionGeneration_ = sessionGeneration;
    lastSessionGeneration_ = sessionGeneration;
    profileGeneration_ = nextProfileGeneration_++;
    shareId_ = *shareId;
    capabilityBytes_ = capabilityBytes;
    capabilityCount_ = capabilityCount;
    features_ = policy.features;
    profileReady_ = true;

    RdpDemandActiveProfileView view{};
    view.owner_ = this;
    view.sourceDescriptor_ = sourceDescriptor_;
    view.capabilitySets_ = std::span<const std::uint8_t>{capabilitySets_}.first(
        capabilityBytes_);
    view.sessionGeneration_ = sessionGeneration_;
    view.profileGeneration_ = profileGeneration_;
    view.shareId_ = shareId_;
    view.sessionId_ = 0U;
    view.capabilityCount_ = capabilityCount_;
    view.features_ = features_;
    return view;
}

void RdpDemandActiveProfileProvider::close() noexcept
{
    capabilitySets_.fill(0U);
    capabilityBytes_ = 0U;
    sessionGeneration_ = 0U;
    profileGeneration_ = 0U;
    shareId_ = 0U;
    capabilityCount_ = 0U;
    features_ = RdpDemandActiveFeature::None;
    profileReady_ = false;
}

} // namespace rdp_server::server::transport
