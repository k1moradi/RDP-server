// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rdp_server::server::transport
{

inline constexpr std::size_t kRdpDemandActiveSourceDescriptorBytes = 4U;
inline constexpr std::size_t kMaximumRdpDemandActiveCapabilityBytes = 248U;

enum class RdpDemandActiveFeature : std::uint32_t
{
    None = 0U,
    SlowPathInput = 1U << 0U,
    DynamicVirtualChannels = 1U << 1U,
};

[[nodiscard]] constexpr RdpDemandActiveFeature operator|(
    RdpDemandActiveFeature lhs, RdpDemandActiveFeature rhs) noexcept
{
    return static_cast<RdpDemandActiveFeature>(
        static_cast<std::uint32_t>(lhs) |
        static_cast<std::uint32_t>(rhs));
}

[[nodiscard]] constexpr bool hasRdpDemandActiveFeature(
    RdpDemandActiveFeature features, RdpDemandActiveFeature feature) noexcept
{
    return (static_cast<std::uint32_t>(features) &
            static_cast<std::uint32_t>(feature)) != 0U;
}

enum class RdpDemandActivePlatform : std::uint8_t
{
    LinuxX11 = 1U,
    MacOS = 2U,
};

struct RdpDemandActiveProfilePolicy
{
    std::uint16_t desktopWidth{};
    std::uint16_t desktopHeight{};
    RdpDemandActivePlatform platform{RdpDemandActivePlatform::LinuxX11};
    RdpDemandActiveFeature features{RdpDemandActiveFeature::None};
};

class RdpDemandActiveProfileProvider;

class RdpDemandActiveProfileView final
{
public:
    RdpDemandActiveProfileView() noexcept = default;

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return owner_ != nullptr && profileGeneration_ != 0U &&
               shareId_ != 0U && !sourceDescriptor_.empty() &&
               capabilityCount_ != 0U && !capabilitySets_.empty();
    }
    [[nodiscard]] std::uint32_t shareId() const noexcept { return shareId_; }
    [[nodiscard]] std::uint32_t sessionId() const noexcept { return sessionId_; }
    [[nodiscard]] std::span<const std::uint8_t>
    sourceDescriptor() const noexcept { return sourceDescriptor_; }
    [[nodiscard]] std::uint16_t capabilityCount() const noexcept
    { return capabilityCount_; }
    [[nodiscard]] std::span<const std::uint8_t> capabilitySets() const noexcept
    { return capabilitySets_; }
    [[nodiscard]] std::uint64_t sessionGeneration() const noexcept
    { return sessionGeneration_; }
    [[nodiscard]] RdpDemandActiveFeature features() const noexcept
    { return features_; }

private:
    friend class RdpDemandActiveProfileProvider;

    const RdpDemandActiveProfileProvider *owner_{};
    std::span<const std::uint8_t> sourceDescriptor_{};
    std::span<const std::uint8_t> capabilitySets_{};
    std::uint64_t sessionGeneration_{};
    std::uint64_t profileGeneration_{};
    std::uint32_t shareId_{};
    std::uint32_t sessionId_{};
    std::uint16_t capabilityCount_{};
    RdpDemandActiveFeature features_{RdpDemandActiveFeature::None};
};

// R3-owned, allocation-free source of one immutable Demand Active profile.
// prepare() is protocol-only and may be used by offline tests. A profile has
// no production authority by itself: live Share startup additionally requires
// the current R2 broker to validate that the view belongs to the exact provider
// embedded in the admitted McsSessionLifecycle.
class RdpDemandActiveProfileProvider final
{
public:
    RdpDemandActiveProfileProvider() noexcept = default;
    RdpDemandActiveProfileProvider(const RdpDemandActiveProfileProvider &) = delete;
    RdpDemandActiveProfileProvider &operator=(
        const RdpDemandActiveProfileProvider &) = delete;

    [[nodiscard]] std::optional<RdpDemandActiveProfileView> prepare(
        std::uint64_t sessionGeneration,
        const RdpDemandActiveProfilePolicy &policy) noexcept;
    [[nodiscard]] bool owns(const RdpDemandActiveProfileView &view) const noexcept
    {
        return view.owner_ == this && profileReady_ &&
               view.profileGeneration_ == profileGeneration_ &&
               view.sessionGeneration_ == sessionGeneration_ &&
               view.shareId_ == shareId_ && view.sessionId_ == 0U &&
               view.sourceDescriptor_.data() == sourceDescriptor_.data() &&
               view.sourceDescriptor_.size() == sourceDescriptor_.size() &&
               view.capabilitySets_.data() == capabilitySets_.data() &&
               view.capabilitySets_.size() == capabilityBytes_ &&
               view.capabilityCount_ == capabilityCount_ &&
               view.features_ == features_;
    }
    void close() noexcept;

private:
    std::array<std::uint8_t, kRdpDemandActiveSourceDescriptorBytes>
        sourceDescriptor_{{'R', 'D', 'P', 0U}};
    std::array<std::uint8_t, kMaximumRdpDemandActiveCapabilityBytes>
        capabilitySets_{};
    std::size_t capabilityBytes_{};
    std::uint64_t sessionGeneration_{};
    std::uint64_t lastSessionGeneration_{};
    std::uint64_t profileGeneration_{};
    std::uint64_t nextProfileGeneration_{1U};
    std::uint32_t shareId_{};
    std::uint16_t capabilityCount_{};
    RdpDemandActiveFeature features_{RdpDemandActiveFeature::None};
    bool profileReady_{};
};

} // namespace rdp_server::server::transport
