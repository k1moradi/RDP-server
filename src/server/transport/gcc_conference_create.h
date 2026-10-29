// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{

// MS-RDPBCGR 2.2.1.3: no Extended Client Data Blocks were advertised.
// The limit applies to the complete GCC Connect Data inside MCS userData.
inline constexpr std::size_t kMaximumBasicGccBytes = 1024;
inline constexpr std::size_t kMaximumStaticChannelCount = 31;

// MS-RDPBCGR 2.2.1.3.2 and MS-RDPEGFX 1.5.1: a client that supports the
// Graphics Pipeline Extension advertises RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL
// in Client Core earlyCapabilityFlags. This is structural capability evidence
// only; it never grants R2 admission, Share or dynamic-channel authority.
inline constexpr std::uint16_t
    kGccClientCoreSupportsDynamicVirtualChannelGraphics = 0x0100U;

enum class GccError : std::uint8_t
{
    None,
    InvalidConnectData,
    InvalidConference,
    InvalidH221Key,
    InvalidSettings,
    InvalidCore,
    InvalidSecurity,
    InvalidNetwork,
};

struct GccChannel
{
    // NUL-terminated ASCII name, at most seven bytes. Fixed ownership,
    // intentionally not used to register/authorize any channel.
    std::array<char, 8> name{};
    std::uint32_t options{};
};

struct GccClientSettings
{
    std::uint32_t clientVersion{};
    std::uint16_t requestedWidth{};
    std::uint16_t requestedHeight{};
    // Optional Client Core replay/capability fields. Presence is explicit;
    // zero can be a meaningful wire value and must not mean "absent".
    std::uint16_t earlyCapabilityFlags{};
    std::uint32_t serverSelectedProtocol{};
    std::uint32_t encryptionMethods{};
    std::uint32_t extEncryptionMethods{};
    std::array<GccChannel, kMaximumStaticChannelCount> channels{};
    std::uint8_t channelCount{};
    bool hasEarlyCapabilityFlags{};
    bool hasServerSelectedProtocol{};
    bool hasNetworkData{};
    bool hasClusterData{};
};

[[nodiscard]] constexpr bool gccClientSupportsDynamicVirtualChannelGraphics(
    const GccClientSettings &settings) noexcept
{
    return settings.hasEarlyCapabilityFlags &&
           (settings.earlyCapabilityFlags &
            kGccClientCoreSupportsDynamicVirtualChannelGraphics) != 0U;
}

struct GccParseResult
{
    GccClientSettings settings{};
    GccError error{GccError::None};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == GccError::None;
    }
};

// Read PER-encoded GCC Conference Create Request inside MCS userData.
// Currently accepts the standard single-userData, no-optional-fields
// conference-name encoding. Reject other conference layouts rather than
// assuming those layouts were validated. No memory allocation, raw pointers,
// persistent borrowed views, MCS response or channel authorization.
[[nodiscard]] GccParseResult parseGccConferenceCreate(
    std::span<const std::uint8_t> gccUserData) noexcept;

} // namespace rdp_server::server::transport
