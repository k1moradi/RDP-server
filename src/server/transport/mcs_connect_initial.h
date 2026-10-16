// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{

 // Bounded R1/R3 first decrypted MCS Connect-Initial TPKT intake.
 // A local allocation/processing limit, not the MS-RDPBCGR GCC userData
 // 1024/4096-byte conditional limit. The ONE shared cap prevents a
 // direct R3 caller from bypassing R1's bounded TLS intake.
inline constexpr std::size_t kMaximumInitialMcsTpktBytes = 8192;


// MS-RDPBCGR 2.2.1.3. Only the X.224 Data TPDU and BER encoded
// MCS Connect-Initial envelope are parsed. The GCC userData is BORROWED.
// No TLS, MCS domain admission, authentication or session is implemented.
enum class McsError : std::uint8_t
{
    None,
    InvalidTpkt,
    InvalidDataTpdu,
    InvalidConnectInitial,
    InvalidDomainParameters,
    InvalidUserData,
};

struct McsDomainParameters
{
    std::array<std::uint32_t, 8> values{};
    // Values are in MS-RDPBCGR DomainParameters order:
    // maxChannelIds, maxUserIds, maxTokenIds, numPriorities, minThroughput,
    // maxHeight, maxMCSPDUsize, protocolVersion.
};

struct McsConnectInitial
{
    McsDomainParameters target{};
    McsDomainParameters minimum{};
    McsDomainParameters maximum{};
    std::span<const std::uint8_t> gccUserData{};
};

// T.125/MS-RDPBCGR 3.3.5.3.3 domain negotiation runs only after a
// complete Connect-Initial has been parsed. No domain is allocated here.
struct McsDomainMergeResult
{
    McsDomainParameters value{};
    bool accepted{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return accepted;
    }
};

[[nodiscard]] McsDomainMergeResult mergeMcsDomainParameters(
    const McsConnectInitial &requested) noexcept;

struct McsParseResult
{
    McsConnectInitial value{};
    McsError error{McsError::None};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return error == McsError::None;
    }
};

// Validated, complete RFC 1006 TPKT containing exactly one X.224 Data TPDU.
// No fragmentation support; never assume that the contents are authenticated.
// The returned view is valid only while the caller's packet remains alive.
[[nodiscard]] bool parseDataTpdu(
    std::span<const std::uint8_t> completeTpkt,
    std::span<const std::uint8_t> &payload) noexcept;

[[nodiscard]] McsParseResult parseMcsConnectInitial(
    std::span<const std::uint8_t> completeTpkt) noexcept;

} // namespace rdp_server::server::transport
