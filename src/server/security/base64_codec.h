// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rdp_server::server::security
{

// Bounds untrusted RDP authentication/negotiation metadata to one allocation
// per small value. Base64 is an encoding, NOT cryptography or authentication.
inline constexpr std::size_t kMaximumBase64DecodedBytes = 8192;
inline constexpr std::size_t kMaximumBase64EncodedBytes =
    ((kMaximumBase64DecodedBytes + 2) / 3) * 4;

// Transactional operations: no output is retained on failure. C++23 caller
// owns buffers; the upstream-derived C implementation never holds pointers.
[[nodiscard]] bool encodeBase64(
    std::span<const std::uint8_t> source, std::string &output) noexcept;

[[nodiscard]] bool decodeBase64(
    std::string_view encoded, std::vector<std::uint8_t> &output) noexcept;

} // namespace rdp_server::server::security
