// SPDX-License-Identifier: GPL-3.0-or-later
#include "base64_codec.h"

#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace rdp_server::server::security
{
namespace
{
constexpr char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
[[nodiscard]] constexpr int digit(unsigned char ch) noexcept
{
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}
} // namespace

bool encodeBase64(std::span<const std::uint8_t> bytes,
                  std::string &output) noexcept
{
    output.clear();
    if (bytes.size() > kMaximumBase64DecodedBytes) return false;
    try
    {
        std::string encoded;
        encoded.reserve(((bytes.size() + 2U) / 3U) * 4U);
        for (std::size_t i = 0; i < bytes.size(); i += 3)
        {
            const auto left = bytes[i];
            const auto middle = i + 1 < bytes.size() ? bytes[i+1] : 0U;
            const auto right = i + 2 < bytes.size() ? bytes[i+2] : 0U;
            encoded.push_back(kAlphabet[left >> 2U]);
            encoded.push_back(kAlphabet[((left & 3U) << 4U) | (middle >> 4U)]);
            encoded.push_back(i + 1 < bytes.size()
                ? kAlphabet[((middle & 15U) << 2U) | (right >> 6U)] : '=');
            encoded.push_back(i + 2 < bytes.size()
                ? kAlphabet[right & 63U] : '=');
        }
        output.swap(encoded);
        return true;
    }
    catch (...) { output.clear(); return false; }
}

bool decodeBase64(std::string_view input,
                  std::vector<std::uint8_t> &output) noexcept
{
    output.clear();
    if (input.size() > kMaximumBase64EncodedBytes ||
        input.size() % 4U != 0U)
        return false;
    try
    {
        std::vector<std::uint8_t> decoded;
        decoded.reserve((input.size() / 4U) * 3U);
        for (std::size_t i = 0; i < input.size(); i += 4)
        {
            const int a = digit(static_cast<unsigned char>(input[i]));
            const int b = digit(static_cast<unsigned char>(input[i + 1]));
            const bool padC = input[i + 2] == '=';
            const bool padD = input[i + 3] == '=';
            const int c = padC ? 0 : digit(static_cast<unsigned char>(input[i + 2]));
            const int d = padD ? 0 : digit(static_cast<unsigned char>(input[i + 3]));
            if (a < 0 || b < 0 || c < 0 || d < 0 ||
                (padC && !padD) ||
                ((padC || padD) && i + 4 != input.size()) ||
                (padC && (b & 15) != 0) ||
                (!padC && padD && (c & 3) != 0))
                return false; // strict canonical padding, no hidden bits
            decoded.push_back(static_cast<std::uint8_t>((a << 2) | (b >> 4)));
            if (!padC)
                decoded.push_back(static_cast<std::uint8_t>((b << 4) | (c >> 2)));
            if (!padD)
                decoded.push_back(static_cast<std::uint8_t>((c << 6) | d));
        }
        if (decoded.size() > kMaximumBase64DecodedBytes)
            return false;
        output.swap(decoded);
        return true;
    }
    catch (...) { output.clear(); return false; }
}
} // namespace rdp_server::server::security
