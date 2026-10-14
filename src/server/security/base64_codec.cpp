// SPDX-License-Identifier: GPL-3.0-or-later
#include "base64_codec.h"

extern "C"
{
#include "base64.h" // Apache-2.0; owned source in src/vendor/xrdp-owned/common
}

#include <algorithm>

namespace rdp_server::server::security
{

bool encodeBase64(std::span<const std::uint8_t> source,
                  std::string &output) noexcept
{
    output.clear();
    if (source.size() > kMaximumBase64DecodedBytes)
    {
        return false;
    }
    try
    {
        const std::size_t encodedSize = ((source.size() + 2U) / 3U) * 4U;
        std::string encoded(encodedSize + 1U, '\0');
        const auto consumed = base64_encode(
            reinterpret_cast<const char *>(source.data()), source.size(),
            encoded.data(), encoded.size());
        if (consumed != source.size() ||
            encoded[encodedSize] != '\0')
        {
            return false;
        }
        encoded.resize(encodedSize);
        output.swap(encoded);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool decodeBase64(std::string_view encoded,
                  std::vector<std::uint8_t> &output) noexcept
{
    output.clear();
    if (encoded.size() > kMaximumBase64EncodedBytes ||
        encoded.find('\0') != std::string_view::npos)
    {
        return false;
    }
    try
    {
        std::string terminated(encoded); // upstream C API requires a NUL
        const auto maximumDecoded = std::min<std::size_t>(
            kMaximumBase64DecodedBytes,
            ((encoded.size() + 3U) / 4U) * 3U);
        std::vector<std::uint8_t> decoded(maximumDecoded);
        std::size_t actualSize = 0;
        const int status = base64_decode(
            terminated.c_str(), reinterpret_cast<char *>(decoded.data()),
            decoded.size(), &actualSize);
        if (status != 0 || actualSize > decoded.size())
        {
            return false;
        }
        decoded.resize(actualSize);
        output.swap(decoded);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

} // namespace rdp_server::server::security
