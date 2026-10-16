// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/base64_codec.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <array>
#include <cstdint>
#include <string>
#include <vector>
using namespace rdp_server::server::security;
int main()
{
    std::string encoded;
    std::vector<std::uint8_t> decoded;
    const std::array<std::uint8_t, 3> abc{'M','a','n'};
    assert(encodeBase64(abc, encoded) && encoded == "TWFu");
    assert(decodeBase64(encoded, decoded) && decoded.size() == 3);
    assert(decoded[0]=='M' && decoded[1]=='a' && decoded[2]=='n');
    const std::array<std::uint8_t, 1> one{'M'};
    assert(encodeBase64(one, encoded) && encoded == "TQ==");
    assert(decodeBase64(encoded, decoded) && decoded == std::vector<std::uint8_t>{'M'});
    const std::array<std::uint8_t, 2> two{'M','a'};
    assert(encodeBase64(two, encoded) && encoded == "TWE=");
    assert(decodeBase64(encoded, decoded) && decoded.size() == 2);
    assert(!decodeBase64("TR==", decoded) && decoded.empty()); // noncanonical bits
    assert(!decodeBase64("TWF=", decoded) && decoded.empty());
    assert(!decodeBase64("TQ=A", decoded) && decoded.empty());
    assert(!decodeBase64("TQ==AAAA", decoded) && decoded.empty());
    assert(!decodeBase64("TQ==\\n", decoded) && decoded.empty());
    assert(!decodeBase64("T!==", decoded) && decoded.empty());
    assert(!decodeBase64("TQ=", decoded) && decoded.empty());
    assert(decodeBase64("", decoded) && decoded.empty());
    const std::vector<std::uint8_t> max(kMaximumBase64DecodedBytes, 255);
    assert(encodeBase64(max, encoded));
    assert(decodeBase64(encoded, decoded) && decoded == max);
    const std::vector<std::uint8_t> excess(kMaximumBase64DecodedBytes+1, 0);
    assert(!encodeBase64(excess, encoded) && encoded.empty());
}
