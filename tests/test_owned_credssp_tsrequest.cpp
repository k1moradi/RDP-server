// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/credssp_tsrequest.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace rdp_server::server::security;

namespace
{

using Bytes = std::vector<std::uint8_t>;

[[nodiscard]] Bytes derLength(std::size_t length)
{
    if (length < 128)
    {
        return {static_cast<std::uint8_t>(length)};
    }
    if (length <= 255)
    {
        return {0x81, static_cast<std::uint8_t>(length)};
    }
    assert(length <= 65535);
    return {0x82, static_cast<std::uint8_t>(length >> 8U),
            static_cast<std::uint8_t>(length)};
}

[[nodiscard]] Bytes wrap(std::uint8_t tag, std::span<const std::uint8_t> value)
{
    Bytes result{tag};
    const auto size = derLength(value.size());
    result.insert(result.end(), size.begin(), size.end());
    result.insert(result.end(), value.begin(), value.end());
    return result;
}

[[nodiscard]] Bytes append(Bytes first, const Bytes &second)
{
    first.insert(first.end(), second.begin(), second.end());
    return first;
}

[[nodiscard]] Bytes version(std::uint8_t value)
{
    const Bytes integer = wrap(0x02, std::array<std::uint8_t, 1>{value});
    return wrap(0xa0, integer);
}

[[nodiscard]] Bytes tokens(const Bytes &token)
{
    const Bytes octet = wrap(0x04, token);
    const Bytes context = wrap(0xa0, octet);
    const Bytes entry = wrap(0x30, context);
    const Bytes sequence = wrap(0x30, entry);
    return wrap(0xa1, sequence);
}

[[nodiscard]] Bytes makeRequest(Bytes fields)
{
    return wrap(0x30, fields);
}

[[nodiscard]] Bytes initialRequest()
{
    const Bytes opaqueSpnego{0x60, 0x82, 0x01, 0x00};
    return makeRequest(append(version(6), tokens(opaqueSpnego)));
}

[[nodiscard]] Bytes octetContext(std::uint8_t tag, const Bytes &data)
{
    const auto octet = wrap(0x04, data);
    return wrap(tag, octet);
}

void testBasicCredSspDer()
{
    const Bytes fixture{
        0x30, 0x13, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa1, 0x0c, 0x30, 0x0a, 0x30, 0x08,
        0xa0, 0x06, 0x04, 0x04, 0x60, 0x82, 0x01, 0x00,
    };
    assert(initialRequest() == fixture);
    const auto parsed = parseCredSspTsRequest(fixture);
    assert(parsed);
    assert(parsed.value.version == 6);
    assert(parsed.value.initialNegoTokenOnly());
    assert(parsed.value.tokenCount == 1);
    assert(parsed.value.tokens[0].size() == 4);
    assert(parsed.value.tokens[0][0] == 0x60);
    assert(parsed.value.tokens[0].data() >= fixture.data());
    assert(parsed.value.tokens[0].data() + 4 <=
           fixture.data() + fixture.size());
    assert(!parsed.value.hasAuthInfo);
    assert(!parsed.value.hasPubKeyAuth);
    assert(!parsed.value.hasErrorCode);
    assert(!parsed.value.hasClientNonce);
    for (std::uint8_t wireVersion = 2; wireVersion <= 6; ++wireVersion)
    {
        auto request = fixture;
        request[6] = wireVersion;
        const auto result = parseCredSspTsRequest(request);
        assert(result && result.value.version == wireVersion);
    }
}

void testCredentialsStayOpaque()
{
    const Bytes opaqueSpnego{0xa0, 0x00};
    const Bytes privatePayload{0xa1, 0xb2, 0xc3, 0xd4};
    const Bytes nonce(32, 0x5e);
    Bytes fields = append(version(6), tokens(opaqueSpnego));
    fields = append(fields, octetContext(0xa2, privatePayload));
    fields = append(fields, octetContext(0xa3, privatePayload));
    const auto negativeStatus = wrap(
        0x02, std::array<std::uint8_t, 4>{0xc0, 0x00, 0x00, 0x01});
    fields = append(fields, wrap(0xa4, negativeStatus));
    fields = append(fields, octetContext(0xa5, nonce));
    const auto input = makeRequest(fields);
    const auto result = parseCredSspTsRequest(input);
    assert(result);
    assert(result.value.version == 6);
    assert(result.value.tokenCount == 1);
    assert(!result.value.initialNegoTokenOnly());
    assert(result.value.hasAuthInfo && result.value.hasPubKeyAuth);
    assert(result.value.hasErrorCode && result.value.hasClientNonce);
    // Both views borrow the encrypted DER input, never own a GSS buffer.
    assert(result.value.encryptedPubKeyAuth.size() ==
           privatePayload.size());
    assert(std::equal(result.value.encryptedPubKeyAuth.begin(),
                      result.value.encryptedPubKeyAuth.end(),
                      privatePayload.begin()));
    assert(result.value.clientNonce.size() == nonce.size());
    assert(std::equal(result.value.clientNonce.begin(),
                      result.value.clientNonce.end(), nonce.begin()));
    const auto withinInput = [&](std::span<const std::uint8_t> view) {
        return view.data() >= input.data() &&
               view.data() + view.size() <= input.data() + input.size();
    };
    assert(withinInput(result.value.encryptedPubKeyAuth));
    assert(withinInput(result.value.clientNonce));
    // No decrypted credential bytes or private-key binding is returned.
    assert(result.value.tokens[1].empty());

    const auto nonceV4 = makeRequest(
        append(version(4), octetContext(0xa5, nonce)));
    const auto wrong = parseCredSspTsRequest(nonceV4);
    assert(!wrong && wrong.error == TsRequestError::InvalidNonce);
    assert(wrong.value.tokenCount == 0);
    assert(wrong.value.encryptedPubKeyAuth.empty());
    assert(wrong.value.clientNonce.empty());
}

void testRejectMalformedFields()
{
    const auto fixture = initialRequest();
    for (std::size_t length = 0; length < fixture.size(); ++length)
    {
        const auto invalid = parseCredSspTsRequest(
            std::span(fixture).first(length));
        assert(!invalid);
        assert(invalid.value.tokenCount == 0);
    }
    auto malformed = fixture;
    malformed[0] = 0x31; // not SEQUENCE
    assert(!parseCredSspTsRequest(malformed));
    malformed = fixture;
    malformed[1] = 0x80; // indefinite DER length
    assert(!parseCredSspTsRequest(malformed));
    malformed = fixture;
    malformed[1] = 0x81; // nonminimal long length
    malformed.insert(malformed.begin() + 2, 0x13);
    assert(!parseCredSspTsRequest(malformed));
    malformed = fixture;
    malformed[2] = 0xa1; // no mandatory first version
    assert(!parseCredSspTsRequest(malformed));
    malformed = fixture;
    malformed[6] = 1; // unsupported old version
    assert(parseCredSspTsRequest(malformed).error ==
           TsRequestError::InvalidVersion);
    malformed[6] = 7; // unsupported future semantics
    assert(!parseCredSspTsRequest(malformed));
    malformed = fixture;
    malformed[4] = 0x04; // version cannot be OCTET STRING
    assert(!parseCredSspTsRequest(malformed));
    malformed = fixture;
    malformed[8] = 0x00; // empty SEQUENCE encoded incorrectly
    assert(!parseCredSspTsRequest(malformed));
    malformed = fixture;
    malformed[16] = 0x05; // no OPTIONAL constructed OCTET here
    assert(!parseCredSspTsRequest(malformed));
    malformed = fixture;
    malformed.push_back(0x00); // trailing DER junk
    assert(!parseCredSspTsRequest(malformed));

    // Not allowed: duplicate, out-of-order or unknown context fields.
    const auto twice = makeRequest(
        append(append(version(6), version(6)),
               tokens(Bytes{0x01})));
    assert(parseCredSspTsRequest(twice).error ==
           TsRequestError::InvalidFields);
    const auto reordered = makeRequest(
        append(tokens(Bytes{1}), version(6)));
    assert(!parseCredSspTsRequest(reordered));
    assert(!parseCredSspTsRequest(makeRequest(
        append(version(6), wrap(0xa6, Bytes{0x02, 0x01, 0x01})))));
    assert(!parseCredSspTsRequest(
        makeRequest(append(version(6), tokens({})))));
    assert(!parseCredSspTsRequest(makeRequest(
        append(version(6), octetContext(0xa2, {})))));
}

void testOversizeAndTokenLimit()
{
    const Bytes huge(kMaximumCredSspRequestBytes + 1, 0);
    assert(parseCredSspTsRequest(huge).error ==
           TsRequestError::InvalidDer);
    const Bytes oversizedToken(kMaximumCredSspTokenBytes + 1, 0x41);
    const auto rejected = parseCredSspTsRequest(makeRequest(
        append(version(6), tokens(oversizedToken))));
    assert(!rejected && rejected.error == TsRequestError::InvalidTokens);

    // 5 valid tokens must fail before writing into a fixed-size result.
    Bytes entries;
    for (std::size_t i = 0; i < kMaximumCredSspTokens + 1; ++i)
    {
        const Bytes octet = wrap(0x04, Bytes{0x51});
        entries = append(entries, wrap(0x30, wrap(0xa0, octet)));
    }
    auto request = makeRequest(append(version(6),
        wrap(0xa1, wrap(0x30, entries))));
    const auto response = parseCredSspTsRequest(request);
    assert(!response && response.value.tokenCount == 0);
}

void testAllByteMutationsRemainBounded()
{
    const auto fixture = initialRequest();
    for (std::size_t index = 0; index < fixture.size(); ++index)
    {
        auto mutated = fixture;
        mutated[index] ^= 0xffU;
        const auto parsed = parseCredSspTsRequest(mutated);
        if (parsed)
        {
            assert(parsed.value.tokenCount <= kMaximumCredSspTokens);
            for (std::size_t token = 0; token < parsed.value.tokenCount; ++token)
            {
                const auto bytes = parsed.value.tokens[token];
                assert(bytes.data() >= mutated.data());
                assert(bytes.data() + bytes.size() <=
                       mutated.data() + mutated.size());
            }
        }
        else
        {
            assert(parsed.value.tokenCount == 0);
            assert(!parsed.value.initialNegoTokenOnly());
        }
    }
}

} // namespace

int main()
{
    testBasicCredSspDer();
    testCredentialsStayOpaque();
    testRejectMalformedFields();
    testOversizeAndTokenLimit();
    testAllByteMutationsRemainBounded();
}
