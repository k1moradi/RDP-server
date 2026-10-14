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
#include <string_view>
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


void testStreamAllFragmentBoundaries()
{
    const auto fixture = initialRequest();
    for (std::size_t split = 0; split <= fixture.size(); ++split)
    {
        TsRequestFrameReader reader;
        assert(reader.bytesNeeded() == 2);
        const auto first = reader.consume(std::span(fixture).first(split));
        assert(first.bytesConsumed == split);
        if (split < fixture.size())
        {
            assert(first.status == TsRequestFrameStatus::NeedMore);
            assert(reader.completeDer().empty());
            assert(reader.bytesNeeded() > 0);
            const auto second = reader.consume(
                std::span(fixture).subspan(split));
            assert(second.bytesConsumed == fixture.size() - split);
            assert(second.status == TsRequestFrameStatus::Complete);
        }
        else
            assert(first.status == TsRequestFrameStatus::Complete);
        const auto frame = reader.completeDer();
        assert(frame.size() == fixture.size());
        assert(std::equal(frame.begin(), frame.end(), fixture.begin()));
        const auto parsed = parseCredSspTsRequest(frame);
        assert(parsed && parsed.value.initialNegoTokenOnly());
        assert(parsed.value.tokenCount == 1);
        assert(parsed.value.tokens[0].data() >= frame.data());
        assert(reader.bytesNeeded() == 0);
        assert(reader.releaseFrame());
        assert(reader.completeDer().empty());
        assert(reader.bytesNeeded() == 2);
    }

    // Exactly one byte per TLS callback, including initial DER header.
    TsRequestFrameReader reader;
    for (std::size_t i = 0; i < fixture.size(); ++i)
    {
        const auto event = reader.consume(std::span(fixture).subspan(i, 1));
        assert(event.bytesConsumed == 1);
        assert(event.status == (i + 1 == fixture.size()
                 ? TsRequestFrameStatus::Complete
                 : TsRequestFrameStatus::NeedMore));
    }
    assert(reader.completeDer().size() == fixture.size());
}

void testStreamCoalescedAndLongDer()
{
    const auto fixture = initialRequest();
    const auto paired = append(fixture, fixture);
    TsRequestFrameReader reader;
    const auto first = reader.consume(paired);
    assert(first.status == TsRequestFrameStatus::Complete);
    assert(first.bytesConsumed == fixture.size());
    assert(reader.completeDer().size() == fixture.size());
    assert(reader.releaseFrame());
    const auto second = reader.consume(std::span(paired).subspan(
        first.bytesConsumed));
    assert(second.status == TsRequestFrameStatus::Complete);
    assert(second.bytesConsumed == fixture.size());
    assert(reader.releaseFrame());

    // The outer header must use canonical 0x81 then 0x82 DER lengths.
    const auto medium = makeRequest(append(
        version(6), octetContext(0xa2, Bytes(200, 0x41))));
    const auto longForm = makeRequest(append(
        version(6), octetContext(0xa2, Bytes(512, 0x52))));
    const auto nearLimit = makeRequest(append(
        version(6), octetContext(0xa2, Bytes(16000, 0x7e))));
    assert(medium[0] == 0x30 && medium[1] == 0x81);
    assert(longForm[0] == 0x30 && longForm[1] == 0x82);
    assert(nearLimit.size() <= kMaximumCredSspRequestBytes);
    assert(nearLimit[1] == 0x82);
    for (const auto &input : {medium, longForm, nearLimit})
    {
        assert(parseCredSspTsRequest(input));
        TsRequestFrameReader framed;
        std::size_t position = 0;
        while (position < input.size())
        {
            const auto bytes = (std::min)(std::size_t{37},
                                          input.size() - position);
            const auto update = framed.consume(
                std::span(input).subspan(position, bytes));
            assert(update.bytesConsumed == bytes);
            position += update.bytesConsumed;
            assert(update.status == (position == input.size()
                 ? TsRequestFrameStatus::Complete
                 : TsRequestFrameStatus::NeedMore));
        }
        const auto message = framed.completeDer();
        assert(message.size() == input.size());
        assert(std::equal(message.begin(), message.end(), input.begin()));
        assert(framed.releaseFrame());
        assert(framed.completeDer().empty());
    }
}

void testStreamDerFailuresAndCancellation()
{
    // Invalid tag, indefinite length, unknown long form,
    // nonminimal DER lengths, over-limit content, semantic invalidity.
    const std::array<Bytes, 8> malformed{{
        Bytes{0x31, 0x00},
        Bytes{0x30, 0x80},
        Bytes{0x30, 0x83, 0x00, 0x01, 0x00},
        Bytes{0x30, 0x81, 0x7f},
        Bytes{0x30, 0x82, 0x00, 0xff},
        Bytes{0x30, 0x82, 0x00, 0x80},
        Bytes{0x30, 0x82, 0x40, 0x01},
        Bytes{0x30, 0x03, 0xa0, 0x01, 0x00},
    }};
    for (const auto &invalid : malformed)
    {
        TsRequestFrameReader reader;
        const auto outcome = reader.consume(invalid);
        assert(outcome.status == TsRequestFrameStatus::Invalid);
        assert(outcome.error != TsRequestError::None);
        assert(outcome.bytesConsumed <= invalid.size());
        assert(reader.completeDer().empty());
        assert(reader.bytesNeeded() == 0);
        assert(!reader.releaseFrame());
        assert(reader.consume(initialRequest()).status ==
               TsRequestFrameStatus::Closed);
    }

    const auto fixture = initialRequest();
    TsRequestFrameReader reader;
    const auto incomplete = reader.consume(std::span(fixture).first(5));
    assert(incomplete.status == TsRequestFrameStatus::NeedMore);
    assert(incomplete.bytesConsumed == 5);
    assert(reader.completeDer().empty());
    assert(!reader.releaseFrame());
    reader.close(); // EOF/timeout/peer cancellation before full DER.
    assert(reader.bytesNeeded() == 0);
    assert(reader.consume(fixture).status == TsRequestFrameStatus::Closed);

    TsRequestFrameReader replay;
    assert(replay.consume(fixture).status == TsRequestFrameStatus::Complete);
    // A second TSRequest cannot overwrite a completed, borrowed frame.
    const auto violation = replay.consume(fixture);
    assert(violation.status == TsRequestFrameStatus::Invalid);
    assert(violation.bytesConsumed == 0);
    assert(replay.completeDer().empty());
    assert(replay.consume(fixture).status == TsRequestFrameStatus::Closed);
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

struct CredSspTestCase
{
    std::string_view name;
    void (*run)();
};
constexpr std::array<CredSspTestCase, 8> kCredSspTests{{
    {"credssp-der-basic", &testBasicCredSspDer},
    {"credssp-der-opaque", &testCredentialsStayOpaque},
    {"credssp-der-rejections", &testRejectMalformedFields},
    {"credssp-der-bounds", &testOversizeAndTokenLimit},
    {"credssp-der-mutations", &testAllByteMutationsRemainBounded},
    {"credssp-stream-fragments", &testStreamAllFragmentBoundaries},
    {"credssp-stream-coalesced", &testStreamCoalescedAndLongDer},
    {"credssp-stream-rejections", &testStreamDerFailuresAndCancellation},
}};

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        for (const auto &test : kCredSspTests)
            test.run();
        return 0;
    }
    if (argc != 2)
        return 2;
    for (const auto &test : kCredSspTests)
    {
        if (std::string_view(argv[1]) == test.name)
        {
            test.run();
            return 0;
        }
    }
    return 2;
}
