// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/credssp_tsrequest.h"
#include "security/credssp_credentials.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
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

[[nodiscard]] Bytes utf16Le(std::u16string_view text)
{
    Bytes result;
    result.reserve(text.size() * 2U);
    for (const char16_t character : text)
    {
        const auto codeUnit = static_cast<std::uint16_t>(character);
        result.push_back(static_cast<std::uint8_t>(codeUnit));
        result.push_back(static_cast<std::uint8_t>(codeUnit >> 8U));
    }
    return result;
}

[[nodiscard]] Bytes passwordCredentials(
    const Bytes &domain,
    const Bytes &user,
    const Bytes &password,
    std::uint8_t credentialType = 1)
{
    Bytes fields = octetContext(0xa0, domain);
    fields = append(fields, octetContext(0xa1, user));
    fields = append(fields, octetContext(0xa2, password));
    const Bytes passwordSequence = wrap(0x30, fields);

    const Bytes typeInteger = wrap(
        0x02, std::array<std::uint8_t, 1>{credentialType});
    return wrap(0x30, append(
        wrap(0xa0, typeInteger),
        octetContext(0xa1, passwordSequence)));
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


void testStrictPasswordCredentialFields()
{
    const auto valid = passwordCredentials(
        {}, utf16Le(u"alice"), utf16Le(u"correct horse battery staple"));
    const auto accepted = inspectCredSspCredentials(valid);
    assert(accepted);
    assert(accepted.kind == CredSspCredentialKind::Password);
    assert(accepted.error == CredSspCredentialError::None);

    assert(inspectCredSspCredentials(passwordCredentials(
        utf16Le(u"EXAMPLE"), utf16Le(u"alice"), utf16Le(u"secret"))));
    assert(inspectCredSspCredentials(
               passwordCredentials({}, {}, utf16Le(u"secret"))).error ==
           CredSspCredentialError::InvalidPasswordFields);
    assert(inspectCredSspCredentials(
               passwordCredentials({}, utf16Le(u"alice"), {})).error ==
           CredSspCredentialError::InvalidPasswordFields);

    auto embeddedNulUser = utf16Le(u"alice");
    embeddedNulUser[2] = 0;
    embeddedNulUser[3] = 0;
    assert(inspectCredSspCredentials(passwordCredentials(
               {}, embeddedNulUser, utf16Le(u"secret"))).error ==
           CredSspCredentialError::InvalidPasswordFields);

    auto embeddedNulPassword = utf16Le(u"secret");
    embeddedNulPassword[4] = 0;
    embeddedNulPassword[5] = 0;
    assert(inspectCredSspCredentials(passwordCredentials(
               {}, utf16Le(u"alice"), embeddedNulPassword)).error ==
           CredSspCredentialError::InvalidPasswordFields);

    auto oddUser = utf16Le(u"alice");
    oddUser.pop_back();
    assert(inspectCredSspCredentials(passwordCredentials(
               {}, oddUser, utf16Le(u"secret"))).error ==
           CredSspCredentialError::InvalidPasswordFields);

    const Bytes loneHighSurrogate{0x00, 0xd8};
    const Bytes loneLowSurrogate{0x00, 0xdc};
    const Bytes wrongSurrogatePair{0x00, 0xd8, 0x41, 0x00};
    const Bytes validSurrogatePair{0x3d, 0xd8, 0x00, 0xde};
    assert(inspectCredSspCredentials(passwordCredentials(
               {}, utf16Le(u"alice"), loneHighSurrogate)).error ==
           CredSspCredentialError::InvalidPasswordFields);
    assert(inspectCredSspCredentials(passwordCredentials(
               {}, utf16Le(u"alice"), loneLowSurrogate)).error ==
           CredSspCredentialError::InvalidPasswordFields);
    assert(inspectCredSspCredentials(passwordCredentials(
               {}, utf16Le(u"alice"), wrongSurrogatePair)).error ==
           CredSspCredentialError::InvalidPasswordFields);
    assert(inspectCredSspCredentials(passwordCredentials(
        {}, utf16Le(u"alice"), validSurrogatePair)));

    Bytes oversizedPassword(4098U, 0x41);
    assert(inspectCredSspCredentials(passwordCredentials(
               {}, utf16Le(u"alice"), oversizedPassword)).error ==
           CredSspCredentialError::InvalidPasswordFields);

    Bytes reorderedFields = octetContext(0xa1, utf16Le(u"alice"));
    reorderedFields = append(reorderedFields, octetContext(0xa0, Bytes{}));
    reorderedFields = append(
        reorderedFields, octetContext(0xa2, utf16Le(u"secret")));
    const Bytes reorderedPassword = wrap(0x30, reorderedFields);
    const Bytes typeInteger = wrap(
        0x02, std::array<std::uint8_t, 1>{1});
    const auto reordered = wrap(0x30, append(
        wrap(0xa0, typeInteger), octetContext(0xa1, reorderedPassword)));
    assert(inspectCredSspCredentials(reordered).error ==
           CredSspCredentialError::InvalidPasswordFields);

    auto nonCanonicalLength = valid;
    assert(nonCanonicalLength.size() < 128U);
    const auto encodedLength = nonCanonicalLength[1];
    nonCanonicalLength[1] = 0x81;
    nonCanonicalLength.insert(nonCanonicalLength.begin() + 2, encodedLength);
    assert(inspectCredSspCredentials(nonCanonicalLength).error ==
           CredSspCredentialError::InvalidDer);

    const auto smartCard = inspectCredSspCredentials(passwordCredentials(
        {}, utf16Le(u"alice"), utf16Le(u"secret"), 2));
    assert(smartCard && smartCard.kind == CredSspCredentialKind::SmartCard);
    const auto remoteGuard = inspectCredSspCredentials(passwordCredentials(
        {}, utf16Le(u"alice"), utf16Le(u"secret"), 6));
    assert(remoteGuard &&
           remoteGuard.kind == CredSspCredentialKind::RemoteGuard);
    assert(inspectCredSspCredentials(passwordCredentials(
               {}, utf16Le(u"alice"), utf16Le(u"secret"), 3)).error ==
           CredSspCredentialError::UnsupportedType);
}


[[nodiscard]] bool validUtf16LeForTest(
    std::span<const std::uint8_t> text,
    bool allowEmpty) noexcept
{
    if (text.empty())
        return allowEmpty;
    if ((text.size() & 1U) != 0)
        return false;

    for (std::size_t offset = 0; offset < text.size(); offset += 2U)
    {
        const auto codeUnit = static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(text[offset]) |
            (static_cast<std::uint16_t>(text[offset + 1U]) << 8U));
        if (codeUnit == 0)
            return false;
        if (codeUnit >= 0xd800U && codeUnit <= 0xdbffU)
        {
            if (offset + 3U >= text.size())
                return false;
            const auto trailing = static_cast<std::uint16_t>(
                static_cast<std::uint16_t>(text[offset + 2U]) |
                (static_cast<std::uint16_t>(text[offset + 3U]) << 8U));
            if (trailing < 0xdc00U || trailing > 0xdfffU)
                return false;
            offset += 2U;
        }
        else if (codeUnit >= 0xdc00U && codeUnit <= 0xdfffU)
            return false;
    }
    return true;
}

void testDelegatedAccountExtraction()
{
    const auto valid = passwordCredentials(
        {}, utf16Le(u"alice"), utf16Le(u"p\u00e4ss\U0001F512"));
    const auto alice = inspectCredSspDelegatedAccount(valid);
    assert(alice && alice.accountName() == "alice");

    std::u16string boundary(32U, u'a');
    const auto maximum = inspectCredSspDelegatedAccount(passwordCredentials(
        {}, utf16Le(boundary), utf16Le(u"secret")));
    assert(maximum && maximum.accountName().size() == 32U);

    std::u16string tooLong(33U, u'a');
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, utf16Le(tooLong), utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::InvalidUnixAccount);
    assert(!inspectCredSspDelegatedAccount(passwordCredentials(
        {}, {}, utf16Le(u"secret"))));
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, utf16Le(u"root"), utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::InvalidUnixAccount);
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, utf16Le(u"alice.name"), utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::InvalidUnixAccount);
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, utf16Le(u"Alice"), utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::InvalidUnixAccount);
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, utf16Le(u"al\u0131ce"), utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::InvalidUnixAccount);

    auto oddUser = utf16Le(u"alice");
    oddUser.pop_back();
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, oddUser, utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::InvalidCredential);
    auto embeddedNul = utf16Le(u"alice");
    embeddedNul[2] = 0;
    embeddedNul[3] = 0;
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, embeddedNul, utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::InvalidCredential);

    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, utf16Le(u"alice"), utf16Le(u"secret"), 2)).error ==
           CredSspDelegatedAccountError::UnsupportedCredentialType);
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, utf16Le(u"alice"), utf16Le(u"secret"), 6)).error ==
           CredSspDelegatedAccountError::UnsupportedCredentialType);

    const auto metadata = inspectCredSspCredentials(valid);
    assert(metadata && metadata.kind == CredSspCredentialKind::Password);
}

void testDelegatedDomainIdentityDenials()
{
    const auto emptyDomain = inspectCredSspDelegatedAccount(
        passwordCredentials({}, utf16Le(u"alice"), utf16Le(u"secret")));
    assert(emptyDomain && emptyDomain.accountName() == "alice");

    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               utf16Le(u"EXAMPLE"), utf16Le(u"alice"),
               utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::NonEmptyDomain);
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, utf16Le(u"DOMAIN\\alice"),
               utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::InvalidUnixAccount);
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, utf16Le(u"alice@OTHER.REALM"),
               utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::InvalidUnixAccount);
    assert(inspectCredSspDelegatedAccount(passwordCredentials(
               {}, utf16Le(u"\u0430lice"),
               utf16Le(u"secret"))).error ==
           CredSspDelegatedAccountError::InvalidUnixAccount);
}

void testDelegatedAccountSensitiveRetirement()
{
    Bytes plaintext = passwordCredentials(
        {}, utf16Le(u"alice"), utf16Le(u"p\u00e4ss\U0001F512"));
    {
        SensitiveBytesGuard guard{plaintext};
        const auto candidate = inspectCredSspDelegatedAccount(plaintext);
        assert(candidate && candidate.accountName() == "alice");
    }
    assert(std::all_of(
        plaintext.begin(), plaintext.end(),
        [](std::uint8_t value) { return value == 0; }));

    Bytes invalid = passwordCredentials(
        {}, utf16Le(u"root"), utf16Le(u"secret"));
    {
        SensitiveBytesGuard guard{invalid};
        assert(!inspectCredSspDelegatedAccount(invalid));
    }
    assert(std::all_of(
        invalid.begin(), invalid.end(),
        [](std::uint8_t value) { return value == 0; }));
}


[[nodiscard]] bool validDelegatedUnixAccountForTest(
    std::span<const std::uint8_t> userUtf16Le) noexcept
{
    if (userUtf16Le.empty() || (userUtf16Le.size() & 1U) != 0 ||
        userUtf16Le.size() > kMaximumDelegatedUnixAccountBytes * 2U)
    {
        return false;
    }

    std::array<char, kMaximumDelegatedUnixAccountBytes + 1U> account{};
    const std::size_t characterCount = userUtf16Le.size() / 2U;
    for (std::size_t index = 0; index < characterCount; ++index)
    {
        const std::size_t offset = index * 2U;
        if (userUtf16Le[offset + 1U] != 0)
            return false;
        const char character = static_cast<char>(userUtf16Le[offset]);
        const bool lowercase = character >= 'a' && character <= 'z';
        const bool digit = character >= '0' && character <= '9';
        if ((index == 0 && !lowercase && character != '_') ||
            (!lowercase && !digit && character != '_' && character != '-'))
        {
            return false;
        }
        account[index] = character;
    }
    return std::string_view(account.data(), characterCount) != "root";
}

void testDelegatedAccountAdversarialBoundaries()
{
    const Bytes password = utf16Le(u"secret");
    const Bytes seedUser = utf16Le(u"alice");
    const Bytes seed = passwordCredentials({}, seedUser, password);
    const Bytes original = seed;

    const auto owned = inspectCredSspDelegatedAccount(seed);
    assert(owned && owned.accountName() == "alice");
    assert(seed == original);

    // The published candidate owns its non-secret account bytes. It must not
    // borrow the decrypted credential buffer or any password bytes.
    Bytes retiredInput = seed;
    const auto retained = inspectCredSspDelegatedAccount(retiredInput);
    std::fill(retiredInput.begin(), retiredInput.end(), 0);
    assert(retained && retained.accountName() == "alice");

    const auto assertInspection = [&](const Bytes &credentials,
                                      bool expectedAccount)
    {
        const Bytes before = credentials;
        const auto first = inspectCredSspDelegatedAccount(credentials);
        const auto second = inspectCredSspDelegatedAccount(credentials);
        assert(credentials == before);
        assert(first.error == second.error);
        assert(first.accountLength == second.accountLength);
        assert(first.account == second.account);

        if (expectedAccount)
        {
            assert(first);
            assert(first.error == CredSspDelegatedAccountError::None);
            assert(first.accountLength != 0);
            assert(first.account[first.accountLength] == '\0');
        }
        else
        {
            assert(!first);
            assert(first.accountLength == 0);
            assert(first.accountName().empty());
            assert(std::all_of(
                first.account.begin(), first.account.end(),
                [](char value) { return value == '\0'; }));
        }
    };

    // Exhaust every ASCII replacement at every code-unit position of the
    // short account seed. The test-only syntax oracle decides whether the
    // changed username remains a valid local-account candidate.
    std::size_t mutationCount = 0;
    for (std::size_t codeUnit = 0; codeUnit < seedUser.size() / 2U; ++codeUnit)
    {
        for (std::uint16_t replacement = 1; replacement <= 0x7fU;
             ++replacement)
        {
            Bytes mutatedUser = seedUser;
            mutatedUser[codeUnit * 2U] =
                static_cast<std::uint8_t>(replacement);
            mutatedUser[codeUnit * 2U + 1U] = 0;
            const bool expected =
                validDelegatedUnixAccountForTest(mutatedUser);
            assertInspection(
                passwordCredentials({}, mutatedUser, password), expected);
            ++mutationCount;
        }

        // Structurally valid non-ASCII UTF-16 must never be silently folded
        // into an ASCII UNIX account candidate.
        Bytes nonAsciiUser = seedUser;
        nonAsciiUser[codeUnit * 2U + 1U] = 1;
        assert(validUtf16LeForTest(nonAsciiUser, false));
        assertInspection(
            passwordCredentials({}, nonAsciiUser, password), false);
        ++mutationCount;
    }
    assert(mutationCount == 640U);

    // Rejected values with a long valid prefix are the failure-output hygiene
    // regression: no partial identity may remain in the public result array.
    for (const auto user : std::array<std::u16string_view, 7>{
             u"alice.name", u"alice@realm", u"alice\\domain",
             u"alice+tag", u"alice!", u"Alice", u"root"})
    {
        assertInspection(
            passwordCredentials({}, utf16Le(user), password), false);
    }

    std::u16string maximum(32U, u'a');
    assertInspection(
        passwordCredentials({}, utf16Le(maximum), password), true);
    std::u16string tooLong(33U, u'a');
    assertInspection(
        passwordCredentials({}, utf16Le(tooLong), password), false);

    const auto nonEmptyDomain = inspectCredSspDelegatedAccount(
        passwordCredentials(utf16Le(u"EXAMPLE"), seedUser, password));
    assert(nonEmptyDomain.error == CredSspDelegatedAccountError::NonEmptyDomain);
    assert(nonEmptyDomain.accountLength == 0);
    assert(std::all_of(
        nonEmptyDomain.account.begin(), nonEmptyDomain.account.end(),
        [](char value) { return value == '\0'; }));

    // Password changes do not influence the account candidate; parsing is
    // still syntax-only and remains insufficient for authentication.
    const auto otherPassword = inspectCredSspDelegatedAccount(
        passwordCredentials({}, seedUser, utf16Le(u"different")));
    assert(otherPassword && otherPassword.accountName() == "alice");
}

void assertDeterministicCredentialInspection(const Bytes &input)
{
    const Bytes original = input;
    const auto first = inspectCredSspCredentials(input);
    const auto second = inspectCredSspCredentials(input);
    assert(input == original);
    assert(first.kind == second.kind && first.error == second.error);
    assert(first.kind <= CredSspCredentialKind::RemoteGuard);
    assert(first.error <= CredSspCredentialError::InvalidPasswordFields);
    if (first.error != CredSspCredentialError::None)
        assert(first.kind == CredSspCredentialKind::None);
    else
        assert(first.kind != CredSspCredentialKind::None);
}

void assertPasswordCredentialAccepted(const Bytes &input)
{
    assertDeterministicCredentialInspection(input);
    const auto inspection = inspectCredSspCredentials(input);
    assert(inspection.kind == CredSspCredentialKind::Password);
    assert(inspection.error == CredSspCredentialError::None);
}

void assertPasswordCredentialDenied(const Bytes &input)
{
    assertDeterministicCredentialInspection(input);
    assert(!inspectCredSspCredentials(input));
}

void testPasswordCredentialNestedDerMutations()
{
    const Bytes domain = utf16Le(u"DOMAIN");
    const Bytes username = utf16Le(u"alice");
    const Bytes password = utf16Le(u"secret");
    const Bytes seed = passwordCredentials(domain, username, password);
    assert(seed.size() == 59U);
    assertPasswordCredentialAccepted(seed);

    // Every one-byte complement of this short seed is deterministic and
    // bounded. A successful mutation may occur only inside a known text
    // payload, and the independent test-only Unicode oracle must still accept
    // all three unchanged-length payloads.
    const auto payloadStart = [&](const Bytes &field)
    {
        const auto found = std::search(seed.begin(), seed.end(),
                                       field.begin(), field.end());
        assert(found != seed.end());
        return static_cast<std::size_t>(found - seed.begin());
    };
    const std::array<std::pair<std::size_t, std::size_t>, 3> payloadRanges{{
        {payloadStart(domain), domain.size()},
        {payloadStart(username), username.size()},
        {payloadStart(password), password.size()},
    }};

    std::size_t bytewiseMutationCount = 0;
    for (std::size_t index = 0; index < seed.size(); ++index)
    {
        Bytes mutated = seed;
        mutated[index] ^= 0xffU;
        ++bytewiseMutationCount;
        assertDeterministicCredentialInspection(mutated);
        const auto inspection = inspectCredSspCredentials(mutated);
        if (inspection.kind == CredSspCredentialKind::Password)
        {
            std::size_t changedField = payloadRanges.size();
            for (std::size_t fieldIndex = 0;
                 fieldIndex < payloadRanges.size(); ++fieldIndex)
            {
                const auto [fieldStart, fieldLength] =
                    payloadRanges[fieldIndex];
                if (index >= fieldStart && index - fieldStart < fieldLength)
                {
                    changedField = fieldIndex;
                    break;
                }
            }
            assert(changedField < payloadRanges.size());
            for (std::size_t fieldIndex = 0;
                 fieldIndex < payloadRanges.size(); ++fieldIndex)
            {
                const auto [fieldStart, fieldLength] =
                    payloadRanges[fieldIndex];
                assert(validUtf16LeForTest(
                    std::span(mutated).subspan(fieldStart, fieldLength),
                    fieldIndex == 0));
            }
            assert(inspection.error == CredSspCredentialError::None);
        }
        else
            assert(inspection.error != CredSspCredentialError::None);
    }

    // Insertions, removals and truncations preserve the original parent
    // lengths, so none can remain a canonical complete TSCredentials value.
    for (std::size_t index = 0; index < seed.size(); ++index)
    {
        Bytes inserted = seed;
        inserted.insert(inserted.begin() + static_cast<std::ptrdiff_t>(index),
                        0x00);
        ++bytewiseMutationCount;
        assertPasswordCredentialDenied(inserted);

        Bytes removed = seed;
        removed.erase(removed.begin() + static_cast<std::ptrdiff_t>(index));
        ++bytewiseMutationCount;
        assertPasswordCredentialDenied(removed);

        Bytes truncated(seed.begin(),
                        seed.begin() + static_cast<std::ptrdiff_t>(index));
        ++bytewiseMutationCount;
        assertPasswordCredentialDenied(truncated);
    }
    assert(bytewiseMutationCount == 236U);

    const Bytes domainField = octetContext(0xa0, domain);
    const Bytes userField = octetContext(0xa1, username);
    const Bytes passwordField = octetContext(0xa2, password);
    const Bytes typeField = wrap(0xa0, wrap(
        0x02, std::array<std::uint8_t, 1>{1}));
    const auto credentialFromFields = [&](const Bytes &fields)
    {
        return wrap(0x30, append(typeField,
                   octetContext(0xa1, wrap(0x30, fields))));
    };

    std::size_t structuredCaseCount = 0;
    const auto denied = [&](const Bytes &candidate)
    {
        ++structuredCaseCount;
        assertPasswordCredentialDenied(candidate);
    };
    const auto accepted = [&](const Bytes &candidate)
    {
        ++structuredCaseCount;
        assertPasswordCredentialAccepted(candidate);
    };

    Bytes trailing = seed;
    trailing.push_back(0);
    denied(trailing);
    denied(credentialFromFields(
        append(append(domainField, userField), userField)));
    denied(credentialFromFields(append(domainField, passwordField)));
    denied(credentialFromFields(
        append(append(userField, domainField), passwordField)));
    denied(credentialFromFields(
        append(append(domainField, passwordField), userField)));
    accepted(credentialFromFields(
        append(append(domainField, userField), passwordField)));

    // Explicitly damage a nested context and an inner OCTET tag while
    // preserving the parent's original length.
    Bytes corruptContext = seed;
    const auto usernameFieldStart = std::search(
        seed.begin(), seed.end(), userField.begin(), userField.end());
    assert(usernameFieldStart != seed.end());
    corruptContext[static_cast<std::size_t>(
        usernameFieldStart - seed.begin())] = 0xa0;
    denied(corruptContext);

    Bytes corruptOctet = seed;
    corruptOctet[static_cast<std::size_t>(
        usernameFieldStart - seed.begin()) + 2U] = 0x05;
    denied(corruptOctet);
    assert(structuredCaseCount == 8U);
}

void testPasswordCredentialLengthBoundaryDenials()
{
    const Bytes username = utf16Le(u"a");
    const Bytes password = utf16Le(u"b");
    std::size_t corpusCaseCount = 0;
    const auto accepted = [&](const Bytes &candidate)
    {
        ++corpusCaseCount;
        assertPasswordCredentialAccepted(candidate);
    };
    const auto denied = [&](const Bytes &candidate)
    {
        ++corpusCaseCount;
        assertPasswordCredentialDenied(candidate);
    };

    // Canonical DER crosses short, 0x81, and 0x82 length forms while the
    // UTF-16 field oracle independently distinguishes even and odd lengths.
    for (const std::size_t bytes : std::array<std::size_t, 14>{
             0, 1, 2, 3, 126, 127, 128, 129,
             254, 255, 256, 257, 4094, 4096})
    {
        Bytes domain(bytes, 0x41);
        for (std::size_t offset = 1; offset < domain.size(); offset += 2)
            domain[offset] = 0;
        const auto credentials = passwordCredentials(domain, username,
                                                     password);
        if (bytes % 2 == 0 && bytes <= 4096)
            accepted(credentials);
        else
            denied(credentials);
    }
    for (const std::size_t bytes : std::array<std::size_t, 4>{
             4094, 4095, 4096, 4097})
    {
        Bytes field(bytes, 0x41);
        for (std::size_t offset = 1; offset < bytes; offset += 2)
            field[offset] = 0;
        const auto credentials = passwordCredentials({}, field, password);
        if (bytes % 2 == 0 && bytes <= 4096)
            accepted(credentials);
        else
            denied(credentials);
    }

    const auto canonicalShort = passwordCredentials({}, username, password);
    const auto canonical81 =
        passwordCredentials(Bytes(128, 0x41), username, password);
    const auto canonical82 =
        passwordCredentials(Bytes(256, 0x41), username, password);
    assert(canonicalShort[1] < 0x80U);
    assert(canonical81[1] == 0x81U);
    assert(canonical82[1] == 0x82U);

    const Bytes seed = canonicalShort;
    accepted(seed);

    // Malformed outer lengths cover BER indefinite form, nonminimal long
    // forms, leading zero, truncated/excessive length-of-length and hostile
    // declarations larger than the physically supplied input.
    for (const Bytes &length : std::array<Bytes, 9>{{
             {0x80}, {0x81}, {0x81, 0x01}, {0x82, 0x00, 0x7f},
             {0x83, 0x00, 0x00, 0x7f}, {0xff}, {0x82, 0xff, 0xff},
             {0x81, 0x00}, {0x82, 0x01}}})
    {
        Bytes malformed{0x30};
        malformed.insert(malformed.end(), length.begin(), length.end());
        malformed.insert(malformed.end(), seed.begin() + 2, seed.end());
        denied(malformed);
    }

    const Bytes domainField = octetContext(0xa0, {});
    const Bytes userField = octetContext(0xa1, username);
    const Bytes passwordField = octetContext(0xa2, password);
    const Bytes typeField = wrap(0xa0, wrap(
        0x02, std::array<std::uint8_t, 1>{1}));
    const auto credentialFromFields = [&](const Bytes &fields)
    {
        return wrap(0x30, append(typeField,
                   octetContext(0xa1, wrap(0x30, fields))));
    };
    const auto withRawUserContext = [&](const Bytes &rawUserContext)
    {
        return credentialFromFields(
            append(append(domainField, rawUserContext), passwordField));
    };
    const auto withRawUserOctet = [&](const Bytes &rawUserOctet)
    {
        return withRawUserContext(wrap(0xa1, rawUserOctet));
    };

    // The malformed length is deliberately nested under otherwise canonical
    // parents so rejection is attributable to the nested boundary.
    std::array<Bytes, 9> nestedMalformed{{
        withRawUserOctet(Bytes{0x04, 0x81, 0x02, 0x61, 0x00}),
        withRawUserOctet(Bytes{0x04, 0x82, 0x00, 0x02, 0x61, 0x00}),
        withRawUserOctet(Bytes{0x04, 0x80, 0x61, 0x00}),
        withRawUserOctet(Bytes{0x04, 0x82, 0x01}),
        withRawUserOctet(
            Bytes{0x04, 0x83, 0x00, 0x00, 0x02, 0x61, 0x00}),
        withRawUserOctet(Bytes{0x04, 0x03, 0x61, 0x00}),
        withRawUserContext(
            Bytes{0xa1, 0x81, 0x04, 0x04, 0x02, 0x61, 0x00}),
        {},
        {},
    }};
    nestedMalformed[7] = userField;
    nestedMalformed[7][1] =
        static_cast<std::uint8_t>(nestedMalformed[7][1] + 1U);
    nestedMalformed[7] = withRawUserContext(nestedMalformed[7]);
    nestedMalformed[8] = userField;
    nestedMalformed[8][1] =
        static_cast<std::uint8_t>(nestedMalformed[8][1] - 1U);
    nestedMalformed[8] = withRawUserContext(nestedMalformed[8]);
    for (const auto &malformed : nestedMalformed)
        denied(malformed);

    // The largest valid encoding under the complete 8192-byte cap is found
    // with a bounded descending scan, not by allocating from hostile lengths.
    Bytes longest;
    for (std::size_t domainBytes = 4096;; domainBytes -= 2U)
    {
        const auto credentials = passwordCredentials(
            Bytes(domainBytes, 0x41), Bytes(4096, 0x42), password);
        if (credentials.size() <= kMaximumDecryptedCredentialsBytes)
        {
            longest = credentials;
            break;
        }
        assert(domainBytes != 0);
    }
    assert(longest.size() == 8191U);
    accepted(longest);

    Bytes exactBound = longest;
    exactBound.push_back(0);
    assert(exactBound.size() == kMaximumDecryptedCredentialsBytes);
    denied(exactBound);

    Bytes overLimit = exactBound;
    overLimit.push_back(0);
    assert(overLimit.size() == kMaximumDecryptedCredentialsBytes + 1U);
    denied(overLimit);
    assert(corpusCaseCount == 40U);
}

void testPasswordCredentialUtf16MutationBoundaries()
{
    const Bytes baseline = utf16Le(u"abcde");
    std::size_t corpusCaseCount = 0;
    for (std::size_t fieldIndex = 0; fieldIndex < 3; ++fieldIndex)
    {
        const auto inspectField = [&](const Bytes &field)
        {
            Bytes fields[3]{baseline, baseline, baseline};
            fields[fieldIndex] = field;
            return passwordCredentials(fields[0], fields[1], fields[2]);
        };
        const auto accepted = [&](const Bytes &field)
        {
            ++corpusCaseCount;
            assert(validUtf16LeForTest(field, fieldIndex == 0));
            assertPasswordCredentialAccepted(inspectField(field));
        };
        const auto denied = [&](const Bytes &field)
        {
            ++corpusCaseCount;
            assert(!validUtf16LeForTest(field, fieldIndex == 0));
            assertPasswordCredentialDenied(inspectField(field));
        };
        for (std::size_t position : std::array<std::size_t, 3>{0, 2, 4})
        {
            auto validBmp = std::u16string(u"abcde");
            validBmp[position] = u'Z';
            accepted(utf16Le(validBmp));

            auto validPair = std::u16string(u"abcde");
            validPair.replace(position, 1, u"\U0001f600");
            accepted(utf16Le(validPair));

            auto invalidHigh = std::u16string(u"abcde");
            invalidHigh[position] = static_cast<char16_t>(0xd800);
            denied(utf16Le(invalidHigh));

            auto invalidLow = std::u16string(u"abcde");
            invalidLow[position] = static_cast<char16_t>(0xdc00);
            denied(utf16Le(invalidLow));

            const auto malformedPair = [&](char16_t second)
            {
                auto text = std::u16string(u"abcde");
                text.replace(position, 1,
                    std::u16string{static_cast<char16_t>(0xd800),
                                   second});
                denied(utf16Le(text));
            };
            malformedPair(static_cast<char16_t>(0xd800));
            malformedPair(u'Q');

            auto reversed = std::u16string(u"abcde");
            reversed.replace(position, 1,
                std::u16string{static_cast<char16_t>(0xdc00),
                               static_cast<char16_t>(0xd800)});
            denied(utf16Le(reversed));

            auto embeddedNull = std::u16string(u"abcde");
            embeddedNull[position] = 0;
            denied(utf16Le(embeddedNull));

            Bytes truncatedPair = utf16Le(validPair);
            truncatedPair.erase(
                truncatedPair.begin() + static_cast<std::ptrdiff_t>(
                    position * 2 + 2));
            denied(truncatedPair);

            truncatedPair = utf16Le(validPair);
            truncatedPair.erase(
                truncatedPair.begin() + static_cast<std::ptrdiff_t>(
                    position * 2 + 2),
                truncatedPair.begin() + static_cast<std::ptrdiff_t>(
                    position * 2 + 4));
            denied(truncatedPair);
        }
        Bytes odd = baseline;
        odd.pop_back();
        denied(odd);
        if (fieldIndex == 0)
            accepted({});
        else
            denied({});
    }
    assert(corpusCaseCount == 96U);
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

    // The first invalid tag byte must reject on THAT callback, without
    // awaiting another network/TLS record. Exercise all 255 invalid tags.
    for (unsigned int tag = 0; tag <= 0xffU; ++tag)
    {
        if (tag == 0x30U)
            continue;
        TsRequestFrameReader invalidFirstByte;
        const std::array<std::uint8_t, 1> byte{
            static_cast<std::uint8_t>(tag)};
        const auto outcome = invalidFirstByte.consume(byte);
        assert(outcome.bytesConsumed == 1);
        assert(outcome.status == TsRequestFrameStatus::Invalid);
        assert(outcome.error == TsRequestError::InvalidDer);
        assert(invalidFirstByte.completeDer().empty());
        assert(invalidFirstByte.bytesNeeded() == 0);
        assert(!invalidFirstByte.releaseFrame());
        assert(invalidFirstByte.consume(initialRequest()).status ==
               TsRequestFrameStatus::Closed);
    }
    // A valid one-byte SEQUENCE prefix must still await its DER length.
    TsRequestFrameReader validFirstByte;
    const std::array<std::uint8_t, 1> sequenceTag{0x30};
    const auto incompleteHeader = validFirstByte.consume(sequenceTag);
    assert(incompleteHeader.bytesConsumed == 1);
    assert(incompleteHeader.status == TsRequestFrameStatus::NeedMore);
    assert(validFirstByte.bytesNeeded() == 1);

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

void testServerReplyWire()
{
    // Two independently authored MS-CSSP 2.2.1 DER oracles, not
    // actual GSS/Kerberos exchanges or authenticated TLS outputs.
    constexpr std::array<std::uint8_t, 4> token{0x60, 0x82, 0x01, 0x00};
    const Bytes expectedNego{
        0x30, 0x13, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa1, 0x0c, 0x30, 0x0a, 0x30, 0x08,
        0xa0, 0x06, 0x04, 0x04, 0x60, 0x82, 0x01, 0x00};
    const auto nego = encodeCredSspServerTsRequest(
        6, CredSspServerReplyField::NegoToken, token);
    assert(nego == expectedNego);
    const auto parsedNego = parseCredSspTsRequest(nego);
    assert(parsedNego && parsedNego.value.tokenCount == 1);
    assert(std::equal(parsedNego.value.tokens[0].begin(),
                      parsedNego.value.tokens[0].end(), token.begin()));

    constexpr std::array<std::uint8_t, 4> encryptedBinding{
        0xde, 0xad, 0xbe, 0xef};
    const Bytes expectedBinding{
        0x30, 0x0d, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa3, 0x06, 0x04, 0x04, 0xde, 0xad, 0xbe, 0xef};
    const auto binding = encodeCredSspServerTsRequest(
        6, CredSspServerReplyField::EncryptedServerBinding,
        encryptedBinding);
    assert(binding == expectedBinding);
    const auto parsedBinding = parseCredSspTsRequest(binding);
    assert(parsedBinding && parsedBinding.value.hasPubKeyAuth);
    assert(parsedBinding.value.tokenCount == 0 &&
           !parsedBinding.value.hasAuthInfo &&
           !parsedBinding.value.hasClientNonce);
    assert(std::equal(parsedBinding.value.encryptedPubKeyAuth.begin(),
                      parsedBinding.value.encryptedPubKeyAuth.end(),
                      encryptedBinding.begin()));

    // Version 5 is the other permitted binding protocol version.
    const auto v5 = encodeCredSspServerTsRequest(
        5, CredSspServerReplyField::EncryptedServerBinding,
        encryptedBinding);
    assert(v5.size() == binding.size() && v5[6] == 5);
    assert(parseCredSspTsRequest(v5));

    // Test canonical short/0x81/0x82 DER lengths around boundaries.
    for (const std::size_t payloadLength :
         {std::size_t{1}, std::size_t{110}, std::size_t{128},
          std::size_t{256}, kMaximumCredSspTokenBytes})
    {
        const Bytes opaque(payloadLength, 0x5a);
        for (const auto field : {CredSspServerReplyField::NegoToken,
                                 CredSspServerReplyField::EncryptedServerBinding})
        {
            const auto encoded = encodeCredSspServerTsRequest(6, field, opaque);
            assert(!encoded.empty() &&
                   encoded.size() <= kMaximumCredSspRequestBytes);
            const auto parsed = parseCredSspTsRequest(encoded);
            assert(parsed);
            const auto borrowed = field == CredSspServerReplyField::NegoToken
                ? parsed.value.tokens[0] : parsed.value.encryptedPubKeyAuth;
            assert(borrowed.size() == payloadLength);
            assert(std::equal(borrowed.begin(), borrowed.end(), opaque.begin()));
            TsRequestFrameReader reader;
            const auto result = reader.consume(encoded);
            assert(result.status == TsRequestFrameStatus::Complete);
            assert(result.bytesConsumed == encoded.size());
            assert(reader.completeDer().size() == encoded.size());
            assert(reader.releaseFrame());
        }
    }
}

void testServerFailureReplyWire()
{
    // Independent MS-CSSP 2.2.1 DER oracles for version 6: a signed
    // 32-bit NTSTATUS INTEGER has exactly four bytes, including bit 31.
    constexpr std::array<std::uint8_t, 15> logonFailure{
        0x30, 0x0d, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa4, 0x06, 0x02, 0x04, 0xc0, 0x00, 0x00, 0x6d};
    constexpr std::array<std::uint8_t, 15> notSupported{
        0x30, 0x0d, 0xa0, 0x03, 0x02, 0x01, 0x06,
        0xa4, 0x06, 0x02, 0x04, 0xc0, 0x00, 0x00, 0xbb};
    for (auto [status, oracle] : {
        std::pair{CredSspServerFailure::LogonFailure, logonFailure},
        std::pair{CredSspServerFailure::NotSupported, notSupported}})
    {
        const auto bytes = encodeCredSspServerFailureTsRequest(6, status);
        assert(bytes == std::vector<std::uint8_t>(
            oracle.begin(), oracle.end()));
        const auto parsed = parseCredSspTsRequest(bytes);
        assert(parsed && parsed.value.version == 6);
        assert(parsed.value.hasErrorCode);
        assert(!parsed.value.hasAuthInfo &&
               !parsed.value.hasPubKeyAuth &&
               !parsed.value.hasClientNonce &&
               parsed.value.tokenCount == 0);
        assert(!parsed.value.initialNegoTokenOnly() &&
               !parsed.value.finalNegoAndBindingOnly());
        TsRequestFrameReader reader;
        const auto received = reader.consume(bytes);
        assert(received.status == TsRequestFrameStatus::Complete);
        assert(received.bytesConsumed == bytes.size());
        assert(reader.completeDer().size() == oracle.size());
        assert(reader.releaseFrame());
    }
}

void testServerFailureReplyRejections()
{
    for (const auto version :
        {std::uint8_t{0}, std::uint8_t{2}, std::uint8_t{3},
         std::uint8_t{4}, std::uint8_t{5}, std::uint8_t{7},
         std::uint8_t{255}})
    {
        // This milestone supports ONLY version 6 NTSTATUS error
        // responses; do not silently pretend v5 or v3/v4 is supported.
        assert(encodeCredSspServerFailureTsRequest(
            version, CredSspServerFailure::LogonFailure).empty());
        assert(encodeCredSspServerFailureTsRequest(
            version, CredSspServerFailure::NotSupported).empty());
    }
    assert(encodeCredSspServerFailureTsRequest(
        6, static_cast<CredSspServerFailure>(255)).empty());

    // No success status, no alternative INTEGER width/sign, no mixed
    // security fields and no provider token can be emitted by this API.
    const auto failure = encodeCredSspServerFailureTsRequest(
        6, CredSspServerFailure::LogonFailure);
    assert(failure.size() == 15);
    auto zeroStatus = failure;
    zeroStatus[11] = 0;
    zeroStatus[14] = 0; // malformed for the selected failure policy
    assert(zeroStatus != failure);
    auto nonminimal = failure;
    nonminimal[1] = 0x0e;
    nonminimal[8] = 0x07;
    nonminimal[10] = 0x05;
    nonminimal.insert(nonminimal.begin() + 11, 0xff);
    assert(!parseCredSspTsRequest(nonminimal));
    constexpr std::array<std::uint8_t, 1> injected{0x55};
    assert(encodeCredSspServerTsRequest(
        6, static_cast<CredSspServerReplyField>(254), injected).empty());
}

void testServerReplyRejections()
{
    constexpr std::array<std::uint8_t, 2> opaque{0x11, 0x22};
    for (const std::uint8_t unsupportedVersion :
         {std::uint8_t{0}, std::uint8_t{2}, std::uint8_t{4},
          std::uint8_t{7}, std::uint8_t{255}})
    {
        assert(encodeCredSspServerTsRequest(
            unsupportedVersion, CredSspServerReplyField::NegoToken,
            opaque).empty());
    }
    assert(encodeCredSspServerTsRequest(
        6, CredSspServerReplyField::NegoToken, {}).empty());
    assert(encodeCredSspServerTsRequest(
        6, CredSspServerReplyField::EncryptedServerBinding, {}).empty());
    assert(encodeCredSspServerTsRequest(
        6, static_cast<CredSspServerReplyField>(255), opaque).empty());
    const Bytes oversized(kMaximumCredSspTokenBytes + 1, 0xb1);
    for (const auto field : {CredSspServerReplyField::NegoToken,
                             CredSspServerReplyField::EncryptedServerBinding})
    {
        assert(encodeCredSspServerTsRequest(6, field, oversized).empty());
    }
}


void testFinalNegotiationBindingShape()
{
    // MS-CSSP 3.1.5: the LAST client SPNEGO token shares the frame
    // with encrypted pubKeyAuth and its 32-byte nonce in versions 5/6.
    const Bytes token{0xa1, 0x22, 0x33};
    const Bytes protectedHash{0x11, 0x22, 0x33, 0x44};
    const Bytes nonce(32, 0x6a);
    for (const std::uint8_t wireVersion : {std::uint8_t{5},
                                           std::uint8_t{6}})
    {
        Bytes body = append(version(wireVersion), tokens(token));
        body = append(body, octetContext(0xa3, protectedHash));
        body = append(body, octetContext(0xa5, nonce));
        const auto der = makeRequest(body);
        const auto parsed = parseCredSspTsRequest(der);
        assert(parsed && parsed.value.version == wireVersion);
        assert(parsed.value.finalNegoAndBindingOnly());
        assert(!parsed.value.initialNegoTokenOnly());
        assert(parsed.value.tokenCount == 1);
        assert(std::equal(parsed.value.tokens[0].begin(),
                          parsed.value.tokens[0].end(), token.begin()));
        assert(std::equal(parsed.value.encryptedPubKeyAuth.begin(),
                          parsed.value.encryptedPubKeyAuth.end(),
                          protectedHash.begin()));
        assert(std::equal(parsed.value.clientNonce.begin(),
                          parsed.value.clientNonce.end(), nonce.begin()));
        TsRequestFrameReader reader;
        for (const auto byte : der)
        {
            const auto step = reader.consume(
                std::span<const std::uint8_t>{&byte, 1});
            assert(step.bytesConsumed == 1);
            assert(step.status == TsRequestFrameStatus::NeedMore ||
                   step.status == TsRequestFrameStatus::Complete);
        }
        assert(reader.status() == TsRequestFrameStatus::Complete);
        assert(parseCredSspTsRequest(reader.completeDer())
                   .value.finalNegoAndBindingOnly());
        assert(reader.releaseFrame());
        assert(reader.completeDer().empty());
    }

    // The largest accepted 8192-byte ciphertext/token shapes use canonical
    // 0x82 DER lengths and remain within the existing 16 KiB frame cap.
    const Bytes nearLimit(8192, 0x44);
    const auto tooLargeTotal = makeRequest(append(
        append(append(version(6), tokens(nearLimit)),
               octetContext(0xa3, nearLimit)),
        octetContext(0xa5, nonce)));
    assert(!parseCredSspTsRequest(tooLargeTotal));
}

void testFinalNegotiationBindingRejections()
{
    const Bytes token{0xa1, 0x22};
    const Bytes binding{0x66, 0x77};
    const Bytes nonce(32, 0x09);
    auto base = append(version(6), tokens(token));
    const auto protectedField = octetContext(0xa3, binding);
    const auto nonceField = octetContext(0xa5, nonce);
    const auto good = makeRequest(append(append(base, protectedField),
                                         nonceField));
    assert(parseCredSspTsRequest(good).value.finalNegoAndBindingOnly());

    const auto assertNotFinal = [](const Bytes &der)
    {
        const auto parsed = parseCredSspTsRequest(der);
        assert(!parsed || !parsed.value.finalNegoAndBindingOnly());
    };
    assertNotFinal(makeRequest(base)); // missing binding and nonce
    assertNotFinal(makeRequest(append(base, nonceField)));
    assertNotFinal(makeRequest(append(base, protectedField)));
    assertNotFinal(makeRequest(append(version(6),
        append(protectedField, nonceField)))); // no GSS token
    assertNotFinal(makeRequest(append(
        append(append(base, octetContext(0xa2, binding)),
               protectedField), nonceField))); // credential mixing
    assertNotFinal(makeRequest(append(
        append(append(base, protectedField),
               wrap(0xa4, wrap(0x02, std::array<std::uint8_t, 1>{1}))),
        nonceField))); // NTSTATUS cannot authenticate
    assertNotFinal(makeRequest(append(append(base, protectedField),
        octetContext(0xa5, Bytes(31, 0x09)))));
    assertNotFinal(makeRequest(append(append(base, protectedField),
        octetContext(0xa5, Bytes(33, 0x09)))));
    assertNotFinal(makeRequest(append(append(base, protectedField),
        octetContext(0xa5, Bytes{}))));
    assertNotFinal(makeRequest(append(append(version(4), tokens(token)),
        append(protectedField, nonceField))));
    assertNotFinal(makeRequest(append(append(version(2), tokens(token)),
        append(protectedField, nonceField))));
    assertNotFinal(makeRequest(append(
        append(base, octetContext(0xa3, Bytes(8193, 0x33))),
        nonceField)));

    // Multiple NegoDataItem tokens are parsed but never acceptable
    // as a single final mechanism token.
    const Bytes item = wrap(0x30, wrap(0xa0, wrap(0x04, token)));
    const Bytes multiToken = wrap(0xa1, wrap(0x30, append(item, item)));
    assertNotFinal(makeRequest(append(
        append(append(version(6), multiToken), protectedField),
        nonceField)));

    auto damaged = good;
    damaged[0] = 0x31;
    assertNotFinal(damaged);
    damaged = good;
    damaged[1] = 0x80;
    assertNotFinal(damaged);
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
constexpr std::array<CredSspTestCase, 22> kCredSspTests{{
    {"credssp-der-basic", &testBasicCredSspDer},
    {"credssp-der-opaque", &testCredentialsStayOpaque},
    {"credssp-der-rejections", &testRejectMalformedFields},
    {"credssp-der-bounds", &testOversizeAndTokenLimit},
    {"credssp-der-mutations", &testAllByteMutationsRemainBounded},
    {"credssp-password-credential-strict-fields",
     &testStrictPasswordCredentialFields},
    {"credssp-password-credential-nested-der-mutations",
     &testPasswordCredentialNestedDerMutations},
    {"credssp-password-credential-length-boundary-denials",
     &testPasswordCredentialLengthBoundaryDenials},
    {"credssp-password-credential-utf16-mutation-boundaries",
     &testPasswordCredentialUtf16MutationBoundaries},
    {"credssp-delegated-account-extraction", &testDelegatedAccountExtraction},
    {"credssp-delegated-domain-identity-denials",
     &testDelegatedDomainIdentityDenials},
    {"credssp-delegated-account-sensitive-retirement",
     &testDelegatedAccountSensitiveRetirement},
    {"credssp-delegated-account-adversarial-boundaries",
     &testDelegatedAccountAdversarialBoundaries},
    {"credssp-stream-fragments", &testStreamAllFragmentBoundaries},
    {"credssp-stream-coalesced", &testStreamCoalescedAndLongDer},
    {"credssp-stream-rejections", &testStreamDerFailuresAndCancellation},
    {"credssp-server-reply-wire", &testServerReplyWire},
    {"credssp-server-reply-rejections", &testServerReplyRejections},
    {"credssp-server-failure-wire", &testServerFailureReplyWire},
    {"credssp-server-failure-rejections", &testServerFailureReplyRejections},
    {"credssp-final-negotiation-binding", &testFinalNegotiationBindingShape},
    {"credssp-final-binding-rejections", &testFinalNegotiationBindingRejections},
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
