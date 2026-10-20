// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/standalone_spnego.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using namespace rdp_server::server::security;

namespace
{

using Bytes = std::vector<std::uint8_t>;

constexpr NtlmServerChallenge kServerChallenge{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
constexpr std::uint64_t kTimestamp = 0x0102030405060708ULL;
constexpr std::array<std::uint8_t, 10> kNtlmOid{
    0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a};
constexpr std::array<std::uint8_t, 9> kKerberosOid{
    0x2a,0x86,0x48,0x86,0xf7,0x12,0x01,0x02,0x02};
constexpr std::array<std::uint8_t, 6> kSpnegoOid{
    0x2b,0x06,0x01,0x05,0x05,0x02};

constexpr std::array<std::uint8_t, 232> kMicrosoftAuthenticateMessage{
    0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
    0x03,0x00,0x00,0x00,0x18,0x00,0x18,0x00,
    0x6c,0x00,0x00,0x00,0x54,0x00,0x54,0x00,
    0x84,0x00,0x00,0x00,0x0c,0x00,0x0c,0x00,
    0x48,0x00,0x00,0x00,0x08,0x00,0x08,0x00,
    0x54,0x00,0x00,0x00,0x10,0x00,0x10,0x00,
    0x5c,0x00,0x00,0x00,0x10,0x00,0x10,0x00,
    0xd8,0x00,0x00,0x00,0x35,0x82,0x88,0xe2,
    0x05,0x01,0x28,0x0a,0x00,0x00,0x00,0x0f,
    0x44,0x00,0x6f,0x00,0x6d,0x00,0x61,0x00,
    0x69,0x00,0x6e,0x00,0x55,0x00,0x73,0x00,
    0x65,0x00,0x72,0x00,0x43,0x00,0x4f,0x00,
    0x4d,0x00,0x50,0x00,0x55,0x00,0x54,0x00,
    0x45,0x00,0x52,0x00,0x86,0xc3,0x50,0x97,
    0xac,0x9c,0xec,0x10,0x25,0x54,0x76,0x4a,
    0x57,0xcc,0xcc,0x19,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0x68,0xcd,0x0a,0xb8,
    0x51,0xe5,0x1c,0x96,0xaa,0xbc,0x92,0x7b,
    0xeb,0xef,0x6a,0x1c,0x01,0x01,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xaa,0xaa,0xaa,0xaa,
    0xaa,0xaa,0xaa,0xaa,0x00,0x00,0x00,0x00,
    0x02,0x00,0x0c,0x00,0x44,0x00,0x6f,0x00,
    0x6d,0x00,0x61,0x00,0x69,0x00,0x6e,0x00,
    0x01,0x00,0x0c,0x00,0x53,0x00,0x65,0x00,
    0x72,0x00,0x76,0x00,0x65,0x00,0x72,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xc5,0xda,0xd2,0x54,0x4f,0xc9,0x79,0x90,
    0x94,0xce,0x1c,0xe9,0x0b,0xc9,0xd0,0x3e};

[[nodiscard]] Bytes lengthBytes(std::size_t size)
{
    if (size < 128U)
        return {static_cast<std::uint8_t>(size)};
    if (size < 256U)
        return {0x81U, static_cast<std::uint8_t>(size)};
    return {
        0x82U,
        static_cast<std::uint8_t>(size >> 8U),
        static_cast<std::uint8_t>(size)};
}

[[nodiscard]] Bytes tlv(std::uint8_t tag, std::span<const std::uint8_t> body)
{
    Bytes output{tag};
    const auto encodedLength = lengthBytes(body.size());
    output.insert(output.end(), encodedLength.begin(), encodedLength.end());
    output.insert(output.end(), body.begin(), body.end());
    return output;
}

[[nodiscard]] Bytes append(Bytes left, std::span<const std::uint8_t> right)
{
    left.insert(left.end(), right.begin(), right.end());
    return left;
}

[[nodiscard]] Bytes oid(std::span<const std::uint8_t> value)
{
    return tlv(0x06U, value);
}

[[nodiscard]] std::array<std::uint8_t, 40> negotiateMessage()
{
    std::array<std::uint8_t, 40> message{};
    constexpr std::array<std::uint8_t, 8> signature{
        'N','T','L','M','S','S','P',0};
    std::copy(signature.begin(), signature.end(), message.begin());
    message[8] = 1U;
    constexpr std::uint32_t flags =
        kNtlmNegotiateUnicode |
        kNtlmNegotiateNtlm |
        kNtlmNegotiateAlwaysSign |
        kRequiredStandaloneCredSspNtlmFlags |
        kNtlmNegotiateKeyExchange |
        kNtlmNegotiate56;
    message[12] = static_cast<std::uint8_t>(flags);
    message[13] = static_cast<std::uint8_t>(flags >> 8U);
    message[14] = static_cast<std::uint8_t>(flags >> 16U);
    message[15] = static_cast<std::uint8_t>(flags >> 24U);
    return message;
}

[[nodiscard]] Bytes initialToken(
    const std::vector<Bytes> &mechanisms,
    std::span<const std::uint8_t> mechanismToken)
{
    Bytes mechanismList;
    for (const auto &mechanism : mechanisms)
    {
        const auto encoded = oid(mechanism);
        mechanismList.insert(
            mechanismList.end(), encoded.begin(), encoded.end());
    }

    Bytes fields = tlv(0xa0U, tlv(0x30U, mechanismList));
    if (!mechanismToken.empty())
    {
        const auto tokenField =
            tlv(0xa2U, tlv(0x04U, mechanismToken));
        fields.insert(fields.end(), tokenField.begin(), tokenField.end());
    }

    const auto init = tlv(0xa0U, tlv(0x30U, fields));
    Bytes body = oid(kSpnegoOid);
    body.insert(body.end(), init.begin(), init.end());
    return tlv(0x60U, body);
}

[[nodiscard]] Bytes continuationToken(
    std::span<const std::uint8_t> mechanismToken,
    std::span<const std::uint8_t> mechListMic = {})
{
    Bytes fields;
    if (!mechanismToken.empty())
    {
        const auto tokenField =
            tlv(0xa2U, tlv(0x04U, mechanismToken));
        fields.insert(fields.end(), tokenField.begin(), tokenField.end());
    }
    if (!mechListMic.empty())
    {
        const auto micField =
            tlv(0xa3U, tlv(0x04U, mechListMic));
        fields.insert(fields.end(), micField.begin(), micField.end());
    }
    return tlv(0xa1U, tlv(0x30U, fields));
}

[[nodiscard]] Bytes expectedServerResponse(
    std::span<const std::uint8_t> responseToken)
{
    constexpr std::array<std::uint8_t, 3> incomplete{
        0x0a,0x01,0x01};
    Bytes fields = tlv(0xa0U, incomplete);
    const auto mechanism = tlv(0xa1U, oid(kNtlmOid));
    fields.insert(fields.end(), mechanism.begin(), mechanism.end());
    if (!responseToken.empty())
    {
        const auto token =
            tlv(0xa2U, tlv(0x04U, responseToken));
        fields.insert(fields.end(), token.begin(), token.end());
    }
    return tlv(0xa1U, tlv(0x30U, fields));
}

[[nodiscard]] bool configure(
    StandaloneSpnegoNtlmAcceptor &acceptor)
{
    return acceptor.configureChallenge(
        {kServerChallenge, u"Domain", u"Server", kTimestamp});
}

[[nodiscard]] std::array<char16_t, 8> password()
{
    return {u'P',u'a',u's',u's',u'w',u'o',u'r',u'd'};
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view testCase{argv[1]};

    if (testCase == "spnego-ntlm-first-negotiate-challenge")
    {
        StandaloneSpnegoNtlmAcceptor acceptor;
        assert(configure(acceptor));

        const auto negotiate = negotiateMessage();
        const auto initial = initialToken({Bytes(kNtlmOid.begin(),
                                                  kNtlmOid.end())},
                                          negotiate);
        std::array<std::uint8_t, kMaximumStandaloneSpnegoTokenBytes> reply{};
        const auto step = acceptor.acceptInitialToken(initial, reply);
        assert(step.status == StandaloneSpnegoStatus::Continue);
        assert(acceptor.stage() ==
               StandaloneSpnegoStage::AwaitNtlmAuthenticate);

        std::array<std::uint8_t, kMaximumStandaloneNtlmMessageBytes>
            challenge{};
        const auto encodedChallenge = encodeNtlmChallengeMessage(
            {kServerChallenge, u"Domain", u"Server", kTimestamp,
             kNtlmNegotiateUnicode |
                 kNtlmNegotiateNtlm |
                 kNtlmNegotiateAlwaysSign |
                 kRequiredStandaloneCredSspNtlmFlags |
                 kNtlmNegotiateKeyExchange |
                 kNtlmNegotiate56},
            challenge);
        assert(encodedChallenge);
        const auto expected = expectedServerResponse(
            std::span<const std::uint8_t>{challenge}.first(
                encodedChallenge.bytesWritten));
        assert(step.bytesWritten == expected.size());
        assert(std::equal(
            expected.begin(), expected.end(), reply.begin()));
        return 0;
    }

    if (testCase == "spnego-ntlm-authenticate-known-answer")
    {
        StandaloneSpnegoNtlmAcceptor acceptor;
        assert(configure(acceptor));

        const auto negotiate = negotiateMessage();
        const auto initial = initialToken({Bytes(kNtlmOid.begin(),
                                                  kNtlmOid.end())},
                                          negotiate);
        std::array<std::uint8_t, kMaximumStandaloneSpnegoTokenBytes> reply{};
        assert(acceptor.acceptInitialToken(initial, reply));

        EphemeralNtlmV2Credential credential;
        auto mutablePassword = password();
        assert(credential.configure(u"User", mutablePassword));

        const auto authenticate =
            continuationToken(kMicrosoftAuthenticateMessage);
        reply.fill(0);
        const auto finalStep = acceptor.acceptContinuationToken(
            authenticate, credential, reply);
        assert(finalStep.status ==
               StandaloneSpnegoStatus::MechanismVerified);
        assert(acceptor.stage() ==
               StandaloneSpnegoStage::MechanismVerified);

        constexpr std::array<std::uint8_t, 9> expectedFinal{
            0xa1,0x07,0x30,0x05,0xa0,0x03,0x0a,0x01,0x00};
        assert(finalStep.bytesWritten == expectedFinal.size());
        assert(std::equal(
            expectedFinal.begin(), expectedFinal.end(), reply.begin()));

        constexpr std::array<std::uint8_t, 21> plaintext{
            'C','r','e','d','S','S','P','-','s','e','r','v','e','r',
            '-','p','u','b','k','e','y'};
        std::array<std::uint8_t, plaintext.size()> sealed{};
        std::array<std::uint8_t, kNtlmMessageSignatureBytes> signature{};
        assert(acceptor.wrapServerMessage(
                   plaintext, sealed, signature) ==
               NtlmMessageSecurityResult::Processed);
        return 0;
    }

    if (testCase == "spnego-fallback-integrity-and-der-denials")
    {
        const auto negotiate = negotiateMessage();
        const std::vector<Bytes> mechanisms{
            Bytes(kKerberosOid.begin(), kKerberosOid.end()),
            Bytes(kNtlmOid.begin(), kNtlmOid.end())};

        StandaloneSpnegoNtlmAcceptor fallback;
        assert(configure(fallback));
        const std::array<std::uint8_t, 1> optimisticKerberos{0x01U};
        const auto initial =
            initialToken(mechanisms, optimisticKerberos);
        std::array<std::uint8_t, kMaximumStandaloneSpnegoTokenBytes> reply{};
        const auto selected = fallback.acceptInitialToken(initial, reply);
        assert(selected.status == StandaloneSpnegoStatus::Continue);
        assert(fallback.stage() ==
               StandaloneSpnegoStage::AwaitNtlmNegotiate);
        const auto expectedSelection = expectedServerResponse({});
        assert(selected.bytesWritten == expectedSelection.size());
        assert(std::equal(
            expectedSelection.begin(), expectedSelection.end(),
            reply.begin()));

        const auto type1 = continuationToken(negotiate);
        assert(fallback.acceptContinuationToken(
            type1, EphemeralNtlmV2Credential{}, reply).status ==
            StandaloneSpnegoStatus::Continue);
        assert(fallback.stage() ==
               StandaloneSpnegoStage::AwaitNtlmAuthenticate);

        EphemeralNtlmV2Credential credential;
        auto mutablePassword = password();
        assert(credential.configure(u"User", mutablePassword));
        const auto type3 =
            continuationToken(kMicrosoftAuthenticateMessage);
        assert(fallback.acceptContinuationToken(
                   type3, credential, reply).status ==
               StandaloneSpnegoStatus::UnsupportedMechanismIntegrity);
        assert(fallback.stage() == StandaloneSpnegoStage::Failed);

        StandaloneSpnegoNtlmAcceptor malformed;
        assert(configure(malformed));
        auto duplicate = initialToken(
            {Bytes(kNtlmOid.begin(), kNtlmOid.end()),
             Bytes(kNtlmOid.begin(), kNtlmOid.end())},
            negotiate);
        assert(malformed.acceptInitialToken(
                   duplicate, reply).status ==
               StandaloneSpnegoStatus::InvalidToken);
        assert(malformed.stage() == StandaloneSpnegoStage::Failed);
        return 0;
    }

    return 2;
}
