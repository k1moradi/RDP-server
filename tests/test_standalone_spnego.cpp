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
    std::span<const std::uint8_t> mechanismToken,
    bool includeNegHints = false)
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
    if (includeNegHints)
    {
        constexpr std::array<std::uint8_t, 6> hint{
            'T','E','R','M','S','R'};
        const auto hintName = tlv(0xa0U, tlv(0x1bU, hint));
        const auto negHints = tlv(0xa3U, tlv(0x30U, hintName));
        fields.insert(fields.end(), negHints.begin(), negHints.end());
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
    std::uint8_t state,
    bool includeSupportedMechanism,
    std::span<const std::uint8_t> responseToken = {},
    std::span<const std::uint8_t> mechListMic = {})
{
    const std::array<std::uint8_t, 3> stateValue{
        0x0a,0x01,state};
    Bytes fields = tlv(0xa0U, stateValue);
    if (includeSupportedMechanism)
    {
        const auto mechanism = tlv(0xa1U, oid(kNtlmOid));
        fields.insert(fields.end(), mechanism.begin(), mechanism.end());
    }
    if (!responseToken.empty())
    {
        const auto token =
            tlv(0xa2U, tlv(0x04U, responseToken));
        fields.insert(fields.end(), token.begin(), token.end());
    }
    if (!mechListMic.empty())
    {
        const auto mic = tlv(0xa3U, tlv(0x04U, mechListMic));
        fields.insert(fields.end(), mic.begin(), mic.end());
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


    if (testCase == "r9-microsoft-neginit2-ntlm-challenge")
    {
        // Windows-compatible synthetic token structure, not an owner capture:
        // Kerberos-first MechTypeList, optimistic Kerberos mechToken,
        // Microsoft's NegTokenInit2 negHints, then explicit NTLM Type 1.
        const std::vector<Bytes> mechanisms{
            Bytes(kKerberosOid.begin(), kKerberosOid.end()),
            Bytes(kNtlmOid.begin(), kNtlmOid.end())};
        const std::array<std::uint8_t, 1> optimisticKerberos{0x01U};
        StandaloneSpnegoNtlmAcceptor acceptor;
        assert(configure(acceptor));
        const auto initial = initialToken(
            mechanisms, optimisticKerberos, true);
        std::array<std::uint8_t, kMaximumStandaloneSpnegoTokenBytes> reply{};
        const auto selected = acceptor.acceptInitialToken(initial, reply);
        assert(selected.status == StandaloneSpnegoStatus::Continue);
        assert(acceptor.stage() ==
               StandaloneSpnegoStage::AwaitNtlmNegotiate);
        const auto expectedSelection = expectedServerResponse(3U, true);
        assert(selected.bytesWritten == expectedSelection.size());
        assert(std::equal(expectedSelection.begin(),
                          expectedSelection.end(), reply.begin()));

        const auto typeOne = continuationToken(negotiateMessage());
        reply.fill(0);
        const auto challenged = acceptor.acceptContinuationToken(
            typeOne, EphemeralNtlmV2Credential{}, reply);
        assert(challenged.status == StandaloneSpnegoStatus::Continue);
        assert(acceptor.stage() ==
               StandaloneSpnegoStage::AwaitNtlmAuthenticate);
        assert(challenged.bytesWritten > 0U);
        // The challenge contains NTLMSSP Type 2 only inside a strict
        // NegTokenResp: do not accept a naked NTLM downgrade.
        const auto challengeEnvelope = expectedServerResponse(
            1U, false, {});
        assert(challenged.bytesWritten > challengeEnvelope.size());
        assert(reply[0] == 0xa1U);
        return 0;
    }


    if (testCase == "r9-spnego-initial-rejection-categories")
    {
        // These exact redacted categories distinguish a malformed GSS
        // envelope from the unsupported mechanism list. No fallback occurs.
        std::array<std::uint8_t, kMaximumStandaloneSpnegoTokenBytes> reply{};
        StandaloneSpnegoNtlmAcceptor malformed;
        assert(configure(malformed));
        constexpr std::array<std::uint8_t, 3> invalidEnvelope{
            0x60U, 0x01U, 0xffU};
        const auto badEnvelope =
            malformed.acceptInitialToken(invalidEnvelope, reply);
        assert(badEnvelope.status == StandaloneSpnegoStatus::InvalidToken);
        assert(malformed.rejectionReason() ==
               StandaloneSpnegoRejectionReason::InitialEnvelope);

        StandaloneSpnegoNtlmAcceptor unsupported;
        assert(configure(unsupported));
        const auto kerberosOnly = initialToken(
            {Bytes(kKerberosOid.begin(), kKerberosOid.end())}, {});
        const auto badMechanism =
            unsupported.acceptInitialToken(kerberosOnly, reply);
        assert(badMechanism.status == StandaloneSpnegoStatus::InvalidToken);
        assert(unsupported.rejectionReason() ==
               StandaloneSpnegoRejectionReason::MechanismList);
        return 0;
    }

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
            1U, true,
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

    if (testCase == "spnego-fallback-mechlistmic-roundtrip")
    {
        constexpr std::array<std::uint8_t, 25> mechanismList{
            0x30,0x17,
            0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x12,0x01,0x02,0x02,
            0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a};
        constexpr std::array<std::uint8_t, 16> clientMechListMic{
            0x01,0x00,0x00,0x00,0x2f,0xc3,0xa4,0x9a,
            0x03,0x64,0x6d,0x31,0x00,0x00,0x00,0x00};
        constexpr std::array<std::uint8_t, 16> serverMechListMic{
            0x01,0x00,0x00,0x00,0x89,0x2e,0x18,0xaa,
            0xaa,0xc3,0x41,0x28,0x00,0x00,0x00,0x00};
        constexpr std::array<std::uint8_t, 21> serverPlaintext{
            'C','r','e','d','S','S','P','-','s','e','r','v','e','r',
            '-','p','u','b','k','e','y'};
        constexpr std::array<std::uint8_t, 21> serverCiphertextAfterMic{
            0x6b,0xb6,0x42,0xb3,0x70,0x08,0x7c,0x0a,0x8a,0xb5,0x66,
            0xfd,0x44,0x71,0x49,0x68,0x60,0xb0,0x06,0xdd,0xbb};
        constexpr std::array<std::uint8_t, 16> serverSignatureAfterMic{
            0x01,0x00,0x00,0x00,0x10,0x2a,0x48,0x96,
            0x4c,0x68,0xa4,0xda,0x01,0x00,0x00,0x00};
        constexpr std::array<std::uint8_t, 21> clientPlaintext{
            'C','r','e','d','S','S','P','-','c','l','i','e','n','t',
            '-','p','u','b','k','e','y'};
        constexpr std::array<std::uint8_t, 21> clientCiphertextAfterMic{
            0xb4,0x12,0x31,0xa5,0xb7,0x48,0x27,0x2b,0xec,0x33,0x66,
            0xe3,0xc8,0xe0,0x1a,0x7b,0x7f,0x1d,0x5f,0xa6,0x1d};
        constexpr std::array<std::uint8_t, 16> clientSignatureAfterMic{
            0x01,0x00,0x00,0x00,0xc2,0x40,0xe1,0x9b,
            0x8e,0x02,0xb0,0x27,0x01,0x00,0x00,0x00};

        const std::vector<Bytes> mechanisms{
            Bytes(kKerberosOid.begin(), kKerberosOid.end()),
            Bytes(kNtlmOid.begin(), kNtlmOid.end())};
        StandaloneSpnegoNtlmAcceptor acceptor;
        assert(configure(acceptor));

        const std::array<std::uint8_t, 1> optimisticKerberos{0x01U};
        const auto initial =
            initialToken(mechanisms, optimisticKerberos, true);
        std::array<std::uint8_t, kMaximumStandaloneSpnegoTokenBytes> reply{};
        const auto selected = acceptor.acceptInitialToken(initial, reply);
        assert(selected.status == StandaloneSpnegoStatus::Continue);
        const auto expectedSelection =
            expectedServerResponse(3U, true);
        assert(selected.bytesWritten == expectedSelection.size());
        assert(std::equal(
            expectedSelection.begin(), expectedSelection.end(),
            reply.begin()));

        const auto negotiate = negotiateMessage();
        const auto type1 = continuationToken(negotiate);
        reply.fill(0);
        const auto challengeStep = acceptor.acceptContinuationToken(
            type1, EphemeralNtlmV2Credential{}, reply);
        assert(challengeStep.status == StandaloneSpnegoStatus::Continue);

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
        const auto expectedChallenge = expectedServerResponse(
            1U, false,
            std::span<const std::uint8_t>{challenge}.first(
                encodedChallenge.bytesWritten));
        assert(challengeStep.bytesWritten == expectedChallenge.size());
        assert(std::equal(
            expectedChallenge.begin(), expectedChallenge.end(),
            reply.begin()));

        EphemeralNtlmV2Credential credential;
        auto mutablePassword = password();
        assert(credential.configure(u"User", mutablePassword));
        const auto type3 = continuationToken(
            kMicrosoftAuthenticateMessage, clientMechListMic);
        reply.fill(0);
        const auto completed = acceptor.acceptContinuationToken(
            type3, credential, reply);
        assert(completed.status ==
               StandaloneSpnegoStatus::MechanismVerified);
        const auto expectedComplete = expectedServerResponse(
            0U, false, {}, serverMechListMic);
        assert(completed.bytesWritten == expectedComplete.size());
        assert(std::equal(
            expectedComplete.begin(), expectedComplete.end(),
            reply.begin()));

        // mechListMIC signs the exact DER MechTypeList and consumes sequence
        // zero plus KEY_EXCH RC4 checksum bytes in each direction. The next
        // protected CredSSP-shaped message therefore starts at sequence one.
        assert(mechanismList.front() == 0x30U);
        std::array<std::uint8_t, serverPlaintext.size()> serverSealed{};
        std::array<std::uint8_t, kNtlmMessageSignatureBytes> serverSignature{};
        assert(acceptor.wrapServerMessage(
                   serverPlaintext, serverSealed, serverSignature) ==
               NtlmMessageSecurityResult::Processed);
        assert(serverSealed == serverCiphertextAfterMic);
        assert(serverSignature == serverSignatureAfterMic);

        std::array<std::uint8_t, clientPlaintext.size()> clientPlain{};
        assert(acceptor.unwrapClientMessage(
                   clientCiphertextAfterMic,
                   clientSignatureAfterMic,
                   clientPlain) ==
               NtlmMessageSecurityResult::Processed);
        assert(clientPlain == clientPlaintext);
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
        const auto expectedSelection =
            expectedServerResponse(3U, true);
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
        assert(fallback.failureStage() ==
               StandaloneSpnegoFailureStage::Mic);

        StandaloneSpnegoNtlmAcceptor tampered;
        assert(configure(tampered));
        const auto tamperedInitial =
            initialToken(mechanisms, optimisticKerberos, true);
        assert(tampered.acceptInitialToken(
            tamperedInitial, reply));
        assert(tampered.acceptContinuationToken(
            type1, EphemeralNtlmV2Credential{}, reply));
        constexpr std::array<std::uint8_t, 16> validMic{
            0x01,0x00,0x00,0x00,0x2f,0xc3,0xa4,0x9a,
            0x03,0x64,0x6d,0x31,0x00,0x00,0x00,0x00};
        auto badMic = validMic;
        badMic[7] ^= 0x01U;
        const auto tamperedType3 =
            continuationToken(kMicrosoftAuthenticateMessage, badMic);
        assert(tampered.acceptContinuationToken(
                   tamperedType3, credential, reply).status ==
               StandaloneSpnegoStatus::CredentialRejected);
        assert(tampered.stage() == StandaloneSpnegoStage::Failed);
        assert(tampered.failureStage() ==
               StandaloneSpnegoFailureStage::Mic);

        StandaloneSpnegoNtlmAcceptor wrongPassword;
        assert(configure(wrongPassword));
        const auto ntlmFirst = initialToken(
            {Bytes(kNtlmOid.begin(), kNtlmOid.end())}, negotiate);
        assert(wrongPassword.acceptInitialToken(ntlmFirst, reply));
        EphemeralNtlmV2Credential wrongCredential;
        std::array<char16_t, 8> wrongPasswordBytes{
            u'P',u'a',u's',u's',u'w',u'0',u'r',u'd'};
        assert(wrongCredential.configure(u"User", wrongPasswordBytes));
        assert(wrongPassword.acceptContinuationToken(
                   type3, wrongCredential, reply).status ==
               StandaloneSpnegoStatus::CredentialRejected);
        assert(wrongPassword.failureStage() ==
               StandaloneSpnegoFailureStage::NtlmNegotiation);

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
        assert(malformed.failureStage() ==
               StandaloneSpnegoFailureStage::Spnego);
        return 0;
    }

    return 2;
}
