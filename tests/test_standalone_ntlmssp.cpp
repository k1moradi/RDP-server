// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/standalone_ntlmssp.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <string_view>

using namespace rdp_server::server::security;

namespace
{

constexpr NtlmServerChallenge kServerChallenge{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
constexpr NtlmV2Key kEncryptedRandomSessionKey{
    0xc5,0xda,0xd2,0x54,0x4f,0xc9,0x79,0x90,
    0x94,0xce,0x1c,0xe9,0x0b,0xc9,0xd0,0x3e};
constexpr NtlmV2Key kExpectedExportedSessionKey{
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};
constexpr std::uint32_t kMicrosoftAuthenticateFlags = 0xe2888235U;

constexpr std::array<std::uint8_t, 40> kMicrosoftNegotiateMessage{
    0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
    0x01,0x00,0x00,0x00,0x07,0x82,0x08,0xa2,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x05,0x01,0x28,0x0a,0x00,0x00,0x00,0x0f};

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

constexpr std::array<std::uint8_t, 96> kExpectedChallengeMessage{
    0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
    0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x30,0x00,0x00,0x00,0x31,0x82,0x8a,0xe0,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x30,0x00,0x30,0x00,0x30,0x00,0x00,0x00,
    0x02,0x00,0x0c,0x00,0x44,0x00,0x6f,0x00,
    0x6d,0x00,0x61,0x00,0x69,0x00,0x6e,0x00,
    0x01,0x00,0x0c,0x00,0x53,0x00,0x65,0x00,
    0x72,0x00,0x76,0x00,0x65,0x00,0x72,0x00,
    0x07,0x00,0x08,0x00,0x08,0x07,0x06,0x05,
    0x04,0x03,0x02,0x01,0x00,0x00,0x00,0x00};

constexpr void storeLe16(
    std::uint8_t *output, std::uint16_t value) noexcept
{
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8U);
}

constexpr void storeLe32(
    std::uint8_t *output, std::uint32_t value) noexcept
{
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8U);
    output[2] = static_cast<std::uint8_t>(value >> 16U);
    output[3] = static_cast<std::uint8_t>(value >> 24U);
}

[[nodiscard]] std::array<char16_t, 8> password()
{
    return {u'P',u'a',u's',u's',u'w',u'o',u'r',u'd'};
}

[[nodiscard]] std::array<std::uint8_t, 160> micAuthenticateMessage()
{
    std::array<std::uint8_t, 160> message{};
    constexpr std::array<std::uint8_t, 8> signature{
        'N','T','L','M','S','S','P',0};
    std::copy(signature.begin(), signature.end(), message.begin());
    storeLe32(message.data() + 8U, 3U);

    storeLe32(message.data() + 16U, 80U);
    storeLe16(message.data() + 20U, 60U);
    storeLe16(message.data() + 22U, 60U);
    storeLe32(message.data() + 24U, 84U);
    storeLe16(message.data() + 28U, 2U);
    storeLe16(message.data() + 30U, 2U);
    storeLe32(message.data() + 32U, 80U);
    storeLe16(message.data() + 36U, 2U);
    storeLe16(message.data() + 38U, 2U);
    storeLe32(message.data() + 40U, 82U);
    storeLe32(message.data() + 48U, 84U);
    storeLe16(message.data() + 52U, 16U);
    storeLe16(message.data() + 54U, 16U);
    storeLe32(message.data() + 56U, 144U);
    storeLe32(
        message.data() + 60U,
        kNtlmNegotiateUnicode |
        kNtlmNegotiateNtlm |
        kRequiredStandaloneCredSspNtlmFlags |
        kNtlmNegotiateKeyExchange);

    std::fill(
        message.begin() + 64,
        message.begin() + 80,
        std::uint8_t{0x5a});
    message[80] = 'D';
    message[82] = 'U';

    const std::size_t blob = 100U;
    message[blob] = 1U;
    message[blob + 1U] = 1U;
    storeLe16(message.data() + 128U, 6U);
    storeLe16(message.data() + 130U, 4U);
    storeLe32(message.data() + 132U, 2U);
    storeLe16(message.data() + 136U, 0U);
    storeLe16(message.data() + 138U, 0U);

    std::fill(
        message.begin() + 144,
        message.end(),
        std::uint8_t{0x11});
    return message;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view testCase{argv[1]};

    if (testCase == "ntlmssp-negotiate-challenge-framing")
    {
        NtlmNegotiateMessage negotiate;
        assert(parseNtlmNegotiateMessage(
                   kMicrosoftNegotiateMessage, negotiate) ==
               NtlmMessageParseResult::Parsed);
        assert(negotiate.negotiateFlags == 0xa2088207U);

        std::array<std::uint8_t, 256> output{};
        NtlmChallengeMessageParameters parameters{
            kServerChallenge,
            u"Domain",
            u"Server",
            0x0102030405060708ULL,
            kMicrosoftAuthenticateFlags};
        const auto encoded =
            encodeNtlmChallengeMessage(parameters, output);
        assert(encoded);
        assert(encoded.bytesWritten ==
               kExpectedChallengeMessage.size());
        assert(encoded.negotiateFlags == 0xe08a8231U);
        assert(std::equal(
            kExpectedChallengeMessage.begin(),
            kExpectedChallengeMessage.end(),
            output.begin()));

        const auto tooSmall = encodeNtlmChallengeMessage(
            parameters,
            std::span(output).first(
                kExpectedChallengeMessage.size() - 1U));
        assert(tooSmall.status ==
               NtlmChallengeEncodeStatus::OutputTooSmall);
        assert(tooSmall.bytesWritten == 0U);

        parameters.clientNegotiateFlags =
            negotiate.negotiateFlags;
        assert(encodeNtlmChallengeMessage(parameters, output).status ==
               NtlmChallengeEncodeStatus::UnsupportedFlags);

        parameters.clientNegotiateFlags =
            kMicrosoftAuthenticateFlags;
        parameters.serverChallenge.fill(0U);
        assert(encodeNtlmChallengeMessage(parameters, output).status ==
               NtlmChallengeEncodeStatus::InvalidInput);
        return 0;
    }

    if (testCase ==
        "ntlmssp-microsoft-authenticate-bridge")
    {
        NtlmAuthenticateMessage authenticate;
        assert(parseNtlmAuthenticateMessage(
                   kMicrosoftAuthenticateMessage,
                   authenticate) ==
               NtlmMessageParseResult::Parsed);
        assert(authenticate.domain() ==
               std::u16string_view{u"Domain"});
        assert(authenticate.username() ==
               std::u16string_view{u"User"});
        assert(authenticate.negotiateFlags ==
               kMicrosoftAuthenticateFlags);
        assert(authenticate.messageIntegrityCode.empty());
        assert(authenticate.encryptedRandomSessionKey.size() ==
               kEncryptedRandomSessionKey.size());
        assert(std::equal(
            kEncryptedRandomSessionKey.begin(),
            kEncryptedRandomSessionKey.end(),
            authenticate.encryptedRandomSessionKey.begin()));

        EphemeralNtlmV2Credential credential;
        auto mutablePassword = password();
        assert(credential.configure(u"User", mutablePassword));
        NtlmV2SecurityContext context;
        assert(credential.verifyAndDeriveSecurityContext(
                   authenticate.verificationRequest(kServerChallenge),
                   context) ==
               NtlmV2VerifyResult::Verified);
        assert(context.active());
        assert(std::equal(
            kExpectedExportedSessionKey.begin(),
            kExpectedExportedSessionKey.end(),
            context.exportedSessionKey().begin()));
        return 0;
    }

    if (testCase ==
        "ntlmssp-security-buffer-mic-denials")
    {
        NtlmAuthenticateMessage parsed;

        auto invalidSignature = kMicrosoftAuthenticateMessage;
        invalidSignature[0] ^= 0x01U;
        assert(parseNtlmAuthenticateMessage(
                   invalidSignature, parsed) ==
               NtlmMessageParseResult::InvalidSignature);

        auto wrongType = kMicrosoftAuthenticateMessage;
        storeLe32(wrongType.data() + 8U, 2U);
        assert(parseNtlmAuthenticateMessage(
                   wrongType, parsed) ==
               NtlmMessageParseResult::WrongMessageType);

        auto invalidOffset = kMicrosoftAuthenticateMessage;
        storeLe32(invalidOffset.data() + 24U, 0xfffffff0U);
        assert(parseNtlmAuthenticateMessage(
                   invalidOffset, parsed) ==
               NtlmMessageParseResult::InvalidSecurityBuffer);

        auto oddUnicode = kMicrosoftAuthenticateMessage;
        storeLe16(oddUnicode.data() + 28U, 11U);
        assert(parseNtlmAuthenticateMessage(
                   oddUnicode, parsed) ==
               NtlmMessageParseResult::InvalidEncoding);

        auto unsupportedEncoding = kMicrosoftAuthenticateMessage;
        unsupportedEncoding[60] &=
            static_cast<std::uint8_t>(~kNtlmNegotiateUnicode);
        assert(parseNtlmAuthenticateMessage(
                   unsupportedEncoding, parsed) ==
               NtlmMessageParseResult::UnsupportedFlags);

        auto micMessage = micAuthenticateMessage();
        assert(parseNtlmAuthenticateMessage(
                   micMessage, parsed) ==
               NtlmMessageParseResult::Parsed);
        assert(parsed.messageIntegrityCode.size() == 16U);
        assert(std::all_of(
            parsed.messageIntegrityCode.begin(),
            parsed.messageIntegrityCode.end(),
            [](std::uint8_t byte) {
                return byte == 0x5aU;
            }));

        storeLe32(micMessage.data() + 32U, 64U);
        assert(parseNtlmAuthenticateMessage(
                   micMessage, parsed) ==
               NtlmMessageParseResult::InvalidSecurityBuffer);
        return 0;
    }

    return 2;
}
