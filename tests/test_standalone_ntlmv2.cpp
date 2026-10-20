// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/standalone_ntlmv2.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>

using namespace rdp_server::server::security;

namespace rdp_server::server::security
{
struct StandaloneNtlmV2TestAccess
{
    [[nodiscard]] static bool credentialSecretCleared(
        const EphemeralNtlmV2Credential &credential) noexcept
    {
        return std::ranges::all_of(
            credential.ntHash_,
            [](std::uint8_t byte) { return byte == 0U; });
    }

    [[nodiscard]] static bool contextSecretsCleared(
        const NtlmV2SecurityContext &context) noexcept
    {
        const auto zero = [](const NtlmV2Key &key) {
            return std::ranges::all_of(
                key, [](std::uint8_t byte) {
                    return byte == 0U;
                });
        };
        return zero(context.sessionBaseKey_) &&
               zero(context.exportedSessionKey_) &&
               zero(context.clientSigningKey_) &&
               zero(context.serverSigningKey_) &&
               zero(context.clientSealingKey_) &&
               zero(context.serverSealingKey_);
    }
};
} // namespace rdp_server::server::security

namespace
{

constexpr NtlmV2Key kExpectedResponseKeyNt{
    0x0c,0x86,0x8a,0x40,0x3b,0xfd,0x7a,0x93,
    0xa3,0x00,0x1e,0xf2,0x2e,0xf0,0x2e,0x3f};
constexpr NtlmV2Key kExpectedSessionBaseKey{
    0x8d,0xe4,0x0c,0xca,0xdb,0xc1,0x4a,0x82,
    0xf1,0x5c,0xb0,0xad,0x0d,0xe9,0x5c,0xa3};
constexpr NtlmV2Key kExpectedExportedSessionKey{
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};
constexpr NtlmV2Key kExpectedClientSigningKey{
    0x47,0x88,0xdc,0x86,0x1b,0x47,0x82,0xf3,
    0x5d,0x43,0xfd,0x98,0xfe,0x1a,0x2d,0x39};
constexpr NtlmV2Key kExpectedServerSigningKey{
    0xd0,0x4d,0x6f,0x10,0x74,0x10,0x41,0xd1,
    0xd2,0x46,0xd6,0x41,0x88,0xd7,0xa8,0xad};
constexpr NtlmV2Key kExpectedClientSealingKey{
    0x59,0xf6,0x00,0x97,0x3c,0xc4,0x96,0x0a,
    0x25,0x48,0x0a,0x7c,0x19,0x6e,0x4c,0x58};
constexpr NtlmV2Key kExpectedServerSealingKey{
    0x93,0x55,0xf3,0xa9,0x57,0xc1,0x58,0x3d,
    0x25,0xc4,0xc2,0xf1,0x1e,0x40,0x39,0x0e};

constexpr NtlmServerChallenge kServerChallenge{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
constexpr NtlmV2Key kEncryptedRandomSessionKey{
    0xc5,0xda,0xd2,0x54,0x4f,0xc9,0x79,0x90,
    0x94,0xce,0x1c,0xe9,0x0b,0xc9,0xd0,0x3e};

// Microsoft MS-NLMP 4.2.4 example NTChallengeResponse, exactly 0x54 bytes.
constexpr std::array<std::uint8_t, 84> kNtlmV2Response{
    0x68,0xcd,0x0a,0xb8,0x51,0xe5,0x1c,0x96,
    0xaa,0xbc,0x92,0x7b,0xeb,0xef,0x6a,0x1c,
    0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0x00,0x00,0x00,0x00,
    0x02,0x00,0x0c,0x00,
    0x44,0x00,0x6f,0x00,0x6d,0x00,0x61,0x00,0x69,0x00,0x6e,0x00,
    0x01,0x00,0x0c,0x00,
    0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x65,0x00,0x72,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00};

constexpr std::uint32_t kMicrosoftExampleFlags = 0xe2888235U;

[[nodiscard]] std::array<char16_t, 8> password()
{
    return {u'P',u'a',u's',u's',u'w',u'o',u'r',u'd'};
}

[[nodiscard]] bool keyEquals(
    std::span<const std::uint8_t, kNtlmV2KeyBytes> actual,
    const NtlmV2Key &expected)
{
    return std::equal(actual.begin(), actual.end(), expected.begin());
}

[[nodiscard]] NtlmV2AuthenticateRequest microsoftRequest()
{
    return {
        kServerChallenge,
        u"User",
        u"Domain",
        kNtlmV2Response,
        kMicrosoftExampleFlags,
        kEncryptedRandomSessionKey};
}

struct CredentialVisitObservation final
{
    bool visited{};
    NtlmV2Key responseKey{};
};

[[nodiscard]] bool observeCredential(
    const EphemeralNtlmV2Credential& credential,
    void* rawContext) noexcept
{
    auto* observation =
        static_cast<CredentialVisitObservation*>(rawContext);
    if (observation == nullptr)
        return false;
    observation->visited = true;
    return credential.deriveResponseKeyNt(
        u"Domain", observation->responseKey);
}

} // namespace

static_assert(!std::is_copy_constructible_v<EphemeralNtlmV2Credential>);
static_assert(!std::is_move_constructible_v<EphemeralNtlmV2Credential>);
static_assert(!std::is_copy_constructible_v<NtlmV2SecurityContext>);
static_assert(!std::is_move_constructible_v<NtlmV2SecurityContext>);
static_assert(
    !std::is_copy_constructible_v<StandalonePasswordCredentialOwner>);
static_assert(
    !std::is_move_constructible_v<StandalonePasswordCredentialOwner>);

int main(int argc, char **argv)
{
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view testCase{argv[1]};

    if (testCase == "ntlmv2-microsoft-known-answer-and-session-keys")
    {
        EphemeralNtlmV2Credential credential;
        auto mutablePassword = password();
        assert(credential.configure(u"User", mutablePassword));
        assert(std::ranges::all_of(
            mutablePassword,
            [](char16_t value) { return value == u'\0'; }));

        NtlmV2Key responseKey{};
        assert(credential.deriveResponseKeyNt(u"Domain", responseKey));
        assert(responseKey == kExpectedResponseKeyNt);

        NtlmV2SecurityContext context;
        assert(credential.verifyAndDeriveSecurityContext(
                   microsoftRequest(), context) ==
               NtlmV2VerifyResult::Verified);
        assert(context.active());
        assert(keyEquals(
            context.sessionBaseKey(), kExpectedSessionBaseKey));
        assert(keyEquals(
            context.exportedSessionKey(),
            kExpectedExportedSessionKey));
        assert(keyEquals(
            context.clientSigningKey(),
            kExpectedClientSigningKey));
        assert(keyEquals(
            context.serverSigningKey(),
            kExpectedServerSigningKey));
        assert(keyEquals(
            context.clientSealingKey(),
            kExpectedClientSealingKey));
        assert(keyEquals(
            context.serverSealingKey(),
            kExpectedServerSealingKey));
        return 0;
    }

    if (testCase == "ntlmv2-proof-blob-and-flag-denials")
    {
        EphemeralNtlmV2Credential credential;
        auto mutablePassword = password();
        assert(credential.configure(u"User", mutablePassword));

        NtlmV2SecurityContext context;
        auto request = microsoftRequest();
        auto badProof = kNtlmV2Response;
        badProof[0] ^= 0x01U;
        request.ntChallengeResponse = badProof;
        assert(credential.verifyAndDeriveSecurityContext(
                   request, context) ==
               NtlmV2VerifyResult::ProofMismatch);
        assert(!context.active());

        auto badBlob = kNtlmV2Response;
        badBlob[18] = 0x01U; // Reserved1 inside the NTLMv2 blob.
        request = microsoftRequest();
        request.ntChallengeResponse = badBlob;
        assert(credential.verifyAndDeriveSecurityContext(
                   request, context) ==
               NtlmV2VerifyResult::InvalidResponse);

        request = microsoftRequest();
        request.username = u"Other";
        assert(credential.verifyAndDeriveSecurityContext(
                   request, context) ==
               NtlmV2VerifyResult::UsernameMismatch);
        assert(!context.active());

        request = microsoftRequest();
        request.negotiateFlags &= ~kNtlmNegotiateSeal;
        assert(credential.verifyAndDeriveSecurityContext(
                   request, context) ==
               NtlmV2VerifyResult::UnsupportedFlags);

        request = microsoftRequest();
        request.encryptedRandomSessionKey =
            request.encryptedRandomSessionKey.first(15U);
        assert(credential.verifyAndDeriveSecurityContext(
                   request, context) ==
               NtlmV2VerifyResult::InvalidInput);
        return 0;
    }

    if (testCase == "ntlmv2-credential-owner-generation-revocation")
    {
        StandalonePasswordCredentialOwner owner;
        const auto empty = owner.observation();
        assert(empty.generation == 0U && !empty.configured);

        auto firstPassword = password();
        assert(owner.configure(u"User", firstPassword));
        assert(std::ranges::all_of(
            firstPassword,
            [](char16_t value) { return value == u'\0'; }));
        const auto first = owner.observation();
        assert(first.generation != 0U && first.configured);

        CredentialVisitObservation observed;
        assert(owner.visit(
            first.generation, &observeCredential, &observed));
        assert(observed.visited);
        assert(observed.responseKey == kExpectedResponseKeyNt);
        assert(!owner.visit(
            first.generation + 1U, &observeCredential, &observed));
        assert(!owner.visit(first.generation, nullptr, &observed));

        std::array<char16_t, 2> rejectedPassword{u'x', u'y'};
        assert(!owner.configure(u"Us\u00e9r", rejectedPassword));
        assert(std::ranges::all_of(
            rejectedPassword,
            [](char16_t value) { return value == u'\0'; }));
        const auto rejected = owner.observation();
        assert(rejected.generation > first.generation);
        assert(!rejected.configured);
        assert(!owner.visit(
            first.generation, &observeCredential, &observed));

        auto secondPassword = password();
        assert(owner.configure(u"User", secondPassword));
        const auto second = owner.observation();
        assert(second.configured);
        assert(second.generation > rejected.generation);
        assert(!owner.visit(
            first.generation, &observeCredential, &observed));
        observed = {};
        assert(owner.visit(
            second.generation, &observeCredential, &observed));
        assert(observed.responseKey == kExpectedResponseKeyNt);

        owner.revoke();
        const auto revoked = owner.observation();
        assert(!revoked.configured);
        assert(revoked.generation > second.generation);
        assert(!owner.visit(
            second.generation, &observeCredential, &observed));
        return 0;
    }

    if (testCase == "ntlmv2-ephemeral-secret-revocation")
    {
        EphemeralNtlmV2Credential credential;

        std::array<char16_t, 2> rejectedPassword{u'x', u'y'};
        assert(!credential.configure(u"Us\u00e9r", rejectedPassword));
        assert(std::ranges::all_of(
            rejectedPassword,
            [](char16_t value) { return value == u'\0'; }));

        auto mutablePassword = password();
        assert(credential.configure(u"User", mutablePassword));
        NtlmV2Key noDomainKey{};
        assert(credential.deriveResponseKeyNt(u"", noDomainKey));

        NtlmV2SecurityContext context;
        assert(credential.verifyAndDeriveSecurityContext(
                   microsoftRequest(), context) ==
               NtlmV2VerifyResult::Verified);
        context.clear();
        assert(!context.active());
        assert(StandaloneNtlmV2TestAccess::contextSecretsCleared(
            context));

        credential.revoke();
        assert(!credential.configured());
        assert(StandaloneNtlmV2TestAccess::credentialSecretCleared(
            credential));
        NtlmV2Key afterRevoke{};
        assert(!credential.deriveResponseKeyNt(u"", afterRevoke));
        assert(std::ranges::all_of(
            afterRevoke,
            [](std::uint8_t value) { return value == 0U; }));
        return 0;
    }

    return 2;
}
