// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/standalone_ntlmv2.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <string_view>

using namespace rdp_server::server::security;

namespace
{
constexpr NtlmServerChallenge kServerChallenge{
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
constexpr NtlmV2Key kEncryptedRandomSessionKey{
    0xc5,0xda,0xd2,0x54,0x4f,0xc9,0x79,0x90,
    0x94,0xce,0x1c,0xe9,0x0b,0xc9,0xd0,0x3e};
constexpr std::array<std::uint8_t,84> kResponse{
    0x68,0xcd,0x0a,0xb8,0x51,0xe5,0x1c,0x96,0xaa,0xbc,0x92,0x7b,0xeb,0xef,0x6a,0x1c,
    0x01,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
    0,0,0,0,0x02,0,0x0c,0,0x44,0,0x6f,0,0x6d,0,0x61,0,0x69,0,0x6e,0,
    0x01,0,0x0c,0,0x53,0,0x65,0,0x72,0,0x76,0,0x65,0,0x72,0,0,0,0,0,0,0};
constexpr std::uint32_t kFlags=0xe2888235U;
constexpr std::array<std::uint8_t,21> kClientPlain{
    'C','r','e','d','S','S','P','-','c','l','i','e','n','t','-','p','u','b','k','e','y'};
constexpr std::array<std::uint8_t,21> kClientCipher{
    0x47,0x97,0x08,0x01,0x8d,0x4a,0x0f,0xf1,0x94,0x0c,0x3d,0xa4,0x8a,0x6f,0x5a,0x76,0xfa,0x3d,0x64,0xe3,0xdf};
constexpr std::array<std::uint8_t,16> kClientSig{
    1,0,0,0,0x0d,0xbc,0xce,0x92,0x64,0xfa,0xb6,0xea,0,0,0,0};
constexpr std::array<std::uint8_t,21> kServerPlain{
    'C','r','e','d','S','S','P','-','s','e','r','v','e','r','-','p','u','b','k','e','y'};
constexpr std::array<std::uint8_t,21> kServerCipher{
    0x05,0x7a,0x78,0xd3,0x02,0xe9,0x4d,0xc4,0x5b,0xa1,0x55,0xa1,0x46,0x29,0x01,0x57,0x8c,0xb2,0x7f,0xee,0x58};
constexpr std::array<std::uint8_t,16> kServerSig{
    1,0,0,0,0x3e,0xb8,0x39,0xae,0x9c,0x8e,0x71,0xd5,0,0,0,0};

bool makeContext(EphemeralNtlmV2Credential& cred,NtlmV2SecurityContext& ctx)
{
    std::array<char16_t,8> pwd{u'P',u'a',u's',u's',u'w',u'o',u'r',u'd'};
    return cred.configure(u"User",pwd) &&
        cred.verifyAndDeriveSecurityContext(
            {kServerChallenge,u"Domain",kResponse,kFlags,kEncryptedRandomSessionKey},ctx)
            == NtlmV2VerifyResult::Verified;
}
}

int main(int argc,char** argv)
{
    if(argc!=2||argv[1]==nullptr) return 2;
    const std::string_view testCase{argv[1]};

    if(testCase=="ntlmv2-transcript-mic-verification")
    {
        EphemeralNtlmV2Credential cred; NtlmV2SecurityContext ctx;
        assert(makeContext(cred,ctx));
        constexpr std::array<std::uint8_t,3> negotiate{1,2,3};
        constexpr std::array<std::uint8_t,2> challenge{4,5};
        std::array<std::uint8_t,20> authenticate{
            6,7,0x0f,0x0a,0x58,0xa3,0xa5,0x30,0xe7,0x8b,0xe2,0xaa,0x88,0xe6,0x94,0x8d,0x07,0x85,8,9};
        assert(ctx.verifyAuthenticateMessageMic(negotiate,challenge,authenticate,2));
        authenticate[8]^=1U;
        assert(!ctx.verifyAuthenticateMessageMic(negotiate,challenge,authenticate,2));
        assert(ctx.active());
        return 0;
    }
    if(testCase=="ntlmv2-session-security-sign-seal-known-answer")
    {
        EphemeralNtlmV2Credential cred; NtlmV2SecurityContext ctx;
        assert(makeContext(cred,ctx));
        std::array<std::uint8_t,21> plain{};
        assert(ctx.unwrapClientMessage(kClientCipher,kClientSig,plain)==NtlmMessageSecurityResult::Processed);
        assert(plain==kClientPlain);
        std::array<std::uint8_t,21> cipher{};
        std::array<std::uint8_t,16> sig{};
        assert(ctx.wrapServerMessage(kServerPlain,cipher,sig)==NtlmMessageSecurityResult::Processed);
        assert(cipher==kServerCipher);
        assert(sig==kServerSig);
        return 0;
    }
    if(testCase=="ntlmv2-session-security-tamper-revokes")
    {
        EphemeralNtlmV2Credential cred; NtlmV2SecurityContext ctx;
        assert(makeContext(cred,ctx));
        auto sig=kClientSig; sig[4]^=1U;
        std::array<std::uint8_t,21> plain{}; plain.fill(0xa5U);
        assert(ctx.unwrapClientMessage(kClientCipher,sig,plain)==NtlmMessageSecurityResult::InvalidSignature);
        assert(!ctx.active());
        assert(std::ranges::all_of(plain,[](std::uint8_t v){return v==0U;}));
        return 0;
    }
    return 2;
}
