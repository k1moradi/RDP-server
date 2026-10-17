// SPDX-License-Identifier: GPL-3.0-or-later
// Bounded libFuzzer entry point for first-party CredSSP structural parsers.
// This is offline syntax/lifetime testing only; it cannot authenticate a user.

#include "security/credssp_credentials.h"
#include "security/credssp_tsrequest.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

namespace
{

using namespace rdp_server::server::security;

[[noreturn]] void failInvariant() noexcept
{
    std::abort();
}

void requireInvariant(bool condition) noexcept
{
    if (!condition)
        failInvariant();
}

void exerciseTsRequestParser(std::span<const std::uint8_t> bytes) noexcept
{
    const auto first = parseCredSspTsRequest(bytes);
    const auto second = parseCredSspTsRequest(bytes);

    requireInvariant(first.error == second.error);
    requireInvariant(first.value.version == second.value.version);
    requireInvariant(first.value.tokenCount == second.value.tokenCount);
    requireInvariant(first.value.hasAuthInfo == second.value.hasAuthInfo);
    requireInvariant(first.value.hasPubKeyAuth == second.value.hasPubKeyAuth);
    requireInvariant(first.value.hasErrorCode == second.value.hasErrorCode);
    requireInvariant(first.value.hasClientNonce == second.value.hasClientNonce);
    requireInvariant(first.value.encryptedAuthInfo.size() ==
                     second.value.encryptedAuthInfo.size());
    requireInvariant(first.value.encryptedPubKeyAuth.size() ==
                     second.value.encryptedPubKeyAuth.size());
    requireInvariant(first.value.clientNonce.size() ==
                     second.value.clientNonce.size());

    for (std::size_t index = 0; index < kMaximumCredSspTokens; ++index)
    {
        requireInvariant(first.value.tokens[index].size() ==
                         second.value.tokens[index].size());
        if (!first.value.tokens[index].empty())
        {
            requireInvariant(first.value.tokens[index].data() ==
                             second.value.tokens[index].data());
        }
    }

    if (!first)
    {
        // Parser failure must not publish any client-controlled borrowed view
        // or scalar field from a partially parsed request.
        requireInvariant(first.value.version == 0);
        requireInvariant(first.value.tokenCount == 0);
        requireInvariant(!first.value.hasAuthInfo);
        requireInvariant(!first.value.hasPubKeyAuth);
        requireInvariant(!first.value.hasErrorCode);
        requireInvariant(!first.value.hasClientNonce);
        requireInvariant(first.value.encryptedAuthInfo.empty());
        requireInvariant(first.value.encryptedPubKeyAuth.empty());
        requireInvariant(first.value.clientNonce.empty());
        for (const auto token : first.value.tokens)
            requireInvariant(token.empty());
        return;
    }

    requireInvariant(first.error == TsRequestError::None);
    requireInvariant(first.value.version >= 2 && first.value.version <= 6);
    requireInvariant(first.value.tokenCount <= kMaximumCredSspTokens);
    for (std::size_t index = 0; index < first.value.tokenCount; ++index)
    {
        requireInvariant(!first.value.tokens[index].empty());
        requireInvariant(first.value.tokens[index].size() <=
                         kMaximumCredSspTokenBytes);
    }
    for (std::size_t index = first.value.tokenCount;
         index < kMaximumCredSspTokens; ++index)
    {
        requireInvariant(first.value.tokens[index].empty());
    }
    requireInvariant(first.value.hasAuthInfo ==
                     !first.value.encryptedAuthInfo.empty());
    requireInvariant(first.value.hasPubKeyAuth ==
                     !first.value.encryptedPubKeyAuth.empty());
    requireInvariant(first.value.hasClientNonce
                         ? first.value.clientNonce.size() == 32U
                         : first.value.clientNonce.empty());
}

void exerciseCredentialParsers(
    std::span<const std::uint8_t> bytes) noexcept
{
    const auto firstCredential = inspectCredSspCredentials(bytes);
    const auto secondCredential = inspectCredSspCredentials(bytes);
    requireInvariant(firstCredential.kind == secondCredential.kind);
    requireInvariant(firstCredential.error == secondCredential.error);
    if (!firstCredential)
    {
        requireInvariant(firstCredential.kind == CredSspCredentialKind::None);
        requireInvariant(firstCredential.error !=
                         CredSspCredentialError::None);
    }
    else
    {
        requireInvariant(firstCredential.kind != CredSspCredentialKind::None);
        requireInvariant(firstCredential.error ==
                         CredSspCredentialError::None);
    }

    const auto firstAccount = inspectCredSspDelegatedAccount(bytes);
    const auto secondAccount = inspectCredSspDelegatedAccount(bytes);
    requireInvariant(firstAccount.account == secondAccount.account);
    requireInvariant(firstAccount.accountLength ==
                     secondAccount.accountLength);
    requireInvariant(firstAccount.error == secondAccount.error);

    if (!firstAccount)
    {
        requireInvariant(firstAccount.accountLength == 0);
        requireInvariant(firstAccount.accountName().empty());
        for (const char byte : firstAccount.account)
            requireInvariant(byte == '\0');
        return;
    }

    requireInvariant(firstAccount.error == CredSspDelegatedAccountError::None);
    requireInvariant(firstAccount.accountLength > 0);
    requireInvariant(firstAccount.accountLength <=
                     kMaximumDelegatedUnixAccountBytes);
    requireInvariant(firstAccount.account[firstAccount.accountLength] == '\0');
    requireInvariant(firstAccount.accountName().size() ==
                     firstAccount.accountLength);
}

void exerciseFrameReader(std::span<const std::uint8_t> bytes) noexcept
{
    TsRequestFrameReader reader;
    const auto whole = reader.consume(bytes);
    requireInvariant(whole.bytesConsumed <= bytes.size());

    if (whole.status == TsRequestFrameStatus::Complete)
    {
        const auto complete = reader.completeDer();
        requireInvariant(!complete.empty());
        requireInvariant(complete.size() <= kMaximumCredSspRequestBytes);
        requireInvariant(static_cast<bool>(parseCredSspTsRequest(complete)));
        requireInvariant(reader.bytesNeeded() == 0);
        requireInvariant(reader.releaseFrame());
        requireInvariant(reader.status() == TsRequestFrameStatus::NeedMore);
        requireInvariant(reader.completeDer().empty());
    }
    else
    {
        requireInvariant(reader.completeDer().empty());
        if (whole.status == TsRequestFrameStatus::Invalid)
        {
            requireInvariant(reader.status() == TsRequestFrameStatus::Closed);
            requireInvariant(reader.bytesNeeded() == 0);
        }
    }
    reader.close();
    requireInvariant(reader.status() == TsRequestFrameStatus::Closed);
    requireInvariant(reader.bytesNeeded() == 0);

    if (bytes.empty())
        return;

    // Drive the same production framer through up to eight deterministic
    // fragments chosen from the fuzz input. This reaches split DER headers
    // and payload boundaries without an input-size-dependent call explosion.
    TsRequestFrameReader fragmented;
    std::size_t offset = 0;
    for (std::size_t step = 0;
         step < 8 && offset < bytes.size() &&
         fragmented.status() == TsRequestFrameStatus::NeedMore;
         ++step)
    {
        const std::size_t remaining = bytes.size() - offset;
        const std::size_t selectorOffset = (offset + step) % bytes.size();
        const std::size_t nextOffset = (selectorOffset + 1U) % bytes.size();
        const std::size_t selector =
            (static_cast<std::size_t>(bytes[selectorOffset]) << 8U) |
            bytes[nextOffset];
        const std::size_t chunk = 1U + selector % remaining;
        const auto result = fragmented.consume(
            bytes.subspan(offset, chunk));
        requireInvariant(result.bytesConsumed <= chunk);
        offset += result.bytesConsumed;
        if (result.status == TsRequestFrameStatus::NeedMore)
            requireInvariant(result.bytesConsumed != 0);
        if (result.status == TsRequestFrameStatus::Invalid)
        {
            requireInvariant(fragmented.status() ==
                             TsRequestFrameStatus::Closed);
        }
    }
    fragmented.close();
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(
    const std::uint8_t *data, std::size_t size)
{
    constexpr std::size_t kMaximumFuzzInputBytes =
        kMaximumCredSspRequestBytes;
    if (size > kMaximumFuzzInputBytes)
        return 0;

    const std::span<const std::uint8_t> bytes{data, size};
    exerciseTsRequestParser(bytes);
    exerciseCredentialParsers(bytes);
    exerciseFrameReader(bytes);
    return 0;
}
