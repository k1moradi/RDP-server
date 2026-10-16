// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp_licensing.h"

#if defined(_WIN32) && !defined(NOMINMAX)
#define NOMINMAX
#endif
#include "nonblocking_tcp_adapter.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>

namespace rdp_server::server::transport
{
static_assert(
    kMaximumRdpServerLicenseGrantTlsApplicationBytes <=
    kMaximumTlsApplicationIoBytes);

namespace
{
constexpr std::size_t kLicensePreambleBytes = 4U;
constexpr std::uint8_t kProtocolVersionMask = 0x0fU;
constexpr std::uint8_t kExtendedErrorSupported = 0x80U;
constexpr std::uint8_t kAllowedPreambleFlags =
    kProtocolVersionMask | kExtendedErrorSupported;
constexpr std::size_t kInitialClientFixedBytes = 40U;
constexpr std::size_t kMacBytes = 16U;
constexpr std::size_t kClientRandomOffset = 8U;

constexpr std::uint16_t kBlobData = 0x0001U;
constexpr std::uint16_t kBlobRandom = 0x0002U;
constexpr std::uint16_t kBlobClientUserName = 0x000fU;
constexpr std::uint16_t kBlobClientMachineName = 0x0010U;
constexpr std::uint16_t kBlobEncryptedData = 0x0009U;
constexpr std::uint16_t kBlobServerCertificate = 0x0003U;
constexpr std::uint16_t kBlobKeyExchangeAlgorithms = 0x000dU;
constexpr std::uint16_t kBlobScope = 0x000eU;
constexpr std::uint32_t kKeyExchangeAlgRsa = 0x00000001U;
constexpr std::uint8_t kServerLicenseRequestPreambleFlags =
    0x03U | kExtendedErrorSupported;

[[nodiscard]] std::uint16_t readLe16(
    std::span<const std::uint8_t> bytes, std::size_t offset) noexcept
{
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes[offset]) |
        (static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U));
}

[[nodiscard]] std::uint32_t readLe32(
    std::span<const std::uint8_t> bytes, std::size_t offset) noexcept
{
    return static_cast<std::uint32_t>(readLe16(bytes, offset)) |
           (static_cast<std::uint32_t>(readLe16(bytes, offset + 2U)) << 16U);
}

[[nodiscard]] bool knownMessageType(std::uint8_t rawType) noexcept
{
    switch (static_cast<RdpLicensingMessageType>(rawType))
    {
    case RdpLicensingMessageType::ServerLicenseRequest:
    case RdpLicensingMessageType::ServerPlatformChallenge:
    case RdpLicensingMessageType::ServerNewLicense:
    case RdpLicensingMessageType::ServerUpgradeLicense:
    case RdpLicensingMessageType::ClientLicenseInfo:
    case RdpLicensingMessageType::ClientNewLicenseRequest:
    case RdpLicensingMessageType::ClientPlatformChallengeResponse:
    case RdpLicensingMessageType::ErrorAlert:
        return true;
    }
    return false;
}

[[nodiscard]] bool readRequiredBlob(
    std::span<const std::uint8_t> body,
    std::size_t &offset,
    std::uint16_t expectedType,
    std::span<const std::uint8_t> &payload) noexcept
{
    constexpr std::size_t headerBytes = 4U;
    if (offset > body.size() || body.size() - offset < headerBytes)
        return false;

    const std::uint16_t type = readLe16(body, offset);
    const std::size_t payloadBytes = readLe16(body, offset + 2U);
    offset += headerBytes;
    if (type != expectedType || payloadBytes == 0U ||
        payloadBytes > body.size() - offset)
        return false;

    payload = body.subspan(offset, payloadBytes);
    offset += payloadBytes;
    return true;
}

[[nodiscard]] bool validNullTerminatedAnsi(
    std::span<const std::uint8_t> text) noexcept
{
    if (text.empty() || text.back() != 0U)
        return false;
    return std::find(text.begin(), text.end() - 1, std::uint8_t{0}) ==
           text.end() - 1;
}

[[nodiscard]] bool validNullTerminatedUtf16Le(
    std::span<const std::uint8_t> text) noexcept
{
    if (text.size() < 2U || (text.size() & 1U) != 0U ||
        text[text.size() - 2U] != 0U || text.back() != 0U)
        return false;
    for (std::size_t offset = 0; offset + 2U < text.size(); offset += 2U)
    {
        if (text[offset] == 0U && text[offset + 1U] == 0U)
            return false;
    }
    return true;
}

void writeLe16(
    std::span<std::uint8_t> output, std::size_t offset,
    std::uint16_t value) noexcept
{
    output[offset] = static_cast<std::uint8_t>(value);
    output[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
}

void writeLe32(
    std::span<std::uint8_t> output, std::size_t offset,
    std::uint32_t value) noexcept
{
    writeLe16(output, offset, static_cast<std::uint16_t>(value));
    writeLe16(output, offset + 2U, static_cast<std::uint16_t>(value >> 16U));
}

[[nodiscard]] bool validInitialClientPrefix(
    std::span<const std::uint8_t> body) noexcept
{
    if (body.size() < kInitialClientFixedBytes)
        return false;
    // MS-RDPELE 2.2.2.2 requires KEY_EXCHANGE_ALG_RSA. PlatformId and the
    // 32-byte ClientRandom are retained as opaque protocol fields here.
    return readLe32(body, 0U) == kKeyExchangeAlgRsa;
}

[[nodiscard]] bool parseClientNewLicenseRequestBody(
    std::span<const std::uint8_t> body,
    RdpClientLicensingKeyExchangeView &view) noexcept
{
    if (!validInitialClientPrefix(body))
        return false;

    std::size_t offset = kInitialClientFixedBytes;
    std::span<const std::uint8_t> encryptedPreMasterSecret;
    std::span<const std::uint8_t> clientUserName;
    std::span<const std::uint8_t> clientMachineName;
    if (!readRequiredBlob(body, offset, kBlobRandom,
                          encryptedPreMasterSecret) ||
        !readRequiredBlob(body, offset, kBlobClientUserName,
                          clientUserName) ||
        !readRequiredBlob(body, offset, kBlobClientMachineName,
                          clientMachineName) ||
        offset != body.size() ||
        !validNullTerminatedAnsi(clientUserName) ||
        !validNullTerminatedAnsi(clientMachineName))
        return false;

    view.type = RdpLicensingMessageType::ClientNewLicenseRequest;
    view.clientRandom =
        body.subspan(kClientRandomOffset, kRdpLicensingRandomBytes);
    view.encryptedPreMasterSecret = encryptedPreMasterSecret;
    return true;
}

struct ParsedClientLicenseInfoBody
{
    std::span<const std::uint8_t> encryptedPreMasterSecret{};
    std::span<const std::uint8_t> licenseInfo{};
    std::span<const std::uint8_t> encryptedHardwareId{};
    std::span<const std::uint8_t> macData{};
};

[[nodiscard]] bool parseClientLicenseInfoBody(
    std::span<const std::uint8_t> body,
    ParsedClientLicenseInfoBody &fields) noexcept
{
    if (!validInitialClientPrefix(body))
        return false;

    std::size_t offset = kInitialClientFixedBytes;
    if (!readRequiredBlob(body, offset, kBlobRandom,
                          fields.encryptedPreMasterSecret) ||
        !readRequiredBlob(body, offset, kBlobData, fields.licenseInfo) ||
        !readRequiredBlob(body, offset, kBlobData,
                          fields.encryptedHardwareId) ||
        fields.encryptedHardwareId.size() != kRdpLicensingHardwareIdBytes ||
        offset > body.size() || body.size() - offset != kMacBytes)
        return false;

    fields.macData = body.subspan(offset, kMacBytes);
    return true;
}

[[nodiscard]] bool appendBytes(
    std::span<std::uint8_t> destination,
    std::size_t &offset,
    std::span<const std::uint8_t> source) noexcept
{
    if (offset > destination.size() ||
        source.size() > destination.size() - offset)
        return false;
    std::copy(source.begin(), source.end(), destination.begin() + offset);
    offset += source.size();
    return true;
}

[[nodiscard]] bool digestExact(
    const EVP_MD *algorithm,
    std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output) noexcept
{
    std::array<std::uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestBytes = 0U;
    const int result = EVP_Digest(
        input.data(), input.size(), digest.data(), &digestBytes,
        algorithm, nullptr);
    if (result != 1 || digestBytes != output.size())
    {
        OPENSSL_cleanse(digest.data(), digest.size());
        return false;
    }
    std::copy_n(digest.begin(), output.size(), output.begin());
    OPENSSL_cleanse(digest.data(), digest.size());
    return true;
}

struct MdContextCloser
{
    void operator()(EVP_MD_CTX *context) const noexcept
    {
        EVP_MD_CTX_free(context);
    }
};
using OwnedMdContext = std::unique_ptr<EVP_MD_CTX, MdContextCloser>;

template <std::size_t SegmentCount>
[[nodiscard]] bool digestSegments(
    const EVP_MD *algorithm,
    const std::array<std::span<const std::uint8_t>, SegmentCount> &segments,
    std::span<std::uint8_t> output) noexcept
{
    OwnedMdContext context{EVP_MD_CTX_new()};
    if (!context || EVP_DigestInit_ex(context.get(), algorithm, nullptr) != 1)
        return false;

    for (const auto segment : segments)
    {
        if (!segment.empty() &&
            EVP_DigestUpdate(
                context.get(), segment.data(), segment.size()) != 1)
            return false;
    }

    std::array<std::uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestBytes = 0U;
    const bool ok =
        EVP_DigestFinal_ex(
            context.get(), digest.data(), &digestBytes) == 1 &&
        digestBytes == output.size();
    if (ok)
        std::copy_n(digest.begin(), output.size(), output.begin());
    OPENSSL_cleanse(digest.data(), digest.size());
    return ok;
}

[[nodiscard]] bool saltedHash(
    std::span<const std::uint8_t> secret,
    std::span<const std::uint8_t> label,
    std::span<const std::uint8_t> firstRandom,
    std::span<const std::uint8_t> secondRandom,
    std::span<std::uint8_t> output) noexcept
{
    std::array<std::uint8_t, 128> shaInput{};
    std::size_t shaBytes = 0U;
    if (!appendBytes(shaInput, shaBytes, label) ||
        !appendBytes(shaInput, shaBytes, secret) ||
        !appendBytes(shaInput, shaBytes, firstRandom) ||
        !appendBytes(shaInput, shaBytes, secondRandom))
        return false;

    std::array<std::uint8_t, 20> shaDigest{};
    if (!digestExact(
            EVP_sha1(), std::span(shaInput).first(shaBytes), shaDigest))
    {
        OPENSSL_cleanse(shaInput.data(), shaInput.size());
        return false;
    }

    std::array<std::uint8_t, 80> md5Input{};
    std::size_t md5Bytes = 0U;
    const bool appended =
        appendBytes(md5Input, md5Bytes, secret) &&
        appendBytes(md5Input, md5Bytes, shaDigest);
    const bool ok =
        appended &&
        digestExact(
            EVP_md5(), std::span(md5Input).first(md5Bytes), output);
    OPENSSL_cleanse(shaInput.data(), shaInput.size());
    OPENSSL_cleanse(shaDigest.data(), shaDigest.size());
    OPENSSL_cleanse(md5Input.data(), md5Input.size());
    return ok;
}
} // namespace

RdpClientLicensingKeyExchangeParseResult
parseRdpClientLicensingKeyExchange(
    std::span<const std::uint8_t> completeMessage) noexcept
{
    const auto parsed = parseRdpLicensingMessage(completeMessage);
    if (!parsed)
        return {{},
                RdpClientLicensingKeyExchangeError::InvalidLicensingMessage};

    RdpClientLicensingKeyExchangeView view{};
    switch (parsed.value.type)
    {
    case RdpLicensingMessageType::ClientNewLicenseRequest:
        if (!parseClientNewLicenseRequestBody(parsed.value.body, view))
            return {{}, RdpClientLicensingKeyExchangeError::MalformedBody};
        break;
    case RdpLicensingMessageType::ClientLicenseInfo:
    {
        ParsedClientLicenseInfoBody fields{};
        if (!parseClientLicenseInfoBody(parsed.value.body, fields))
            return {{}, RdpClientLicensingKeyExchangeError::MalformedBody};
        view.type = RdpLicensingMessageType::ClientLicenseInfo;
        view.clientRandom = parsed.value.body.subspan(
            kClientRandomOffset, kRdpLicensingRandomBytes);
        view.encryptedPreMasterSecret = fields.encryptedPreMasterSecret;
        break;
    }
    default:
        return {{}, RdpClientLicensingKeyExchangeError::UnexpectedMessage};
    }
    return {view, RdpClientLicensingKeyExchangeError::None};
}

RdpClientLicenseInfoParseResult parseRdpClientLicenseInfo(
    std::span<const std::uint8_t> completeMessage) noexcept
{
    const auto parsed = parseRdpLicensingMessage(completeMessage);
    if (!parsed)
        return {{}, RdpClientLicenseInfoParseError::InvalidLicensingMessage};
    if (parsed.value.type != RdpLicensingMessageType::ClientLicenseInfo)
        return {{}, RdpClientLicenseInfoParseError::UnexpectedMessage};

    ParsedClientLicenseInfoBody fields{};
    if (!parseClientLicenseInfoBody(parsed.value.body, fields))
        return {{}, RdpClientLicenseInfoParseError::MalformedBody};

    return {{
        fields.licenseInfo,
        fields.encryptedHardwareId,
        fields.macData},
        RdpClientLicenseInfoParseError::None};
}

RdpLicensingRc4Result cryptRdpLicensingData(
    std::span<const std::uint8_t> encryptionKey,
    std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output) noexcept
{
    if (encryptionKey.size() != kRdpLicensingKeyBytes)
        return {RdpLicensingRc4Error::InvalidKey};
    if (input.size() != output.size())
        return {RdpLicensingRc4Error::SizeMismatch};

    if (!input.empty())
        std::memmove(output.data(), input.data(), input.size());

    std::array<std::uint8_t, 256> state{};
    for (std::size_t index = 0U; index < state.size(); ++index)
        state[index] = static_cast<std::uint8_t>(index);

    std::uint16_t j = 0U;
    for (std::size_t index = 0U; index < state.size(); ++index)
    {
        j = static_cast<std::uint16_t>(
            (j + state[index] +
             encryptionKey[index % kRdpLicensingKeyBytes]) & 0xffU);
        std::swap(state[index], state[j]);
    }

    std::uint16_t i = 0U;
    j = 0U;
    for (std::size_t index = 0U; index < output.size(); ++index)
    {
        i = static_cast<std::uint16_t>((i + 1U) & 0xffU);
        j = static_cast<std::uint16_t>((j + state[i]) & 0xffU);
        std::swap(state[i], state[j]);
        const std::uint16_t streamIndex = static_cast<std::uint16_t>(
            (state[i] + state[j]) & 0xffU);
        output[index] ^= state[streamIndex];
    }

    OPENSSL_cleanse(state.data(), state.size());
    return {RdpLicensingRc4Error::None};
}

RdpLicensingMacResult generateRdpLicensingMac(
    std::span<const std::uint8_t> macSaltKey,
    std::span<const std::uint8_t> data) noexcept
{
    RdpLicensingMacResult result{};
    if (macSaltKey.size() != kRdpLicensingKeyBytes)
        return result;
    if (data.size() > std::numeric_limits<std::uint32_t>::max())
    {
        result.error = RdpLicensingMacError::OversizedData;
        return result;
    }

    std::array<std::uint8_t, 40> pad1{};
    std::array<std::uint8_t, 48> pad2{};
    pad1.fill(0x36U);
    pad2.fill(0x5cU);
    std::array<std::uint8_t, 4> lengthBytes{
        static_cast<std::uint8_t>(data.size()),
        static_cast<std::uint8_t>(data.size() >> 8U),
        static_cast<std::uint8_t>(data.size() >> 16U),
        static_cast<std::uint8_t>(data.size() >> 24U)};
    std::array<std::uint8_t, 20> shaDigest{};

    const std::array<std::span<const std::uint8_t>, 4> shaSegments{
        macSaltKey, pad1, lengthBytes, data};
    if (!digestSegments(EVP_sha1(), shaSegments, shaDigest))
    {
        result.error = RdpLicensingMacError::DigestFailure;
        OPENSSL_cleanse(shaDigest.data(), shaDigest.size());
        return result;
    }

    const std::array<std::span<const std::uint8_t>, 3> md5Segments{
        macSaltKey, pad2, shaDigest};
    if (!digestSegments(EVP_md5(), md5Segments, result.value))
    {
        result.value.fill(0U);
        result.error = RdpLicensingMacError::DigestFailure;
        OPENSSL_cleanse(shaDigest.data(), shaDigest.size());
        return result;
    }

    OPENSSL_cleanse(shaDigest.data(), shaDigest.size());
    result.error = RdpLicensingMacError::None;
    return result;
}

RdpServerPlatformChallengeEncodeResult
encodeRdpServerPlatformChallenge(
    std::span<const std::uint8_t> plaintextChallenge,
    const RdpLicensingKeyMaterial &keyMaterial,
    std::span<std::uint8_t> output) noexcept
{
    if (plaintextChallenge.size() != kRdpPlatformChallengePlaintextBytes ||
        !validNullTerminatedUtf16Le(plaintextChallenge))
        return {0U, RdpServerPlatformChallengeEncodeError::InvalidChallenge};
    if (output.size() < kRdpServerPlatformChallengeBytes)
        return {0U, RdpServerPlatformChallengeEncodeError::OutputTooSmall};

    std::array<std::uint8_t, kRdpServerPlatformChallengeBytes> packet{};
    packet[0] = static_cast<std::uint8_t>(
        RdpLicensingMessageType::ServerPlatformChallenge);
    packet[1] = 0x03U;
    writeLe16(
        packet, 2U,
        static_cast<std::uint16_t>(kRdpServerPlatformChallengeBytes));

    std::size_t offset = 4U;
    writeLe32(packet, offset, 0xffffffffU);
    offset += 4U;
    // wBlobType is explicitly unused for EncryptedPlatformChallenge.
    writeLe16(packet, offset, 0x0000U);
    writeLe16(
        packet, offset + 2U,
        static_cast<std::uint16_t>(plaintextChallenge.size()));
    offset += 4U;

    const auto encryptedOutput =
        std::span(packet).subspan(offset, plaintextChallenge.size());
    if (!cryptRdpLicensingData(
            keyMaterial.encryptionKey,
            plaintextChallenge,
            encryptedOutput))
    {
        OPENSSL_cleanse(packet.data(), packet.size());
        return {0U,
                RdpServerPlatformChallengeEncodeError::EncryptionFailure};
    }
    offset += plaintextChallenge.size();

    auto mac = generateRdpLicensingMac(
        keyMaterial.macSaltKey, plaintextChallenge);
    if (!mac)
    {
        OPENSSL_cleanse(packet.data(), packet.size());
        OPENSSL_cleanse(mac.value.data(), mac.value.size());
        return {0U, RdpServerPlatformChallengeEncodeError::MacFailure};
    }
    std::copy(mac.value.begin(), mac.value.end(), packet.begin() + offset);
    OPENSSL_cleanse(mac.value.data(), mac.value.size());
    offset += kRdpLicensingMacBytes;

    std::copy(packet.begin(), packet.begin() + offset, output.begin());
    OPENSSL_cleanse(packet.data(), packet.size());
    return {offset, RdpServerPlatformChallengeEncodeError::None};
}

RdpClientPlatformChallengeResponseResult
verifyRdpClientPlatformChallengeResponse(
    std::span<const std::uint8_t> completeMessage,
    const RdpLicensingKeyMaterial &keyMaterial,
    std::span<const std::uint8_t> expectedChallenge) noexcept
{
    const auto parsed = parseRdpLicensingMessage(completeMessage);
    if (!parsed ||
        parsed.value.type !=
            RdpLicensingMessageType::ClientPlatformChallengeResponse)
        return {};

    if (expectedChallenge.size() != kRdpPlatformChallengePlaintextBytes)
        return {0U, 0U,
                RdpClientPlatformChallengeResponseError::InvalidResponseData};

    std::size_t offset = 0U;
    std::span<const std::uint8_t> encryptedResponse;
    std::span<const std::uint8_t> encryptedHardwareId;
    if (!readRequiredBlob(
            parsed.value.body, offset, kBlobEncryptedData,
            encryptedResponse) ||
        !readRequiredBlob(
            parsed.value.body, offset, kBlobEncryptedData,
            encryptedHardwareId) ||
        encryptedResponse.size() != kRdpPlatformChallengeResponseDataBytes ||
        encryptedHardwareId.size() != kRdpLicensingHardwareIdBytes ||
        offset > parsed.value.body.size() ||
        parsed.value.body.size() - offset != kRdpLicensingMacBytes)
    {
        return {0U, 0U, RdpClientPlatformChallengeResponseError::InvalidBlob};
    }

    std::array<std::uint8_t, kRdpPlatformChallengeResponseDataBytes>
        responseData{};
    std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> hardwareId{};
    const auto responseDecrypted = cryptRdpLicensingData(
        keyMaterial.encryptionKey, encryptedResponse, responseData);
    const auto hardwareIdDecrypted = cryptRdpLicensingData(
        keyMaterial.encryptionKey, encryptedHardwareId, hardwareId);
    if (!responseDecrypted || !hardwareIdDecrypted)
    {
        OPENSSL_cleanse(responseData.data(), responseData.size());
        OPENSSL_cleanse(hardwareId.data(), hardwareId.size());
        return {0U, 0U,
                RdpClientPlatformChallengeResponseError::DecryptFailure};
    }

    const std::uint16_t version = readLe16(responseData, 0U);
    const std::uint16_t clientType = readLe16(responseData, 2U);
    const std::uint16_t detailLevel = readLe16(responseData, 4U);
    const std::size_t challengeBytes = readLe16(responseData, 6U);
    const bool validClientType =
        clientType == 0x0100U || clientType == 0x0200U ||
        clientType == 0x0300U || clientType == 0xff00U;
    const bool validDetailLevel =
        detailLevel >= 0x0001U && detailLevel <= 0x0003U;
    if (version != 0x0100U || !validClientType || !validDetailLevel ||
        challengeBytes != expectedChallenge.size())
    {
        OPENSSL_cleanse(responseData.data(), responseData.size());
        OPENSSL_cleanse(hardwareId.data(), hardwareId.size());
        return {clientType, detailLevel,
                RdpClientPlatformChallengeResponseError::InvalidResponseData};
    }

    const auto responseChallenge =
        std::span(responseData).subspan(
            kRdpPlatformChallengeResponseHeaderBytes);
    if (CRYPTO_memcmp(
            responseChallenge.data(), expectedChallenge.data(),
            expectedChallenge.size()) != 0)
    {
        OPENSSL_cleanse(responseData.data(), responseData.size());
        OPENSSL_cleanse(hardwareId.data(), hardwareId.size());
        return {clientType, detailLevel,
                RdpClientPlatformChallengeResponseError::ChallengeMismatch};
    }

    std::array<std::uint8_t,
               kRdpPlatformChallengeResponseDataBytes +
                   kRdpLicensingHardwareIdBytes> macInput{};
    std::copy(
        responseData.begin(), responseData.end(), macInput.begin());
    std::copy(
        hardwareId.begin(), hardwareId.end(),
        macInput.begin() +
            static_cast<std::ptrdiff_t>(responseData.size()));
    auto mac = generateRdpLicensingMac(keyMaterial.macSaltKey, macInput);
    if (!mac)
    {
        OPENSSL_cleanse(responseData.data(), responseData.size());
        OPENSSL_cleanse(hardwareId.data(), hardwareId.size());
        OPENSSL_cleanse(macInput.data(), macInput.size());
        OPENSSL_cleanse(mac.value.data(), mac.value.size());
        return {clientType, detailLevel,
                RdpClientPlatformChallengeResponseError::MacFailure};
    }

    const auto receivedMac = parsed.value.body.subspan(offset);
    const bool macMatches =
        CRYPTO_memcmp(
            receivedMac.data(), mac.value.data(), mac.value.size()) == 0;
    OPENSSL_cleanse(responseData.data(), responseData.size());
    OPENSSL_cleanse(hardwareId.data(), hardwareId.size());
    OPENSSL_cleanse(macInput.data(), macInput.size());
    OPENSSL_cleanse(mac.value.data(), mac.value.size());
    return {
        clientType, detailLevel,
        macMatches
            ? RdpClientPlatformChallengeResponseError::None
            : RdpClientPlatformChallengeResponseError::MacMismatch};
}

RdpClientLicenseInfoHardwareIdResult
verifyRdpClientLicenseInfoHardwareId(
    std::span<const std::uint8_t> completeMessage,
    const RdpLicensingKeyMaterial &keyMaterial) noexcept
{
    const auto info = parseRdpClientLicenseInfo(completeMessage);
    if (!info)
        return {RdpClientLicenseInfoHardwareIdError::InvalidMessage};

    std::array<std::uint8_t, kRdpLicensingHardwareIdBytes> hardwareId{};
    const auto decrypted = cryptRdpLicensingData(
        keyMaterial.encryptionKey,
        info.value.encryptedHardwareId,
        hardwareId);
    if (!decrypted)
    {
        OPENSSL_cleanse(hardwareId.data(), hardwareId.size());
        return {RdpClientLicenseInfoHardwareIdError::DecryptFailure};
    }

    auto mac = generateRdpLicensingMac(
        keyMaterial.macSaltKey, hardwareId);
    if (!mac)
    {
        OPENSSL_cleanse(hardwareId.data(), hardwareId.size());
        OPENSSL_cleanse(mac.value.data(), mac.value.size());
        return {RdpClientLicenseInfoHardwareIdError::MacFailure};
    }

    const bool matches =
        info.value.macData.size() == mac.value.size() &&
        CRYPTO_memcmp(
            info.value.macData.data(), mac.value.data(),
            mac.value.size()) == 0;
    OPENSSL_cleanse(hardwareId.data(), hardwareId.size());
    OPENSSL_cleanse(mac.value.data(), mac.value.size());
    return {
        matches ? RdpClientLicenseInfoHardwareIdError::None
                : RdpClientLicenseInfoHardwareIdError::MacMismatch};
}

namespace
{
struct BioCloser
{
    void operator()(BIO *bio) const noexcept { BIO_free(bio); }
};

struct X509Closer
{
    void operator()(X509 *certificate) const noexcept
    {
        X509_free(certificate);
    }
};

struct PkeyCloser
{
    void operator()(EVP_PKEY *key) const noexcept { EVP_PKEY_free(key); }
};

struct PkeyContextCloser
{
    void operator()(EVP_PKEY_CTX *context) const noexcept
    {
        EVP_PKEY_CTX_free(context);
    }
};

using OwnedBio = std::unique_ptr<BIO, BioCloser>;
using OwnedX509 = std::unique_ptr<X509, X509Closer>;
using OwnedPkey = std::unique_ptr<EVP_PKEY, PkeyCloser>;
using OwnedPkeyContext = std::unique_ptr<EVP_PKEY_CTX, PkeyContextCloser>;

int rejectPrivateKeyPassword(char *, int, int, void *) noexcept
{
    return 0;
}

[[nodiscard]] bool bioRemainderIsWhitespace(BIO *bio) noexcept
{
    if (bio == nullptr)
        return false;

    std::array<unsigned char, 256> buffer{};
    for (;;)
    {
        std::size_t bytesRead = 0U;
        const int result =
            BIO_read_ex(bio, buffer.data(), buffer.size(), &bytesRead);
        for (std::size_t index = 0U; index < bytesRead; ++index)
        {
            const unsigned char value = buffer[index];
            if (value != ' ' && value != '\t' &&
                value != '\r' && value != '\n')
                return false;
        }
        if (result != 1)
            return bytesRead == 0U && !BIO_should_retry(bio);
        if (bytesRead == 0U)
            return true;
    }
}

struct X509ChainLeafResult
{
    OwnedX509 leaf{};

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return leaf != nullptr;
    }
};

[[nodiscard]] X509ChainLeafResult parseLicensingX509Leaf(
    std::span<const std::uint8_t> serverCertificate) noexcept
{
    constexpr std::uint32_t certificateVersionMask = 0x7fffffffU;
    constexpr std::uint32_t x509CertificateChainVersion = 0x00000002U;
    constexpr std::uint32_t minimumCertificateCount = 2U;
    constexpr std::uint32_t maximumCertificateCount = 200U;

    if (serverCertificate.size() < 8U)
        return {};

    const std::uint32_t rawVersion = readLe32(serverCertificate, 0U);
    if ((rawVersion & certificateVersionMask) != x509CertificateChainVersion)
        return {};

    const std::uint32_t certificateCount =
        readLe32(serverCertificate, 4U);
    if (certificateCount < minimumCertificateCount ||
        certificateCount > maximumCertificateCount)
        return {};

    std::size_t offset = 8U;
    OwnedX509 issuer{};
    for (std::uint32_t index = 0U; index < certificateCount; ++index)
    {
        if (offset > serverCertificate.size() ||
            serverCertificate.size() - offset < 4U)
            return {};

        const std::size_t certificateBytes =
            readLe32(serverCertificate, offset);
        offset += 4U;
        if (certificateBytes == 0U ||
            certificateBytes > serverCertificate.size() - offset ||
            certificateBytes >
                static_cast<std::size_t>(std::numeric_limits<long>::max()))
            return {};

        const auto der =
            serverCertificate.subspan(offset, certificateBytes);
        const unsigned char *cursor = der.data();
        const unsigned char *const end = der.data() + der.size();
        OwnedX509 current{
            d2i_X509(nullptr, &cursor, static_cast<long>(der.size()))};
        if (!current || cursor != end)
            return {};

        // The first element is the external trust anchor for this bounded
        // check. Every later certificate must be cryptographically signed by
        // the immediately preceding root-first issuer. This proves internal
        // chain coherence without claiming the root is trusted by policy.
        if (issuer)
        {
            OwnedPkey issuerPublicKey{X509_get_pubkey(issuer.get())};
            if (!issuerPublicKey ||
                X509_verify(current.get(), issuerPublicKey.get()) != 1)
                return {};
        }

        issuer = std::move(current);
        offset += certificateBytes;
    }

    const std::size_t expectedPaddingBytes =
        8U + 4U * static_cast<std::size_t>(certificateCount);
    if (offset > serverCertificate.size() ||
        serverCertificate.size() - offset != expectedPaddingBytes ||
        !issuer)
        return {};

    return {std::move(issuer)};
}

[[nodiscard]] OwnedPkey loadLicensingPrivateKey(
    std::span<const std::uint8_t> privateKeyPem) noexcept
{
    if (privateKeyPem.empty() ||
        privateKeyPem.size() > kMaximumRdpLicensingPrivateKeyPemBytes ||
        privateKeyPem.size() >
            static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return {};

    OwnedBio privateKeyBio{BIO_new_mem_buf(
        privateKeyPem.data(), static_cast<int>(privateKeyPem.size()))};
    if (!privateKeyBio)
        return {};

    OwnedPkey privateKey{PEM_read_bio_PrivateKey(
        privateKeyBio.get(), nullptr, rejectPrivateKeyPassword, nullptr)};
    if (!privateKey || !bioRemainderIsWhitespace(privateKeyBio.get()))
        return {};
    return privateKey;
}

[[nodiscard]] bool supportedLicensingRsaKey(
    const EVP_PKEY *privateKey, std::size_t &modulusBytes) noexcept
{
    constexpr std::size_t minimumRsaModulusBytes = 64U; // legacy 512-bit
    if (privateKey == nullptr ||
        EVP_PKEY_base_id(privateKey) != EVP_PKEY_RSA)
        return false;

    const int keyBytesSigned = EVP_PKEY_get_size(privateKey);
    if (keyBytesSigned < static_cast<int>(minimumRsaModulusBytes) ||
        keyBytesSigned >
            static_cast<int>(kMaximumRdpLicensingRsaModulusBytes))
        return false;
    modulusBytes = static_cast<std::size_t>(keyBytesSigned);
    return true;
}
} // namespace

void cleanseRdpLicensingKeyMaterial(
    RdpLicensingKeyMaterial &material) noexcept
{
    OPENSSL_cleanse(
        material.macSaltKey.data(), material.macSaltKey.size());
    OPENSSL_cleanse(
        material.encryptionKey.data(), material.encryptionKey.size());
}

RdpLicensingKeyDerivationResult deriveRdpLicensingKeys(
    std::span<const std::uint8_t> preMasterSecret,
    std::span<const std::uint8_t> clientRandom,
    std::span<const std::uint8_t> serverRandom) noexcept
{
    if (preMasterSecret.size() != kRdpLicensingPreMasterSecretBytes ||
        clientRandom.size() != kRdpLicensingRandomBytes ||
        serverRandom.size() != kRdpLicensingRandomBytes)
        return {};

    constexpr std::array<std::uint8_t, 1> labelA{'A'};
    constexpr std::array<std::uint8_t, 2> labelBB{'B', 'B'};
    constexpr std::array<std::uint8_t, 3> labelCCC{'C', 'C', 'C'};
    const std::array<std::span<const std::uint8_t>, 3> labels{
        labelA, labelBB, labelCCC};

    std::array<std::uint8_t, 48> masterSecret{};
    std::array<std::uint8_t, 48> sessionKeyBlob{};
    bool ok = true;
    for (std::size_t index = 0U; index < labels.size(); ++index)
    {
        ok = ok && saltedHash(
            preMasterSecret, labels[index], clientRandom, serverRandom,
            std::span(masterSecret).subspan(index * 16U, 16U));
    }
    for (std::size_t index = 0U; ok && index < labels.size(); ++index)
    {
        ok = saltedHash(
            masterSecret, labels[index], serverRandom, clientRandom,
            std::span(sessionKeyBlob).subspan(index * 16U, 16U));
    }

    RdpLicensingKeyDerivationResult result{};
    if (ok)
    {
        std::copy_n(
            sessionKeyBlob.begin(), kRdpLicensingKeyBytes,
            result.value.macSaltKey.begin());

        std::array<std::uint8_t, 80> finalInput{};
        std::size_t finalBytes = 0U;
        ok = appendBytes(
                 finalInput, finalBytes,
                 std::span(sessionKeyBlob).subspan(16U, 16U)) &&
             appendBytes(finalInput, finalBytes, clientRandom) &&
             appendBytes(finalInput, finalBytes, serverRandom) &&
             digestExact(
                 EVP_md5(), std::span(finalInput).first(finalBytes),
                 result.value.encryptionKey);
        OPENSSL_cleanse(finalInput.data(), finalInput.size());
    }

    OPENSSL_cleanse(masterSecret.data(), masterSecret.size());
    OPENSSL_cleanse(sessionKeyBlob.data(), sessionKeyBlob.size());
    if (!ok)
    {
        result.value = {};
        result.error = RdpLicensingKeyDerivationError::DigestFailure;
        return result;
    }
    result.error = RdpLicensingKeyDerivationError::None;
    return result;
}

RdpLicensingServiceCredential::~RdpLicensingServiceCredential()
{
    OPENSSL_cleanse(privateKeyPem_.data(), privateKeyPem_.size());
    OPENSSL_cleanse(
        serverCertificateSha256_.data(), serverCertificateSha256_.size());
    privateKeyPemLength_ = 0U;
    rsaModulusBytes_ = 0U;
    configured_ = false;
}

bool RdpLicensingServiceCredential::configure(
    const RdpServerLicenseIdentity &identity,
    std::span<const std::uint8_t> privateKeyPem) noexcept
{
    if (attempted_)
        return false;
    attempted_ = true;

    if (!identity.configured())
        return false;

    auto leaf = parseLicensingX509Leaf(identity.serverCertificate());
    if (!leaf)
        return false;

    auto privateKey = loadLicensingPrivateKey(privateKeyPem);
    std::size_t rsaModulusBytes = 0U;
    if (!privateKey ||
        X509_check_private_key(leaf.leaf.get(), privateKey.get()) != 1 ||
        !supportedLicensingRsaKey(privateKey.get(), rsaModulusBytes))
        return false;

    std::array<std::uint8_t, 32> certificateDigest{};
    if (!digestExact(
            EVP_sha256(), identity.serverCertificate(), certificateDigest))
        return false;

    std::copy(
        privateKeyPem.begin(), privateKeyPem.end(), privateKeyPem_.begin());
    std::copy(
        certificateDigest.begin(), certificateDigest.end(),
        serverCertificateSha256_.begin());
    OPENSSL_cleanse(certificateDigest.data(), certificateDigest.size());

    privateKeyPemLength_ = privateKeyPem.size();
    rsaModulusBytes_ = rsaModulusBytes;
    configured_ = true;
    return true;
}

bool RdpLicensingServiceCredential::matches(
    const RdpServerLicenseIdentity &identity) const noexcept
{
    if (!configured_ || !identity.configured())
        return false;

    std::array<std::uint8_t, 32> certificateDigest{};
    if (!digestExact(
            EVP_sha256(), identity.serverCertificate(), certificateDigest))
        return false;
    const bool matches =
        CRYPTO_memcmp(
            certificateDigest.data(), serverCertificateSha256_.data(),
            certificateDigest.size()) == 0;
    OPENSSL_cleanse(certificateDigest.data(), certificateDigest.size());
    return matches;
}

RdpLicensingPreMasterDecryptResult
RdpLicensingServiceCredential::decryptPreMasterSecret(
    std::span<const std::uint8_t> encryptedPreMasterSecret) const noexcept
{
    RdpLicensingPreMasterDecryptResult result{};
    if (!configured_ || privateKeyPemLength_ == 0U ||
        rsaModulusBytes_ == 0U)
        return result;

    auto privateKey = loadLicensingPrivateKey(
        std::span(privateKeyPem_).first(privateKeyPemLength_));
    std::size_t keyBytes = 0U;
    if (!privateKey ||
        !supportedLicensingRsaKey(privateKey.get(), keyBytes) ||
        keyBytes != rsaModulusBytes_)
    {
        result.error = RdpLicensingPreMasterDecryptError::DecryptFailure;
        return result;
    }

    constexpr std::size_t protocolPaddingBytes = 8U;
    if (encryptedPreMasterSecret.size() !=
            keyBytes + protocolPaddingBytes ||
        !std::all_of(
            encryptedPreMasterSecret.end() -
                static_cast<std::ptrdiff_t>(protocolPaddingBytes),
            encryptedPreMasterSecret.end(),
            [](std::uint8_t value) { return value == 0U; }))
    {
        result.error =
            RdpLicensingPreMasterDecryptError::
                InvalidEncryptedPreMasterSecret;
        return result;
    }

    std::array<std::uint8_t, kMaximumRdpLicensingRsaModulusBytes>
        ciphertextBigEndian{};
    std::array<std::uint8_t, kMaximumRdpLicensingRsaModulusBytes>
        plaintextBigEndian{};
    std::array<std::uint8_t, kMaximumRdpLicensingRsaModulusBytes>
        plaintextLittleEndian{};

    std::reverse_copy(
        encryptedPreMasterSecret.begin(),
        encryptedPreMasterSecret.begin() +
            static_cast<std::ptrdiff_t>(keyBytes),
        ciphertextBigEndian.begin());

    OwnedPkeyContext context{EVP_PKEY_CTX_new(privateKey.get(), nullptr)};
    std::size_t plaintextBytes = keyBytes;
    const bool decrypted =
        context != nullptr &&
        EVP_PKEY_decrypt_init(context.get()) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(
            context.get(), RSA_NO_PADDING) == 1 &&
        EVP_PKEY_decrypt(
            context.get(), plaintextBigEndian.data(), &plaintextBytes,
            ciphertextBigEndian.data(), keyBytes) == 1 &&
        plaintextBytes == keyBytes;

    if (decrypted)
    {
        std::reverse_copy(
            plaintextBigEndian.begin(),
            plaintextBigEndian.begin() +
                static_cast<std::ptrdiff_t>(keyBytes),
            plaintextLittleEndian.begin());
    }

    const auto clearTemporaryBuffers = [&]() noexcept
    {
        OPENSSL_cleanse(
            ciphertextBigEndian.data(), ciphertextBigEndian.size());
        OPENSSL_cleanse(
            plaintextBigEndian.data(), plaintextBigEndian.size());
        OPENSSL_cleanse(
            plaintextLittleEndian.data(), plaintextLittleEndian.size());
    };

    if (!decrypted ||
        !std::all_of(
            plaintextLittleEndian.begin() +
                static_cast<std::ptrdiff_t>(
                    kRdpLicensingPreMasterSecretBytes),
            plaintextLittleEndian.begin() +
                static_cast<std::ptrdiff_t>(keyBytes),
            [](std::uint8_t value) { return value == 0U; }))
    {
        clearTemporaryBuffers();
        result.error = RdpLicensingPreMasterDecryptError::DecryptFailure;
        return result;
    }

    std::copy_n(
        plaintextLittleEndian.begin(),
        result.value.size(), result.value.begin());
    clearTemporaryBuffers();
    result.error = RdpLicensingPreMasterDecryptError::None;
    return result;
}

RdpInitialLicensingCryptoResult prepareInitialRdpLicensingCrypto(
    const RdpLicensingServiceCredential &credential,
    std::span<const std::uint8_t> completeMessage,
    std::span<const std::uint8_t> serverRandom) noexcept
{
    if (serverRandom.size() != kRdpLicensingRandomBytes)
        return {{}, RdpInitialLicensingCryptoError::InvalidServerRandom};

    const auto exchange =
        parseRdpClientLicensingKeyExchange(completeMessage);
    if (!exchange)
        return {{}, RdpInitialLicensingCryptoError::InvalidClientMessage};

    auto preMaster = credential.decryptPreMasterSecret(
        exchange.value.encryptedPreMasterSecret);
    if (!preMaster)
        return {{}, RdpInitialLicensingCryptoError::PreMasterDecryptFailure};

    auto derived = deriveRdpLicensingKeys(
        preMaster.value, exchange.value.clientRandom, serverRandom);
    OPENSSL_cleanse(preMaster.value.data(), preMaster.value.size());
    if (!derived)
    {
        cleanseRdpLicensingKeyMaterial(derived.value);
        return {{}, RdpInitialLicensingCryptoError::KeyDerivationFailure};
    }

    RdpInitialLicensingCryptoResult result{
        derived.value, RdpInitialLicensingCryptoError::None,
        exchange.value.type};
    cleanseRdpLicensingKeyMaterial(derived.value);
    return result;
}

bool RdpServerLicenseIdentity::configure(
    std::uint32_t productVersion,
    std::span<const std::uint8_t> companyNameUtf16,
    std::span<const std::uint8_t> productIdUtf16,
    std::span<const std::uint8_t> serverCertificate,
    std::span<const std::uint8_t> scopeAnsi) noexcept
{
    if (attempted_)
        return false;
    attempted_ = true;

    // At least one logical character plus the required terminator.
    if (productVersion == 0U ||
        companyNameUtf16.size() < 4U ||
        productIdUtf16.size() < 4U ||
        scopeAnsi.size() < 2U ||
        companyNameUtf16.size() > companyNameUtf16_.size() ||
        productIdUtf16.size() > productIdUtf16_.size() ||
        serverCertificate.empty() ||
        serverCertificate.size() > serverCertificate_.size() ||
        scopeAnsi.size() > scopeAnsi_.size() ||
        !validNullTerminatedUtf16Le(companyNameUtf16) ||
        !validNullTerminatedUtf16Le(productIdUtf16) ||
        !validNullTerminatedAnsi(scopeAnsi))
    {
        return false;
    }

    productVersion_ = productVersion;
    companyNameUtf16Length_ = companyNameUtf16.size();
    productIdUtf16Length_ = productIdUtf16.size();
    serverCertificateLength_ = serverCertificate.size();
    scopeAnsiLength_ = scopeAnsi.size();
    std::copy(companyNameUtf16.begin(), companyNameUtf16.end(),
              companyNameUtf16_.begin());
    std::copy(productIdUtf16.begin(), productIdUtf16.end(),
              productIdUtf16_.begin());
    std::copy(serverCertificate.begin(), serverCertificate.end(),
              serverCertificate_.begin());
    std::copy(scopeAnsi.begin(), scopeAnsi.end(), scopeAnsi_.begin());
    configured_ = true;
    return true;
}

RdpNewLicenseInfoEncodeResult encodeRdpNewLicenseInformation(
    const RdpServerLicenseIdentity &identity,
    std::span<const std::uint8_t> issuedCal,
    std::span<std::uint8_t> output) noexcept
{
    if (!identity.configured())
        return {0U, RdpNewLicenseInfoEncodeError::IdentityNotConfigured};
    if (issuedCal.empty())
        return {0U, RdpNewLicenseInfoEncodeError::InvalidLicense};
    if (issuedCal.size() > kMaximumRdpIssuedCalBytes)
        return {0U, RdpNewLicenseInfoEncodeError::Oversized};

    const auto scope = identity.scopeAnsi();
    const auto company = identity.companyNameUtf16();
    const auto product = identity.productIdUtf16();
    constexpr std::size_t fixedLengthBytes = 20U;
    const std::size_t variableBytes =
        scope.size() + company.size() + product.size() + issuedCal.size();
    if (variableBytes >
        std::numeric_limits<std::uint32_t>::max() - fixedLengthBytes)
        return {0U, RdpNewLicenseInfoEncodeError::Oversized};
    const std::size_t totalBytes = fixedLengthBytes + variableBytes;
    if (output.size() < totalBytes)
        return {0U, RdpNewLicenseInfoEncodeError::OutputTooSmall};

    // All validation is complete before the first write, so rejection is
    // transactional without a second packet-sized scratch buffer.
    std::size_t offset = 0U;
    writeLe32(output, offset, identity.productVersion());
    offset += 4U;
    writeLe32(output, offset, static_cast<std::uint32_t>(scope.size()));
    offset += 4U;
    std::copy(scope.begin(), scope.end(), output.begin() + offset);
    offset += scope.size();
    writeLe32(output, offset, static_cast<std::uint32_t>(company.size()));
    offset += 4U;
    std::copy(company.begin(), company.end(), output.begin() + offset);
    offset += company.size();
    writeLe32(output, offset, static_cast<std::uint32_t>(product.size()));
    offset += 4U;
    std::copy(product.begin(), product.end(), output.begin() + offset);
    offset += product.size();
    writeLe32(output, offset, static_cast<std::uint32_t>(issuedCal.size()));
    offset += 4U;
    std::copy(issuedCal.begin(), issuedCal.end(), output.begin() + offset);
    offset += issuedCal.size();

    return {offset, RdpNewLicenseInfoEncodeError::None};
}

RdpLicensingAuthorityGrantError RdpLicensingAuthorityGrant::configure(
    RdpServerLicenseGrantKind kind,
    std::uint64_t authorityGeneration,
    std::span<const std::uint8_t> authorityFingerprint,
    std::span<const std::uint8_t> issuedCal) noexcept
{
    if (attempted_)
        return RdpLicensingAuthorityGrantError::AlreadyConfigured;
    attempted_ = true;

    switch (kind)
    {
    case RdpServerLicenseGrantKind::NewLicense:
    case RdpServerLicenseGrantKind::UpgradeLicense:
        break;
    default:
        return RdpLicensingAuthorityGrantError::InvalidLicense;
    }

    if (authorityGeneration == 0U)
        return RdpLicensingAuthorityGrantError::InvalidAuthorityGeneration;
    if (authorityFingerprint.size() != authorityFingerprint_.size() ||
        std::all_of(
            authorityFingerprint.begin(), authorityFingerprint.end(),
            [](std::uint8_t value) { return value == 0U; }))
    {
        return RdpLicensingAuthorityGrantError::InvalidAuthorityFingerprint;
    }
    if (issuedCal.empty())
        return RdpLicensingAuthorityGrantError::InvalidLicense;
    if (issuedCal.size() > issuedCal_.size())
        return RdpLicensingAuthorityGrantError::Oversized;

    kind_ = kind;
    authorityGeneration_ = authorityGeneration;
    issuedCalLength_ = issuedCal.size();
    std::copy(
        authorityFingerprint.begin(), authorityFingerprint.end(),
        authorityFingerprint_.begin());
    std::copy(issuedCal.begin(), issuedCal.end(), issuedCal_.begin());
    configured_ = true;
    return RdpLicensingAuthorityGrantError::None;
}

bool RdpLicensingAuthorityGrant::matchesAuthority(
    std::uint64_t authorityGeneration,
    std::span<const std::uint8_t> authorityFingerprint) const noexcept
{
    return configured_ &&
           authorityGeneration != 0U &&
           authorityGeneration == authorityGeneration_ &&
           authorityFingerprint.size() == authorityFingerprint_.size() &&
           CRYPTO_memcmp(
               authorityFingerprint.data(),
               authorityFingerprint_.data(),
               authorityFingerprint_.size()) == 0;
}

RdpServerLicenseGrantEncodeResult encodeRdpServerLicenseGrant(
    RdpServerLicenseGrantKind kind,
    const RdpServerLicenseIdentity &identity,
    std::span<const std::uint8_t> issuedCal,
    RdpLicensingKeyMaterialView keyMaterial,
    std::span<std::uint8_t> output) noexcept
{
    constexpr std::size_t preambleBytes = 4U;
    constexpr std::size_t blobHeaderBytes = 4U;
    constexpr std::uint16_t encryptedDataBlobType = 0x0009U;

    std::uint8_t messageType = 0U;
    switch (kind)
    {
    case RdpServerLicenseGrantKind::NewLicense:
        messageType = static_cast<std::uint8_t>(
            RdpLicensingMessageType::ServerNewLicense);
        break;
    case RdpServerLicenseGrantKind::UpgradeLicense:
        messageType = static_cast<std::uint8_t>(
            RdpLicensingMessageType::ServerUpgradeLicense);
        break;
    default:
        return {0U, RdpServerLicenseGrantEncodeError::InvalidGrantKind};
    }

    if (!identity.configured())
        return {0U,
                RdpServerLicenseGrantEncodeError::IdentityNotConfigured};
    if (issuedCal.empty())
        return {0U, RdpServerLicenseGrantEncodeError::InvalidLicense};
    if (issuedCal.size() > kMaximumRdpServerLicenseGrantCalBytes)
        return {0U, RdpServerLicenseGrantEncodeError::Oversized};
    if (keyMaterial.macSaltKey.size() != kRdpLicensingKeyBytes ||
        keyMaterial.encryptionKey.size() != kRdpLicensingKeyBytes)
        return {0U, RdpServerLicenseGrantEncodeError::InvalidKeyMaterial};

    std::array<std::uint8_t, kMaximumRdpServerLicenseGrantPlaintextBytes>
        plaintext{};
    std::array<std::uint8_t, kMaximumRdpServerLicenseGrantBytes> packet{};
    const auto cleanseTemporaryBuffers = [&]() noexcept
    {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        OPENSSL_cleanse(packet.data(), packet.size());
    };

    const auto plaintextResult =
        encodeRdpNewLicenseInformation(identity, issuedCal, plaintext);
    if (!plaintextResult)
    {
        cleanseTemporaryBuffers();
        return {0U,
                RdpServerLicenseGrantEncodeError::PlaintextEncodingFailure};
    }

    const std::size_t plaintextBytes = plaintextResult.bytesWritten;
    if (plaintextBytes > kMaximumRdpServerLicenseGrantPlaintextBytes ||
        plaintextBytes > std::numeric_limits<std::uint16_t>::max())
    {
        cleanseTemporaryBuffers();
        return {0U, RdpServerLicenseGrantEncodeError::Oversized};
    }

    const std::size_t totalBytes =
        kRdpServerLicenseGrantFixedBytes + plaintextBytes;
    if (totalBytes > kMaximumRdpServerLicenseGrantBytes ||
        totalBytes > std::numeric_limits<std::uint16_t>::max())
    {
        cleanseTemporaryBuffers();
        return {0U, RdpServerLicenseGrantEncodeError::Oversized};
    }
    if (output.size() < totalBytes)
    {
        cleanseTemporaryBuffers();
        return {0U, RdpServerLicenseGrantEncodeError::OutputTooSmall};
    }

    packet[0] = messageType;
    packet[1] = 0x03U;
    writeLe16(packet, 2U, static_cast<std::uint16_t>(totalBytes));

    std::size_t offset = preambleBytes;
    writeLe16(packet, offset, encryptedDataBlobType);
    writeLe16(
        packet, offset + 2U,
        static_cast<std::uint16_t>(plaintextBytes));
    offset += blobHeaderBytes;

    const auto plaintextView =
        std::span<const std::uint8_t>{plaintext}.first(plaintextBytes);
    auto encrypted = std::span(packet).subspan(offset, plaintextBytes);
    if (!cryptRdpLicensingData(
            keyMaterial.encryptionKey, plaintextView, encrypted))
    {
        cleanseTemporaryBuffers();
        return {0U, RdpServerLicenseGrantEncodeError::EncryptionFailure};
    }
    offset += plaintextBytes;

    auto mac = generateRdpLicensingMac(
        keyMaterial.macSaltKey, plaintextView);
    if (!mac)
    {
        cleanseTemporaryBuffers();
        OPENSSL_cleanse(mac.value.data(), mac.value.size());
        return {0U, RdpServerLicenseGrantEncodeError::MacFailure};
    }
    std::copy(mac.value.begin(), mac.value.end(), packet.begin() + offset);
    OPENSSL_cleanse(mac.value.data(), mac.value.size());
    offset += kRdpLicensingMacBytes;

    std::copy(packet.begin(), packet.begin() + offset, output.begin());
    cleanseTemporaryBuffers();
    return {offset, RdpServerLicenseGrantEncodeError::None};
}

RdpServerLicenseRequestEncodeResult
encodeEnhancedSecurityServerLicenseRequest(
    const RdpServerLicenseRequestFields &fields,
    std::span<std::uint8_t> output) noexcept
{
    constexpr std::size_t preambleBytes = 4U;
    constexpr std::size_t serverRandomBytes = 32U;
    constexpr std::size_t productFixedBytes = 12U;
    constexpr std::size_t blobHeaderBytes = 4U;
    constexpr std::size_t keyExchangePayloadBytes = 4U;
    constexpr std::size_t scopeCountBytes = 4U;

    if (fields.serverRandom.size() != serverRandomBytes ||
        std::all_of(fields.serverRandom.begin(), fields.serverRandom.end(),
                    [](std::uint8_t value) { return value == 0U; }))
    {
        return {0U, RdpServerLicenseRequestEncodeError::InvalidRandom};
    }
    if (fields.productVersion == 0U ||
        !validNullTerminatedUtf16Le(fields.companyNameUtf16) ||
        !validNullTerminatedUtf16Le(fields.productIdUtf16))
    {
        return {0U, RdpServerLicenseRequestEncodeError::InvalidProductInfo};
    }
    if (fields.serverCertificate.empty() ||
        fields.serverCertificate.size() >
            kMaximumRdpServerLicenseCertificateBytes)
    {
        return {0U,
                RdpServerLicenseRequestEncodeError::InvalidServerCertificate};
    }
    if (!validNullTerminatedAnsi(fields.scopeAnsi))
        return {0U, RdpServerLicenseRequestEncodeError::InvalidScope};

    if (fields.companyNameUtf16.size() >
            std::numeric_limits<std::uint32_t>::max() ||
        fields.productIdUtf16.size() >
            std::numeric_limits<std::uint32_t>::max() ||
        fields.serverCertificate.size() >
            std::numeric_limits<std::uint16_t>::max() ||
        fields.scopeAnsi.size() > std::numeric_limits<std::uint16_t>::max())
    {
        return {0U, RdpServerLicenseRequestEncodeError::Oversized};
    }

    const std::size_t fixedBytes =
        preambleBytes + serverRandomBytes + productFixedBytes +
        blobHeaderBytes + keyExchangePayloadBytes +
        blobHeaderBytes + scopeCountBytes + blobHeaderBytes;
    const std::size_t variableBytes =
        fields.companyNameUtf16.size() +
        fields.productIdUtf16.size() +
        fields.serverCertificate.size() +
        fields.scopeAnsi.size();
    if (variableBytes >
        kMaximumRdpServerLicenseRequestBytes - fixedBytes)
    {
        return {0U, RdpServerLicenseRequestEncodeError::Oversized};
    }
    const std::size_t totalBytes = fixedBytes + variableBytes;
    if (totalBytes > std::numeric_limits<std::uint16_t>::max())
        return {0U, RdpServerLicenseRequestEncodeError::Oversized};
    if (output.size() < totalBytes)
        return {0U, RdpServerLicenseRequestEncodeError::OutputTooSmall};

    std::size_t offset = 0U;
    output[offset++] =
        static_cast<std::uint8_t>(
            RdpLicensingMessageType::ServerLicenseRequest);
    output[offset++] = kServerLicenseRequestPreambleFlags;
    writeLe16(output, offset, static_cast<std::uint16_t>(totalBytes));
    offset += 2U;

    std::copy(fields.serverRandom.begin(), fields.serverRandom.end(),
              output.begin() + offset);
    offset += fields.serverRandom.size();

    writeLe32(output, offset, fields.productVersion);
    offset += 4U;
    writeLe32(output, offset,
              static_cast<std::uint32_t>(fields.companyNameUtf16.size()));
    offset += 4U;
    std::copy(fields.companyNameUtf16.begin(), fields.companyNameUtf16.end(),
              output.begin() + offset);
    offset += fields.companyNameUtf16.size();
    writeLe32(output, offset,
              static_cast<std::uint32_t>(fields.productIdUtf16.size()));
    offset += 4U;
    std::copy(fields.productIdUtf16.begin(), fields.productIdUtf16.end(),
              output.begin() + offset);
    offset += fields.productIdUtf16.size();

    writeLe16(output, offset, kBlobKeyExchangeAlgorithms);
    writeLe16(output, offset + 2U,
              static_cast<std::uint16_t>(keyExchangePayloadBytes));
    offset += blobHeaderBytes;
    writeLe32(output, offset, kKeyExchangeAlgRsa);
    offset += keyExchangePayloadBytes;

    // Enhanced RDP Security protects transport confidentiality, but its
    // SC_SECURITY block deliberately carries no server certificate. The
    // licensing certificate must therefore be present here for RSA exchange.
    writeLe16(output, offset, kBlobServerCertificate);
    writeLe16(
        output, offset + 2U,
        static_cast<std::uint16_t>(fields.serverCertificate.size()));
    offset += blobHeaderBytes;
    std::copy(fields.serverCertificate.begin(),
              fields.serverCertificate.end(), output.begin() + offset);
    offset += fields.serverCertificate.size();

    writeLe32(output, offset, 1U);
    offset += scopeCountBytes;
    writeLe16(output, offset, kBlobScope);
    writeLe16(output, offset + 2U,
              static_cast<std::uint16_t>(fields.scopeAnsi.size()));
    offset += blobHeaderBytes;
    std::copy(fields.scopeAnsi.begin(), fields.scopeAnsi.end(),
              output.begin() + offset);
    offset += fields.scopeAnsi.size();

    return {offset, RdpServerLicenseRequestEncodeError::None};
}

RdpLicensingParseResult parseRdpLicensingMessage(
    std::span<const std::uint8_t> completeMessage) noexcept
{
    if (completeMessage.size() < kLicensePreambleBytes)
        return {{}, RdpLicensingParseError::Truncated};
    if (completeMessage.size() > kMaximumRdpLicensingPduBytes)
        return {{}, RdpLicensingParseError::Oversized};

    const std::size_t declaredBytes = readLe16(completeMessage, 2U);
    if (declaredBytes != completeMessage.size())
        return {{}, RdpLicensingParseError::LengthMismatch};

    const std::uint8_t rawType = completeMessage[0];
    if (!knownMessageType(rawType))
        return {{}, RdpLicensingParseError::InvalidType};

    const std::uint8_t flags = completeMessage[1];
    const std::uint8_t protocolVersion = flags & kProtocolVersionMask;
    if ((flags & static_cast<std::uint8_t>(~kAllowedPreambleFlags)) != 0U ||
        (protocolVersion != 2U && protocolVersion != 3U))
        return {{}, RdpLicensingParseError::InvalidFlags};

    RdpLicensingMessageView view{};
    view.type = static_cast<RdpLicensingMessageType>(rawType);
    view.protocolVersion = protocolVersion;
    view.extendedErrorSupported = (flags & kExtendedErrorSupported) != 0U;
    view.body = completeMessage.subspan(kLicensePreambleBytes);
    return {view, RdpLicensingParseError::None};
}

bool RdpServerLicenseRequestWriteGate::advanceReplySequence() noexcept
{
    if (replySequence_ == std::numeric_limits<std::uint64_t>::max())
        return false;
    ++replySequence_;
    return replySequence_ != 0U;
}

bool RdpServerLicenseRequestWriteGate::advanceWriteSliceSequence() noexcept
{
    if (writeSliceSequence_ == std::numeric_limits<std::uint64_t>::max())
        return false;
    ++writeSliceSequence_;
    return writeSliceSequence_ != 0U;
}

bool RdpServerLicenseRequestWriteGate::queue(
    const RdpServerLicenseIdentity &identity) noexcept
{
    if (closed_ || delivered_ || pendingLength_ != 0U ||
        lifecycle_ == nullptr ||
        lifecycle_->phase() != RdpLicensingPhase::NotStarted ||
        !identity.configured())
    {
        close();
        return false;
    }

    serverRandom_.fill(0U);
    if (RAND_priv_bytes(
            serverRandom_.data(),
            static_cast<int>(serverRandom_.size())) != 1)
    {
        close();
        return false;
    }

    const RdpServerLicenseRequestFields fields{
        serverRandom_,
        identity.productVersion(),
        identity.companyNameUtf16(),
        identity.productIdUtf16(),
        identity.serverCertificate(),
        identity.scopeAnsi()};
    const auto encoded = encodeEnhancedSecurityServerLicenseRequest(
        fields, pending_);
    if (!encoded || !advanceReplySequence() ||
        !advanceWriteSliceSequence())
    {
        close();
        return false;
    }

    pendingLength_ = encoded.bytesWritten;
    bytesWritten_ = 0U;
    return true;
}

RdpServerLicenseRequestWriteView
RdpServerLicenseRequestWriteGate::pendingWrite() const noexcept
{
    if (closed_ || delivered_ || pendingLength_ == 0U ||
        bytesWritten_ >= pendingLength_)
        return {};
    return {
        std::span(pending_).first(pendingLength_).subspan(bytesWritten_),
        replySequence_,
        writeSliceSequence_};
}

RdpServerLicenseRequestWriteOutcome
RdpServerLicenseRequestWriteGate::onBytesWritten(
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (closed_ || delivered_ || pendingLength_ == 0U ||
        lifecycle_ == nullptr ||
        lifecycle_->phase() != RdpLicensingPhase::NotStarted ||
        replySequence == 0U || replySequence != replySequence_ ||
        writeSliceSequence == 0U ||
        writeSliceSequence != writeSliceSequence_ ||
        acceptedBytes > pendingLength_ - bytesWritten_)
    {
        close();
        return RdpServerLicenseRequestWriteOutcome::Rejected;
    }

    if (acceptedBytes == 0U)
        return RdpServerLicenseRequestWriteOutcome::Pending;

    bytesWritten_ += acceptedBytes;
    if (bytesWritten_ != pendingLength_)
    {
        if (!advanceWriteSliceSequence())
        {
            close();
            return RdpServerLicenseRequestWriteOutcome::Rejected;
        }
        return RdpServerLicenseRequestWriteOutcome::Pending;
    }

    if (!lifecycle_->onServerLicenseRequestWritten(serverRandom_))
    {
        close();
        return RdpServerLicenseRequestWriteOutcome::Rejected;
    }
    serverRandom_.fill(0U);

    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    delivered_ = true;
    return RdpServerLicenseRequestWriteOutcome::Delivered;
}

void RdpServerLicenseRequestWriteGate::close() noexcept
{
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    serverRandom_.fill(0U);
    delivered_ = false;
    closed_ = true;
    if (lifecycle_ != nullptr)
        lifecycle_->close();
}

bool RdpServerPlatformChallengeWriteGate::advanceReplySequence() noexcept
{
    if (replySequence_ == std::numeric_limits<std::uint64_t>::max())
        return false;
    ++replySequence_;
    return replySequence_ != 0U;
}

bool RdpServerPlatformChallengeWriteGate::advanceWriteSliceSequence() noexcept
{
    if (writeSliceSequence_ == std::numeric_limits<std::uint64_t>::max())
        return false;
    ++writeSliceSequence_;
    return writeSliceSequence_ != 0U;
}

bool RdpServerPlatformChallengeWriteGate::queue(
    const RdpLicensingKeyMaterial &keyMaterial) noexcept
{
    if (closed_ || delivered_ || pendingLength_ != 0U ||
        lifecycle_ == nullptr ||
        lifecycle_->phase() != RdpLicensingPhase::AwaitServerDecision ||
        lifecycle_->decisionBranch() !=
            RdpLicensingDecisionBranch::PlatformChallengeRequired)
    {
        close();
        return false;
    }

    std::array<std::uint8_t, kRdpPlatformChallengeSeedBytes> seed{};
    if (RAND_priv_bytes(seed.data(), static_cast<int>(seed.size())) != 1)
    {
        OPENSSL_cleanse(seed.data(), seed.size());
        close();
        return false;
    }

    static constexpr std::array<std::uint8_t, 16> hex{
        '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    std::size_t challengeOffset = 0U;
    for (const std::uint8_t value : seed)
    {
        plaintextChallenge_[challengeOffset++] = hex[value >> 4U];
        plaintextChallenge_[challengeOffset++] = 0U;
        plaintextChallenge_[challengeOffset++] = hex[value & 0x0fU];
        plaintextChallenge_[challengeOffset++] = 0U;
    }
    plaintextChallenge_[challengeOffset++] = 0U;
    plaintextChallenge_[challengeOffset++] = 0U;
    OPENSSL_cleanse(seed.data(), seed.size());

    if (challengeOffset != plaintextChallenge_.size())
    {
        close();
        return false;
    }

    const auto encoded = encodeRdpServerPlatformChallenge(
        plaintextChallenge_, keyMaterial, pending_);
    if (!encoded || !advanceReplySequence() ||
        !advanceWriteSliceSequence())
    {
        close();
        return false;
    }

    pendingLength_ = encoded.bytesWritten;
    bytesWritten_ = 0U;
    return true;
}

RdpServerPlatformChallengeWriteView
RdpServerPlatformChallengeWriteGate::pendingWrite() const noexcept
{
    if (closed_ || delivered_ || pendingLength_ == 0U ||
        bytesWritten_ >= pendingLength_)
        return {};
    return {
        std::span(pending_).first(pendingLength_).subspan(bytesWritten_),
        replySequence_,
        writeSliceSequence_};
}

RdpServerPlatformChallengeWriteOutcome
RdpServerPlatformChallengeWriteGate::onBytesWritten(
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (closed_ || delivered_ || pendingLength_ == 0U ||
        lifecycle_ == nullptr ||
        lifecycle_->phase() != RdpLicensingPhase::AwaitServerDecision ||
        lifecycle_->decisionBranch() !=
            RdpLicensingDecisionBranch::PlatformChallengeRequired ||
        replySequence == 0U || replySequence != replySequence_ ||
        writeSliceSequence == 0U ||
        writeSliceSequence != writeSliceSequence_ ||
        acceptedBytes > pendingLength_ - bytesWritten_)
    {
        close();
        return RdpServerPlatformChallengeWriteOutcome::Rejected;
    }

    if (acceptedBytes == 0U)
        return RdpServerPlatformChallengeWriteOutcome::Pending;

    bytesWritten_ += acceptedBytes;
    if (bytesWritten_ != pendingLength_)
    {
        if (!advanceWriteSliceSequence())
        {
            close();
            return RdpServerPlatformChallengeWriteOutcome::Rejected;
        }
        return RdpServerPlatformChallengeWriteOutcome::Pending;
    }

    if (!lifecycle_->onServerPlatformChallengeWritten(plaintextChallenge_))
    {
        close();
        return RdpServerPlatformChallengeWriteOutcome::Rejected;
    }

    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    delivered_ = true;
    OPENSSL_cleanse(
        plaintextChallenge_.data(), plaintextChallenge_.size());
    return RdpServerPlatformChallengeWriteOutcome::Delivered;
}

void RdpServerPlatformChallengeWriteGate::close() noexcept
{
    OPENSSL_cleanse(pending_.data(), pending_.size());
    OPENSSL_cleanse(
        plaintextChallenge_.data(), plaintextChallenge_.size());
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    delivered_ = false;
    closed_ = true;
    if (lifecycle_ != nullptr)
        lifecycle_->close();
}

bool RdpServerLicenseGrantWriteGate::advanceReplySequence() noexcept
{
    if (replySequence_ == std::numeric_limits<std::uint64_t>::max())
        return false;
    ++replySequence_;
    return replySequence_ != 0U;
}

bool RdpServerLicenseGrantWriteGate::advanceWriteSliceSequence() noexcept
{
    if (writeSliceSequence_ == std::numeric_limits<std::uint64_t>::max())
        return false;
    ++writeSliceSequence_;
    return writeSliceSequence_ != 0U;
}

bool RdpServerLicenseGrantWriteGate::queue(
    const RdpLicensingAuthorityGrant &grant,
    const RdpServerLicenseIdentity &identity,
    const RdpLicensingKeyMaterial &keyMaterial,
    std::uint64_t authorityGeneration,
    std::span<const std::uint8_t> authorityFingerprint) noexcept
{
    if (closed_ || delivered_ || pendingLength_ != 0U ||
        lifecycle_ == nullptr ||
        lifecycle_->phase() != RdpLicensingPhase::AwaitServerDecision ||
        lifecycle_->decisionBranch() !=
            RdpLicensingDecisionBranch::NewLicenseIssuanceRequired ||
        !grant.configured() ||
        grant.kind() != RdpServerLicenseGrantKind::NewLicense ||
        !grant.matchesAuthority(
            authorityGeneration, authorityFingerprint))
    {
        close();
        return false;
    }

    const auto encoded = encodeRdpServerLicenseGrant(
        grant.kind(), identity, grant.issuedCal(), keyMaterial, pending_);
    if (!encoded || !advanceReplySequence() ||
        !advanceWriteSliceSequence())
    {
        close();
        return false;
    }

    pendingLength_ = encoded.bytesWritten;
    bytesWritten_ = 0U;
    return true;
}

RdpServerLicenseGrantWriteView
RdpServerLicenseGrantWriteGate::pendingWrite() const noexcept
{
    if (closed_ || delivered_ || pendingLength_ == 0U ||
        bytesWritten_ >= pendingLength_)
        return {};
    return {
        std::span(pending_).first(pendingLength_).subspan(bytesWritten_),
        replySequence_,
        writeSliceSequence_};
}

RdpServerLicenseGrantWriteOutcome
RdpServerLicenseGrantWriteGate::onBytesWritten(
    std::uint64_t replySequence,
    std::uint64_t writeSliceSequence,
    std::size_t acceptedBytes) noexcept
{
    if (closed_ || delivered_ || pendingLength_ == 0U ||
        lifecycle_ == nullptr ||
        lifecycle_->phase() != RdpLicensingPhase::AwaitServerDecision ||
        lifecycle_->decisionBranch() !=
            RdpLicensingDecisionBranch::NewLicenseIssuanceRequired ||
        replySequence == 0U || replySequence != replySequence_ ||
        writeSliceSequence == 0U ||
        writeSliceSequence != writeSliceSequence_ ||
        acceptedBytes > pendingLength_ - bytesWritten_)
    {
        close();
        return RdpServerLicenseGrantWriteOutcome::Rejected;
    }

    if (acceptedBytes == 0U)
        return RdpServerLicenseGrantWriteOutcome::Pending;

    bytesWritten_ += acceptedBytes;
    if (bytesWritten_ != pendingLength_)
    {
        if (!advanceWriteSliceSequence())
        {
            close();
            return RdpServerLicenseGrantWriteOutcome::Rejected;
        }
        return RdpServerLicenseGrantWriteOutcome::Pending;
    }

    if (!lifecycle_->onServerLicenseGrantWritten(
            RdpServerLicenseGrantKind::NewLicense))
    {
        close();
        return RdpServerLicenseGrantWriteOutcome::Rejected;
    }

    OPENSSL_cleanse(pending_.data(), pending_.size());
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    delivered_ = true;
    return RdpServerLicenseGrantWriteOutcome::Delivered;
}

void RdpServerLicenseGrantWriteGate::close() noexcept
{
    OPENSSL_cleanse(pending_.data(), pending_.size());
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    delivered_ = false;
    closed_ = true;
    if (lifecycle_ != nullptr)
        lifecycle_->close();
}

bool RdpLicensingLifecycle::onServerLicenseRequestWritten(
    std::span<const std::uint8_t> serverRandom) noexcept
{
    if (phase_ == RdpLicensingPhase::Closed)
        return false;
    if (phase_ != RdpLicensingPhase::NotStarted ||
        serverRandom.size() != serverRandom_.size())
    {
        fail();
        return false;
    }
    std::copy(serverRandom.begin(), serverRandom.end(), serverRandom_.begin());
    serverRandomReady_ = true;
    platformChallenge_.fill(0U);
    platformChallengeReady_ = false;
    decisionBranch_ = RdpLicensingDecisionBranch::None;
    phase_ = RdpLicensingPhase::AwaitClientLicenseResponse;
    return true;
}

bool RdpLicensingLifecycle::onServerPlatformChallengeWritten(
    std::span<const std::uint8_t> plaintextChallenge) noexcept
{
    if (phase_ == RdpLicensingPhase::Closed)
        return false;
    if (phase_ != RdpLicensingPhase::AwaitServerDecision ||
        decisionBranch_ !=
            RdpLicensingDecisionBranch::PlatformChallengeRequired ||
        plaintextChallenge.size() != platformChallenge_.size() ||
        !validNullTerminatedUtf16Le(plaintextChallenge))
    {
        fail();
        return false;
    }

    std::copy(
        plaintextChallenge.begin(), plaintextChallenge.end(),
        platformChallenge_.begin());
    platformChallengeReady_ = true;
    decisionBranch_ =
        RdpLicensingDecisionBranch::AwaitPlatformChallengeResponse;
    phase_ = RdpLicensingPhase::AwaitClientPlatformChallengeResponse;
    return true;
}

bool RdpLicensingLifecycle::onServerLicenseGrantWritten(
    RdpServerLicenseGrantKind kind) noexcept
{
    if (phase_ == RdpLicensingPhase::Closed)
        return false;
    if (phase_ != RdpLicensingPhase::AwaitServerDecision ||
        decisionBranch_ !=
            RdpLicensingDecisionBranch::NewLicenseIssuanceRequired ||
        kind != RdpServerLicenseGrantKind::NewLicense)
    {
        fail();
        return false;
    }

    serverRandom_.fill(0U);
    platformChallenge_.fill(0U);
    serverRandomReady_ = false;
    platformChallengeReady_ = false;
    decisionBranch_ = RdpLicensingDecisionBranch::None;
    phase_ = RdpLicensingPhase::Licensed;
    return true;
}

RdpLicensingIntake
RdpLicensingLifecycle::onClientPlatformChallengeResponse(
    std::span<const std::uint8_t> completeMessage,
    const RdpLicensingKeyMaterial &keyMaterial) noexcept
{
    if (phase_ == RdpLicensingPhase::Closed)
        return RdpLicensingIntake::Closed;
    if (phase_ == RdpLicensingPhase::Failed)
        return RdpLicensingIntake::Failed;
    if (phase_ != RdpLicensingPhase::AwaitClientPlatformChallengeResponse ||
        decisionBranch_ !=
            RdpLicensingDecisionBranch::AwaitPlatformChallengeResponse ||
        !platformChallengeReady_)
    {
        fail();
        return RdpLicensingIntake::UnexpectedMessage;
    }

    const auto verified = verifyRdpClientPlatformChallengeResponse(
        completeMessage, keyMaterial, platformChallenge());
    if (!verified)
    {
        fail();
        return RdpLicensingIntake::MalformedMessage;
    }

    platformChallenge_.fill(0U);
    platformChallengeReady_ = false;
    serverRandom_.fill(0U);
    serverRandomReady_ = false;
    decisionBranch_ =
        RdpLicensingDecisionBranch::NewLicenseIssuanceRequired;
    phase_ = RdpLicensingPhase::AwaitServerDecision;
    return RdpLicensingIntake::ClientPlatformChallengeResponseAccepted;
}

RdpLicensingIntake RdpLicensingLifecycle::onClientMessage(
    std::span<const std::uint8_t> completeMessage) noexcept
{
    if (phase_ == RdpLicensingPhase::Closed)
        return RdpLicensingIntake::Closed;
    if (phase_ == RdpLicensingPhase::Failed)
        return RdpLicensingIntake::Failed;
    if (phase_ != RdpLicensingPhase::AwaitClientLicenseResponse)
    {
        fail();
        return RdpLicensingIntake::UnexpectedMessage;
    }

    const auto parsed = parseRdpLicensingMessage(completeMessage);
    if (!parsed)
    {
        fail();
        return RdpLicensingIntake::MalformedMessage;
    }

    switch (parsed.value.type)
    {
    case RdpLicensingMessageType::ClientNewLicenseRequest:
    {
        RdpClientLicensingKeyExchangeView view{};
        if (!parseClientNewLicenseRequestBody(parsed.value.body, view))
        {
            fail();
            return RdpLicensingIntake::MalformedMessage;
        }
        decisionBranch_ =
            RdpLicensingDecisionBranch::PlatformChallengeRequired;
        phase_ = RdpLicensingPhase::AwaitServerDecision;
        return RdpLicensingIntake::ClientNewLicenseRequestAccepted;
    }

    case RdpLicensingMessageType::ClientLicenseInfo:
    {
        ParsedClientLicenseInfoBody fields{};
        if (!parseClientLicenseInfoBody(parsed.value.body, fields))
        {
            fail();
            return RdpLicensingIntake::MalformedMessage;
        }
        decisionBranch_ =
            RdpLicensingDecisionBranch::ClientLicenseInfoValidation;
        phase_ = RdpLicensingPhase::AwaitServerDecision;
        return RdpLicensingIntake::ClientLicenseInfoAccepted;
    }

    default:
        fail();
        return RdpLicensingIntake::UnexpectedMessage;
    }
}

} // namespace rdp_server::server::transport
