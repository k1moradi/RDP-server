// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp_licensing.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{
namespace
{
constexpr std::size_t kLicensePreambleBytes = 4U;
constexpr std::uint8_t kProtocolVersionMask = 0x0fU;
constexpr std::uint8_t kExtendedErrorSupported = 0x80U;
constexpr std::uint8_t kAllowedPreambleFlags =
    kProtocolVersionMask | kExtendedErrorSupported;
constexpr std::size_t kInitialClientFixedBytes = 40U;
constexpr std::size_t kMacBytes = 16U;

constexpr std::uint16_t kBlobData = 0x0001U;
constexpr std::uint16_t kBlobRandom = 0x0002U;
constexpr std::uint16_t kBlobClientUserName = 0x000fU;
constexpr std::uint16_t kBlobClientMachineName = 0x0010U;
constexpr std::uint32_t kKeyExchangeAlgRsa = 0x00000001U;

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

[[nodiscard]] bool validInitialClientPrefix(
    std::span<const std::uint8_t> body) noexcept
{
    if (body.size() < kInitialClientFixedBytes)
        return false;
    // MS-RDPELE 2.2.2.2 requires KEY_EXCHANGE_ALG_RSA. PlatformId and the
    // 32-byte ClientRandom are retained as opaque protocol fields here.
    return readLe32(body, 0U) == kKeyExchangeAlgRsa;
}

[[nodiscard]] bool validClientNewLicenseRequest(
    std::span<const std::uint8_t> body) noexcept
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
        offset != body.size())
        return false;

    return validNullTerminatedAnsi(clientUserName) &&
           validNullTerminatedAnsi(clientMachineName);
}

[[nodiscard]] bool validClientLicenseInfo(
    std::span<const std::uint8_t> body) noexcept
{
    if (!validInitialClientPrefix(body))
        return false;

    std::size_t offset = kInitialClientFixedBytes;
    std::span<const std::uint8_t> encryptedPreMasterSecret;
    std::span<const std::uint8_t> licenseInfo;
    std::span<const std::uint8_t> encryptedHardwareId;
    if (!readRequiredBlob(body, offset, kBlobRandom,
                          encryptedPreMasterSecret) ||
        !readRequiredBlob(body, offset, kBlobData, licenseInfo) ||
        !readRequiredBlob(body, offset, kBlobData, encryptedHardwareId))
        return false;

    // MACData is exactly 16 bytes and terminates CLIENT_LICENSE_INFO.
    return offset <= body.size() && body.size() - offset == kMacBytes;
}
} // namespace

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

bool RdpLicensingLifecycle::onServerLicenseRequestWritten() noexcept
{
    if (phase_ == RdpLicensingPhase::Closed)
        return false;
    if (phase_ != RdpLicensingPhase::NotStarted)
    {
        fail();
        return false;
    }
    phase_ = RdpLicensingPhase::AwaitClientLicenseResponse;
    return true;
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
        if (!validClientNewLicenseRequest(parsed.value.body))
        {
            fail();
            return RdpLicensingIntake::MalformedMessage;
        }
        phase_ = RdpLicensingPhase::AwaitServerDecision;
        return RdpLicensingIntake::ClientNewLicenseRequestAccepted;

    case RdpLicensingMessageType::ClientLicenseInfo:
        if (!validClientLicenseInfo(parsed.value.body))
        {
            fail();
            return RdpLicensingIntake::MalformedMessage;
        }
        phase_ = RdpLicensingPhase::AwaitServerDecision;
        return RdpLicensingIntake::ClientLicenseInfoAccepted;

    default:
        fail();
        return RdpLicensingIntake::UnexpectedMessage;
    }
}

} // namespace rdp_server::server::transport
