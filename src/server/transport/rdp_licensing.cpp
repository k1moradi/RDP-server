// SPDX-License-Identifier: GPL-3.0-or-later
#include "rdp_licensing.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
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
    if (!validNullTerminatedAnsi(fields.scopeAnsi))
        return {0U, RdpServerLicenseRequestEncodeError::InvalidScope};

    if (fields.companyNameUtf16.size() >
            std::numeric_limits<std::uint32_t>::max() ||
        fields.productIdUtf16.size() >
            std::numeric_limits<std::uint32_t>::max() ||
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

    // Enhanced RDP Security already protects this connection.
    writeLe16(output, offset, kBlobServerCertificate);
    writeLe16(output, offset + 2U, 0U);
    offset += blobHeaderBytes;

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
    const RdpServerLicenseRequestFields &fields) noexcept
{
    if (closed_ || delivered_ || pendingLength_ != 0U ||
        lifecycle_ == nullptr ||
        lifecycle_->phase() != RdpLicensingPhase::NotStarted)
    {
        close();
        return false;
    }

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

    if (!lifecycle_->onServerLicenseRequestWritten())
    {
        close();
        return RdpServerLicenseRequestWriteOutcome::Rejected;
    }

    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    delivered_ = true;
    return RdpServerLicenseRequestWriteOutcome::Delivered;
}

void RdpServerLicenseRequestWriteGate::close() noexcept
{
    pendingLength_ = 0U;
    bytesWritten_ = 0U;
    delivered_ = false;
    closed_ = true;
    if (lifecycle_ != nullptr)
        lifecycle_->close();
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
