// SPDX-License-Identifier: GPL-3.0-or-later
#include "credssp_tsrequest.h"

#include <algorithm>
#include <openssl/crypto.h>

namespace rdp_server::server::security
{
namespace
{

struct DerCursor
{
    std::span<const std::uint8_t> bytes{};
    std::size_t offset{};

    [[nodiscard]] bool read(std::uint8_t tag,
                            std::span<const std::uint8_t> &value) noexcept
    {
        value = {};
        if (offset >= bytes.size() || bytes[offset++] != tag ||
            offset >= bytes.size())
        {
            return false;
        }
        const std::uint8_t first = bytes[offset++];
        std::size_t length = 0;
        if ((first & 0x80U) == 0)
        {
            length = first;
        }
        else
        {
            const std::size_t count = first & 0x7fU;
            if (count == 0 || count > 2 || count > bytes.size() - offset ||
                bytes[offset] == 0)
            {
                return false;
            }
            for (std::size_t index = 0; index < count; ++index)
            {
                length = (length << 8U) | bytes[offset++];
            }
            if ((count == 1 && length < 128) ||
                (count == 2 && length < 256))
            {
                return false;
            }
        }
        if (length > bytes.size() - offset)
        {
            return false;
        }
        value = bytes.subspan(offset, length);
        offset += length;
        return true;
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return offset == bytes.size();
    }
};

[[nodiscard]] bool explicitValue(
    std::span<const std::uint8_t> contextValue,
    std::uint8_t expectedTag,
    std::span<const std::uint8_t> &decoded) noexcept
{
    DerCursor field{contextValue};
    return field.read(expectedTag, decoded) && field.empty();
}

[[nodiscard]] bool readUnsignedInteger(
    std::span<const std::uint8_t> bytes,
    std::uint32_t &output) noexcept
{
    // Positive, minimal DER integer; avoid signed rollover and 5-byte
    // leading-zero cases which cannot fit the 32-bit version field.
    if (bytes.empty() || bytes.size() > 5 ||
        (bytes.front() & 0x80U) != 0 ||
        (bytes.size() > 1 && bytes.front() == 0 &&
         (bytes[1] & 0x80U) == 0) ||
        (bytes.size() == 5 && bytes.front() != 0))
    {
        return false;
    }
    std::uint64_t result = 0;
    for (const auto byte : bytes)
    {
        result = (result << 8U) | byte;
    }
    if (result > 0xffffffffULL)
    {
        return false;
    }
    output = static_cast<std::uint32_t>(result);
    return true;
}

// NTSTATUS codes are 32-bit bit patterns, often with the sign bit set.
// Accept their canonical DER signed integer form without treating error
// responses as authenticators or interpreting their semantic meaning.
[[nodiscard]] bool validNtStatusInteger(
    std::span<const std::uint8_t> bytes) noexcept
{
    if (bytes.empty() || bytes.size() > 5 ||
        (bytes.size() == 5 && bytes.front() != 0))
    {
        return false;
    }
    if (bytes.size() > 1 &&
        ((bytes.front() == 0 && (bytes[1] & 0x80U) == 0) ||
         (bytes.front() == 0xff && (bytes[1] & 0x80U) != 0)))
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool parseNegoData(
    std::span<const std::uint8_t> explicitPayload,
    TsRequestInfo &result) noexcept
{
    std::span<const std::uint8_t> sequenceBytes;
    if (!explicitValue(explicitPayload, 0x30, sequenceBytes))
    {
        return false;
    }
    DerCursor sequence{sequenceBytes};
    while (!sequence.empty())
    {
        if (result.tokenCount >= kMaximumCredSspTokens)
        {
            return false;
        }
        std::span<const std::uint8_t> item;
        std::span<const std::uint8_t> wrapper;
        std::span<const std::uint8_t> token;
        if (!sequence.read(0x30, item))
        {
            return false;
        }
        DerCursor itemCursor{item};
        if (!itemCursor.read(0xa0, wrapper) || !itemCursor.empty() ||
            !explicitValue(wrapper, 0x04, token) || token.empty() ||
            token.size() > kMaximumCredSspTokenBytes)
        {
            return false;
        }
        result.tokens[result.tokenCount++] = token;
    }
    return result.tokenCount != 0;
}

[[nodiscard]] TsRequestResult failure(TsRequestError reason) noexcept
{
    return {{}, reason};
}

} // namespace

TsRequestResult parseCredSspTsRequest(
    std::span<const std::uint8_t> der) noexcept
{
    if (der.empty() || der.size() > kMaximumCredSspRequestBytes)
    {
        return failure(TsRequestError::InvalidDer);
    }
    std::span<const std::uint8_t> encodedSequence;
    DerCursor outer{der};
    if (!outer.read(0x30, encodedSequence) || !outer.empty())
    {
        return failure(TsRequestError::InvalidDer);
    }
    DerCursor fields{encodedSequence};
    TsRequestInfo info{};
    std::uint8_t previousTag = 0x9fU;
    while (!fields.empty())
    {
        const auto next = fields.bytes[fields.offset];
        if (next < 0xa0U || next > 0xa5U ||
            (previousTag != 0x9fU && next <= previousTag) ||
            (previousTag == 0x9fU && next != 0xa0U))
        {
            return failure(TsRequestError::InvalidFields);
        }
        previousTag = next;
        std::span<const std::uint8_t> content;
        if (!fields.read(next, content))
        {
            return failure(TsRequestError::InvalidDer);
        }
        std::span<const std::uint8_t> payload;
        switch (next)
        {
            case 0xa0: // [0] EXPLICIT INTEGER version
                if (!explicitValue(content, 0x02, payload) ||
                    !readUnsignedInteger(payload, info.version) ||
                    info.version < 2 || info.version > 6)
                {
                    // Unknown versions fail until the selected security
                    // mechanism explicitly supports their semantics.
                    return failure(TsRequestError::InvalidVersion);
                }
                break;
            case 0xa1: // [1] EXPLICIT NegoData
                if (!parseNegoData(content, info))
                {
                    return failure(TsRequestError::InvalidTokens);
                }
                break;
            case 0xa2: // [2] encrypted and signed authInfo, opaque
            case 0xa3: // [3] encrypted public key binding, opaque
                if (!explicitValue(content, 0x04, payload) || payload.empty())
                {
                    return failure(TsRequestError::InvalidFields);
                }
                if (next == 0xa2)
                {
                    info.hasAuthInfo = true;
                    info.encryptedAuthInfo = payload;
                }
                else
                {
                    info.hasPubKeyAuth = true;
                    info.encryptedPubKeyAuth = payload;
                }
                break;
            case 0xa4: // [4] NTSTATUS errorCode
            {
                if (!explicitValue(content, 0x02, payload) ||
                    !validNtStatusInteger(payload))
                {
                    return failure(TsRequestError::InvalidFields);
                }
                // Never interpret it as authentication or log secrets.
                info.hasErrorCode = true;
                break;
            }
            case 0xa5: // [5] clientNonce for TLS binding, version >= 5
                if (!explicitValue(content, 0x04, payload) ||
                    payload.size() != 32 || info.version < 5)
                {
                    return failure(TsRequestError::InvalidNonce);
                }
                info.hasClientNonce = true;
                info.clientNonce = payload;
                break;
            default:
                return failure(TsRequestError::InvalidFields);
        }
    }
    if (previousTag == 0x9fU)
    {
        return failure(TsRequestError::InvalidFields);
    }
    return {info, TsRequestError::None};
}


namespace
{

// DER uses definite minimal length octets, not BER indefinite lengths.
[[nodiscard]] constexpr std::size_t derLengthOctets(
    std::size_t payloadSize) noexcept
{
    return payloadSize < 128 ? 1 : payloadSize < 256 ? 2 : 3;
}

[[nodiscard]] constexpr std::size_t derFieldSize(
    std::size_t payloadSize) noexcept
{
    return 1 + derLengthOctets(payloadSize) + payloadSize;
}

void appendDerHeader(std::vector<std::uint8_t> &output,
                     std::uint8_t tag,
                     std::size_t payloadSize)
{
    output.push_back(tag);
    if (payloadSize < 128)
    {
        output.push_back(static_cast<std::uint8_t>(payloadSize));
    }
    else if (payloadSize < 256)
    {
        output.push_back(0x81);
        output.push_back(static_cast<std::uint8_t>(payloadSize));
    }
    else
    {
        output.push_back(0x82);
        output.push_back(static_cast<std::uint8_t>(payloadSize >> 8U));
        output.push_back(static_cast<std::uint8_t>(payloadSize));
    }
}

} // namespace

std::vector<std::uint8_t> encodeCredSspServerTsRequest(
    std::uint8_t version,
    CredSspServerReplyField field,
    std::span<const std::uint8_t> opaquePayload) noexcept
{
    // A serializer has no evidence of the authenticated GSS context.
    // Restrict it to one permitted reply field and never encode authInfo.
    if ((version != 5 && version != 6) ||
        (field != CredSspServerReplyField::NegoToken &&
         field != CredSspServerReplyField::EncryptedServerBinding) ||
        opaquePayload.empty() ||
        opaquePayload.size() > kMaximumCredSspTokenBytes)
    {
        return {};
    }

    const std::size_t octetFieldSize = derFieldSize(opaquePayload.size());
    const bool isNegoToken = field == CredSspServerReplyField::NegoToken;
    // negoTokens: [1] SEQUENCE OF SEQUENCE { [0] OCTET STRING }.
    // pubKeyAuth: [3] OCTET STRING. Never mix these two server phases.
    const std::size_t outerFieldContentSize = isNegoToken
        ? derFieldSize(derFieldSize(derFieldSize(octetFieldSize)))
        : octetFieldSize;
    const std::size_t fieldsSize = 5 + derFieldSize(outerFieldContentSize);
    const std::size_t encodedSize = derFieldSize(fieldsSize);
    if (encodedSize > kMaximumCredSspRequestBytes)
    {
        return {};
    }

    try
    {
        std::vector<std::uint8_t> output;
        output.reserve(encodedSize); // One bounded allocation, no reallocations.
        appendDerHeader(output, 0x30, fieldsSize);
        output.insert(output.end(), {0xa0, 0x03, 0x02, 0x01, version});
        appendDerHeader(output, isNegoToken ? 0xa1 : 0xa3,
                        outerFieldContentSize);
        if (isNegoToken)
        {
            const std::size_t itemSize = derFieldSize(derFieldSize(octetFieldSize));
            appendDerHeader(output, 0x30, itemSize);
            appendDerHeader(output, 0x30, derFieldSize(octetFieldSize));
            appendDerHeader(output, 0xa0, octetFieldSize);
        }
        appendDerHeader(output, 0x04, opaquePayload.size());
        output.insert(output.end(), opaquePayload.begin(), opaquePayload.end());
        // Ensure no incomplete or overlong reply can escape this builder.
        if (output.size() != encodedSize)
        {
            return {};
        }
        return output;
    }
    catch (...)
    {
        return {};
    }
}

std::vector<std::uint8_t> encodeCredSspServerFailureTsRequest(
    std::uint8_t version, CredSspServerFailure failure) noexcept
{
    // MS-CSSP 2.2.1: errorCode represents a signed 32-bit NTSTATUS
    // INTEGER. Do not emit a positive/success code, shorten 0xC000...,
    // or include clientNonce, SPNEGO tokens, or any credential field.
    if (version != 6 ||
        (failure != CredSspServerFailure::LogonFailure &&
         failure != CredSspServerFailure::NotSupported))
        return {};

    const std::uint8_t lowByte =
        failure == CredSspServerFailure::LogonFailure ? 0x6d : 0xbb;
    try
    {
        return {0x30, 0x0d, 0xa0, 0x03, 0x02, 0x01, 0x06,
                0xa4, 0x06, 0x02, 0x04, 0xc0, 0x00, 0x00, lowByte};
    }
    catch (...)
    {
        return {};
    }
}

void TsRequestFrameReader::clear() noexcept
{
    if (buffered_ != 0)
    {
        // Even opaque GSS/authInfo tokens may be sensitive: wipe their
        // owned ciphertext before the next exchange or destruction.
        OPENSSL_cleanse(buffer_.data(), buffered_);
    }
    buffered_ = 0;
    expected_ = 0;
}

void TsRequestFrameReader::close() noexcept
{
    clear();
    boundServerTls_ = nullptr;
    OPENSSL_cleanse(pinnedCertificate_.data(), pinnedCertificate_.size());
    certificatePinned_ = false;
    status_ = TsRequestFrameStatus::Closed;
}

TsRequestFrameResult TsRequestFrameReader::reject(
    std::size_t consumed, TsRequestError error) noexcept
{
    close();
    return {consumed, TsRequestFrameStatus::Invalid, error};
}

std::size_t TsRequestFrameReader::bytesNeeded() const noexcept
{
    if (status_ != TsRequestFrameStatus::NeedMore)
        return 0;
    if (expected_ != 0)
        return expected_ - buffered_;
    if (buffered_ < 2)
        return 2 - buffered_;
    const auto lengthByte = buffer_[1];
    const std::size_t header = lengthByte < 128 ? 2 :
                               lengthByte == 0x81 ? 3 : 4;
    return header - buffered_;
}

const SSL *TsRequestFrameReader::completedFrameServerTls() const noexcept
{
    if (status_ != TsRequestFrameStatus::Complete ||
        boundServerTls_ == nullptr || !certificatePinned_)
        return nullptr;
    CredSspTlsCertificateFingerprint current{};
    if (!fingerprintActiveCredSspServerTlsCertificate(
            boundServerTls_, current))
        return nullptr;
    const bool identical = CRYPTO_memcmp(
        current.data(), pinnedCertificate_.data(),
        current.size()) == 0;
    OPENSSL_cleanse(current.data(), current.size());
    return identical ? boundServerTls_ : nullptr;
}

std::span<const std::uint8_t>
TsRequestFrameReader::completeDer() const noexcept
{
    if (status_ != TsRequestFrameStatus::Complete)
        return {};
    return std::span(buffer_).first(buffered_);
}

bool TsRequestFrameReader::releaseFrame() noexcept
{
    if (status_ != TsRequestFrameStatus::Complete)
        return false;
    clear();
    status_ = TsRequestFrameStatus::NeedMore;
    return true;
}

TsRequestFrameResult TsRequestFrameReader::consume(
    std::span<const std::uint8_t> plaintext) noexcept
{
    // Raw plaintext may not be injected into a live TLS-bound reader.
    if (boundServerTls_ != nullptr)
        return reject(0, TsRequestError::InvalidFields);
    return consumePlaintext(plaintext);
}

TsRequestTlsReadResult TsRequestFrameReader::readOneTlsStep(
    SSL *serverTls) noexcept
{
    if (status_ == TsRequestFrameStatus::Closed)
        return {0, TsRequestTlsReadStatus::Closed, TsRequestError::None};

    if (serverTls == nullptr ||
        (boundServerTls_ != nullptr && boundServerTls_ != serverTls) ||
        SSL_is_server(serverTls) != 1 ||
        SSL_is_init_finished(serverTls) != 1 ||
        SSL_version(serverTls) < TLS1_2_VERSION ||
        SSL_get_current_cipher(serverTls) == nullptr ||
        SSL_get_certificate(serverTls) == nullptr)
    {
        close();
        return {0, TsRequestTlsReadStatus::Invalid,
                TsRequestError::InvalidFields};
    }
    if (status_ == TsRequestFrameStatus::Complete)
    {
        // A manually supplied Complete frame must never acquire TLS
        // provenance after the fact. No second TLS read before release.
        if (completedFrameServerTls() == nullptr)
        {
            close();
            return {0, TsRequestTlsReadStatus::Invalid,
                    TsRequestError::InvalidFields};
        }
        return {0, TsRequestTlsReadStatus::Complete, TsRequestError::None};
    }

    // A partial frame injected through the direct plaintext parser cannot
    // later acquire TLS provenance. TLS ownership starts with an empty frame.
    if (boundServerTls_ == nullptr && buffered_ != 0)
    {
        close();
        return {0, TsRequestTlsReadStatus::Invalid,
                TsRequestError::InvalidFields};
    }
    // An unchanged SSL* is NOT sufficient: the same object could have a
    // different selected certificate after renegotiation/reconfiguration.
    // Check it even for Complete frames and WANT retries before touching
    // any further untrusted TLS plaintext.
    CredSspTlsCertificateFingerprint current{};
    if (!fingerprintActiveCredSspServerTlsCertificate(serverTls, current) ||
        (certificatePinned_ &&
         CRYPTO_memcmp(current.data(), pinnedCertificate_.data(),
                       current.size()) != 0))
    {
        OPENSSL_cleanse(current.data(), current.size());
        close();
        return {0, TsRequestTlsReadStatus::Invalid,
                TsRequestError::InvalidFields};
    }
    if (!certificatePinned_)
    {
        pinnedCertificate_ = current;
        certificatePinned_ = true;
    }
    OPENSSL_cleanse(current.data(), current.size());
    boundServerTls_ = serverTls;
    std::array<std::uint8_t, 512> plaintext{};
    const std::size_t length =
        (std::min)(plaintext.size(), bytesNeeded());
    if (length == 0)
    {
        close();
        return {0, TsRequestTlsReadStatus::Invalid,
                TsRequestError::InvalidFields};
    }

    std::size_t obtained = 0;
    const int ok = SSL_read_ex(serverTls, plaintext.data(), length, &obtained);
    if (ok != 1)
    {
        // Consult OpenSSL immediately, without disturbing the error queue.
        const int error = SSL_get_error(serverTls, ok);
        if (error == SSL_ERROR_WANT_READ)
            return {0, TsRequestTlsReadStatus::NeedRead,
                    TsRequestError::None};
        if (error == SSL_ERROR_WANT_WRITE)
            return {0, TsRequestTlsReadStatus::NeedWrite,
                    TsRequestError::None};
        // close_notify, truncated TLS, alerts and fatal provider failures.
        close();
        return {0, TsRequestTlsReadStatus::Invalid,
                TsRequestError::InvalidFields};
    }
    if (obtained == 0 || obtained > length)
    {
        close();
        return {0, TsRequestTlsReadStatus::Invalid,
                TsRequestError::InvalidFields};
    }

    // SSL can internally buffer a coalesced record. The request passed to
    // SSL_read_ex is exactly the next required DER prefix/body size so the
    // following TSRequest remains unread until releaseFrame().
    const auto framed = consumePlaintext(
        std::span(plaintext).first(obtained));
    OPENSSL_cleanse(plaintext.data(), obtained);
    if (framed.bytesConsumed != obtained ||
        framed.status == TsRequestFrameStatus::Invalid)
    {
        return {obtained, TsRequestTlsReadStatus::Invalid, framed.error};
    }
    return {obtained,
            framed.status == TsRequestFrameStatus::Complete
                ? TsRequestTlsReadStatus::Complete
                : TsRequestTlsReadStatus::Progress,
            TsRequestError::None};
}

TsRequestFrameResult TsRequestFrameReader::consumePlaintext(
    std::span<const std::uint8_t> plaintext) noexcept
{
    if (status_ == TsRequestFrameStatus::Closed)
        return {0, TsRequestFrameStatus::Closed, TsRequestError::None};
    if (status_ != TsRequestFrameStatus::NeedMore)
        return reject(0, TsRequestError::InvalidFields);

    std::size_t consumed = 0;
    for (;;)
    {
        if (expected_ == 0 && buffered_ >= 2)
        {
            if (buffer_[0] != 0x30)
                return reject(consumed, TsRequestError::InvalidDer);
            const std::uint8_t first = buffer_[1];
            // 0x80 is indefinite BER (forbidden in DER); 0x83..ff
            // are unsupported/noncanonical or fragmented lengths.
            if (first >= 0x80 && first != 0x81 && first != 0x82)
                return reject(consumed, TsRequestError::InvalidDer);
            const std::size_t header = first < 128 ? 2 :
                                       first == 0x81 ? 3 : 4;
            if (buffered_ == header)
            {
                std::size_t payload = 0;
                if (first < 128)
                    payload = first;
                else if (first == 0x81)
                {
                    payload = buffer_[2];
                    if (payload < 128)
                        return reject(consumed, TsRequestError::InvalidDer);
                }
                else
                {
                    payload = (static_cast<std::size_t>(buffer_[2]) << 8U) |
                              buffer_[3];
                    if (buffer_[2] == 0 || payload < 256)
                        return reject(consumed, TsRequestError::InvalidDer);
                }
                if (payload > buffer_.size() - header)
                    return reject(consumed, TsRequestError::InvalidDer);
                expected_ = payload + header;
            }
        }

        if (expected_ != 0 && buffered_ == expected_)
        {
            const auto parsed = parseCredSspTsRequest(
                std::span(buffer_).first(buffered_));
            if (!parsed)
                return reject(consumed, parsed.error);
            status_ = TsRequestFrameStatus::Complete;
            return {consumed, TsRequestFrameStatus::Complete,
                    TsRequestError::None};
        }

        // Validate the FIRST DER tag byte even when this event ends
        // immediately after it. Never wait for a second peer byte to
        // reject a non-SEQUENCE prefix or retain it across callbacks.
        if (buffered_ == 1 && buffer_[0] != 0x30)
            return reject(consumed, TsRequestError::InvalidDer);

        if (consumed == plaintext.size())
            return {consumed, TsRequestFrameStatus::NeedMore,
                    TsRequestError::None};

        const auto count = (std::min)(bytesNeeded(),
                                      plaintext.size() - consumed);
        if (count == 0 || count > buffer_.size() - buffered_)
            return reject(consumed, TsRequestError::InvalidDer);
        std::copy_n(plaintext.data() + consumed, count,
                    buffer_.data() + buffered_);
        buffered_ += count;
        consumed += count;
    }
}


bool TsRequestTlsReplyWriter::matchesPinnedCertificate(
    const SSL *serverTls,
    CredSspTlsCertificateFingerprint &current) const noexcept
{
    if (!fingerprintActiveCredSspServerTlsCertificate(serverTls, current))
        return false;
    return !certificatePinned_ ||
           CRYPTO_memcmp(current.data(), pinnedCertificate_.data(),
                         current.size()) == 0;
}

void TsRequestTlsReplyWriter::clear() noexcept
{
    if (!frame_.empty())
        OPENSSL_cleanse(frame_.data(), frame_.size());
    frame_.clear();
    offset_ = 0;
}

void TsRequestTlsReplyWriter::close() noexcept
{
    clear();
    boundServerTls_ = nullptr;
    OPENSSL_cleanse(pinnedCertificate_.data(), pinnedCertificate_.size());
    certificatePinned_ = false;
    failureQueued_ = false;
    status_ = TsRequestTlsWriteStatus::Closed;
}

bool TsRequestTlsReplyWriter::queueReply(
    SSL *serverTls, std::uint8_t version, CredSspServerReplyField field,
    std::span<const std::uint8_t> providerOutput) noexcept
{
    return queueEncoded(
        serverTls, encodeCredSspServerTsRequest(version, field, providerOutput),
        false);
}

bool TsRequestTlsReplyWriter::queueFailureReply(
    SSL *serverTls, std::uint8_t version,
    CredSspServerFailure failure) noexcept
{
    return queueEncoded(
        serverTls, encodeCredSspServerFailureTsRequest(version, failure),
        true);
}

bool TsRequestTlsReplyWriter::queueEncoded(
    SSL *serverTls, std::vector<std::uint8_t> encoded,
    bool isFailure) noexcept
{
    // This method is PRIVATE: callers cannot inject arbitrary DER.
    // Both canonical serializers share the single TLS identity and
    // pending-reply owner. Erase even discarded encoded GSS tokens.
    auto discard = [&encoded]() noexcept {
        if (!encoded.empty())
            OPENSSL_cleanse(encoded.data(), encoded.size());
    };
    if (status_ == TsRequestTlsWriteStatus::Closed)
    {
        discard();
        return false;
    }
    if (status_ != TsRequestTlsWriteStatus::Idle ||
        (boundServerTls_ != nullptr && boundServerTls_ != serverTls))
    {
        discard();
        close();
        return false;
    }

    CredSspTlsCertificateFingerprint current{};
    const bool validCertificate =
        matchesPinnedCertificate(serverTls, current);
    if (!validCertificate || encoded.empty() ||
        encoded.size() > kMaximumCredSspRequestBytes)
    {
        discard();
        OPENSSL_cleanse(current.data(), current.size());
        close();
        return false;
    }
    frame_.swap(encoded); // Stable OpenSSL retry pointer, no extra copy.
    offset_ = 0;
    boundServerTls_ = serverTls;
    failureQueued_ = isFailure;
    if (!certificatePinned_)
    {
        pinnedCertificate_ = current;
        certificatePinned_ = true;
    }
    OPENSSL_cleanse(current.data(), current.size());
    status_ = TsRequestTlsWriteStatus::NeedWrite;
    return true;
}

TsRequestTlsWriteResult TsRequestTlsReplyWriter::writeOneTlsStep(
    SSL *serverTls) noexcept
{
    if (status_ == TsRequestTlsWriteStatus::Closed)
        return {0, TsRequestTlsWriteStatus::Closed};
    if (status_ == TsRequestTlsWriteStatus::Idle)
        return {0, TsRequestTlsWriteStatus::Idle};
    // Recheck the selected TLS certificate even after Complete; do not
    // report idempotent completion for another selected certificate.
    CredSspTlsCertificateFingerprint current{};
    const bool sameCertificate =
        boundServerTls_ == serverTls && certificatePinned_ &&
        matchesPinnedCertificate(serverTls, current);
    OPENSSL_cleanse(current.data(), current.size());
    if (!sameCertificate)
    {
        close();
        return {0, TsRequestTlsWriteStatus::Invalid};
    }
    if (status_ == TsRequestTlsWriteStatus::Complete)
        return {0, TsRequestTlsWriteStatus::Complete};

    const auto remaining = frame_.size() - offset_;
    if (remaining == 0)
    {
        close();
        return {0, TsRequestTlsWriteStatus::Invalid};
    }
    std::size_t written = 0;
    const int ok = SSL_write_ex(serverTls, frame_.data() + offset_,
                                remaining, &written);
    if (ok != 1)
    {
        // OpenSSL's nonblocking retry MUST use the same buffer and size
        // on WANT_READ/WANT_WRITE: never advance offsets in those cases.
        const int error = SSL_get_error(serverTls, ok);
        if (error == SSL_ERROR_WANT_READ)
        {
            status_ = TsRequestTlsWriteStatus::NeedRead;
            return {0, status_};
        }
        if (error == SSL_ERROR_WANT_WRITE)
        {
            status_ = TsRequestTlsWriteStatus::NeedWrite;
            return {0, status_};
        }
        close();
        return {0, TsRequestTlsWriteStatus::Invalid};
    }
    if (written == 0 || written > remaining)
    {
        close();
        return {0, TsRequestTlsWriteStatus::Invalid};
    }
    offset_ += written;
    status_ = offset_ == frame_.size()
                  ? TsRequestTlsWriteStatus::Complete
                  : TsRequestTlsWriteStatus::Progress;
    return {written, status_};
}

bool TsRequestTlsReplyWriter::releaseReply() noexcept
{
    if (status_ != TsRequestTlsWriteStatus::Complete)
        return false;
    CredSspTlsCertificateFingerprint current{};
    const bool sameCertificate =
        certificatePinned_ &&
        matchesPinnedCertificate(boundServerTls_, current);
    OPENSSL_cleanse(current.data(), current.size());
    if (!sameCertificate)
    {
        close();
        return false;
    }
    if (failureQueued_)
    {
        // MS-CSSP: a client receiving errorCode MUST terminate.
        // A local writer must also refuse any success reply after error.
        close();
        return true;
    }
    clear();
    // Keep the original SSL and certificate fingerprint across the next
    // provider response; a new certificate requires a NEW writer/handshake.
    status_ = TsRequestTlsWriteStatus::Idle;
    return true;
}

} // namespace rdp_server::server::security
