// SPDX-License-Identifier: GPL-3.0-or-later
#include "preauth_session.h"
#include "gcc_conference_create.h"
#include "security/credssp_tls_certificate.h"

#include <openssl/ssl.h>
#include <openssl/crypto.h>

#include <algorithm>

namespace rdp_server::server::transport
{

SecurityReply PreauthSession::onConnectionRequest(
    const ConnectionParseResult &request) noexcept
{
    if (stage_ != PreauthStage::AwaitConnectionRequest)
    {
        stage_ = PreauthStage::Closed;
        return negotiateDiagnosticTls({});
    }
    const auto reply = negotiateDiagnosticTls(request);
    stage_ = reply.decision == SecurityDecision::Tls
                 ? PreauthStage::AwaitTls
                 : PreauthStage::Closed;
    return reply;
}

bool PreauthSession::onTlsHandshake(bool completed) noexcept
{
    if (stage_ != PreauthStage::AwaitTls || !completed)
    {
        stage_ = PreauthStage::Closed;
        return false;
    }
    stage_ = PreauthStage::AwaitMcsConnectInitial;
    return true;
}

bool PreauthSession::onEncryptedMcsConnectInitial(
    std::span<const std::uint8_t> packet) noexcept
{
    const bool awaiting = stage_ == PreauthStage::AwaitMcsConnectInitial;
    stage_ = PreauthStage::Closed;

    if (!awaiting || packet.size() < 8 ||
        packet.size() > kMaximumInitialMcsTpktBytes)
    {
        return false;
    }
    const auto parsed = parseMcsConnectInitial(packet);
    if (!parsed || !mergeMcsDomainParameters(parsed.value))
    {
        return false;
    }
    // The GCC user data view is borrowed only during this call.
    // Static channel names and flags are checked but NEVER registered.
    const auto gcc = parseGccConferenceCreate(parsed.value.gccUserData);
    return static_cast<bool>(gcc);
}


void PreauthConnectionStream::clearIntakeBuffer() noexcept
{
    // The unauthenticated request may contain routing identifiers/cookies.
    // Clear the fixed buffer after completing or abandoning the request.
    // Only the occupied prefix can contain peer-controlled bytes.
    std::fill(intakeBuffer_.begin(), intakeBuffer_.begin() + bufferedBytes_, 0);
    bufferedBytes_ = 0;
    expectedBytes_ = 0;
}

void PreauthConnectionStream::close() noexcept
{
    clearIntakeBuffer();
    connectionReplySent_ = false;
    pendingReply_ = {};
    replyBytesWritten_ = 0;
    replyPending_ = false;
    activeServerTls_ = nullptr;
    handshakingServerTls_ = nullptr;
    // Keep the pin strictly scoped to this connection diagnostic.
    OPENSSL_cleanse(selectedTlsCertificateFingerprint_.data(),
                    selectedTlsCertificateFingerprint_.size());
    selectedTlsCertificatePinned_ = false;
    session_.close();
}

std::span<const std::uint8_t>
PreauthConnectionStream::pendingConnectionReply() const noexcept
{
    if (!replyPending_)
    {
        return {};
    }
    return std::span(pendingReply_.packet).subspan(replyBytesWritten_);
}

ConnectionReplyWriteStatus
PreauthConnectionStream::onConnectionReplyBytesWritten(
    std::size_t bytesWritten) noexcept
{
    if (!replyPending_)
    {
        const auto result = stage() == PreauthStage::Closed
                                ? ConnectionReplyWriteStatus::Closed
                                : ConnectionReplyWriteStatus::Invalid;
        close();
        return result;
    }
    const std::size_t remaining =
        pendingReply_.packet.size() - replyBytesWritten_;
    if (bytesWritten > remaining)
    {
        close();
        return ConnectionReplyWriteStatus::Invalid;
    }
    if (bytesWritten == 0)
    {
        return ConnectionReplyWriteStatus::NeedMore;
    }
    replyBytesWritten_ += bytesWritten;
    if (replyBytesWritten_ != pendingReply_.packet.size())
    {
        return ConnectionReplyWriteStatus::NeedMore;
    }

    replyPending_ = false;
    replyBytesWritten_ = 0;
    const auto decision = pendingReply_.decision;
    pendingReply_ = {};
    if (decision == SecurityDecision::Tls &&
        stage() == PreauthStage::AwaitTls)
    {
        connectionReplySent_ = true;
        return ConnectionReplyWriteStatus::ReplySentStartTls;
    }
    // MS-RDPBCGR 3.3.5.3.2: NEG_FAILURE must be sent before close.
    close();
    return decision == SecurityDecision::Reject
               ? ConnectionReplyWriteStatus::ReplySentClose
               : ConnectionReplyWriteStatus::Invalid;
}

bool PreauthConnectionStream::onTlsHandshake(const SSL *serverTls) noexcept
{
    if (stage() != PreauthStage::AwaitTls || !connectionReplySent_ ||
        (handshakingServerTls_ != nullptr &&
         handshakingServerTls_ != serverTls))
    {
        close();
        return false;
    }
    connectionReplySent_ = false;

    // MS-RDPBCGR 5.4: PROTOCOL_SSL delegates TLS to the security provider.
    // Do not accept an SSL object that is merely configured/started, or
    // one from the peer/client role. This is a transport phase check,
    // NOT certificate-chain trust or user/desktop authorization.
    const bool established =
        serverTls != nullptr &&
        SSL_is_server(serverTls) == 1 &&
        SSL_is_init_finished(serverTls) == 1 &&
        SSL_version(serverTls) >= TLS1_2_VERSION &&
        SSL_get_current_cipher(serverTls) != nullptr &&
        SSL_get_certificate(serverTls) != nullptr;
    // Reuse the CredSSP-selected-certificate SHA-256 primitive rather
    // than treating the (possibly reconfigured) SSL* as identity.
    // No OS/GSS admission is derived from the certificate fingerprint.
    security::CredSspTlsCertificateFingerprint selectedCertificate{};
    if (!established ||
        !security::fingerprintActiveCredSspServerTlsCertificate(
            serverTls, selectedCertificate))
    {
        close();
        return false;
    }
    if (!session_.onTlsHandshake(true))
    {
        close();
        return false;
    }
    activeServerTls_ = serverTls;
    handshakingServerTls_ = nullptr;
    selectedTlsCertificateFingerprint_ = selectedCertificate;
    selectedTlsCertificatePinned_ = true;
    return true;
}

TlsHandshakeStatus PreauthConnectionStream::advanceTlsHandshake(
    SSL *serverTls) noexcept
{
    if (stage() == PreauthStage::Closed)
    {
        return TlsHandshakeStatus::Closed;
    }
    if (stage() != PreauthStage::AwaitTls ||
        !connectionReplySent_ || serverTls == nullptr ||
        SSL_is_server(serverTls) != 1 ||
        (handshakingServerTls_ != nullptr &&
         handshakingServerTls_ != serverTls))
    {
        close();
        return TlsHandshakeStatus::Invalid;
    }

    // One provider operation per event-loop callback. Do not read raw
    // socket bytes here or spin on a nonblocking WANT_READ/WANT_WRITE.
    handshakingServerTls_ = serverTls;
    const int completed = SSL_do_handshake(serverTls);
    if (completed != 1)
    {
        // SSL_get_error must be called immediately, without touching the
        // thread's OpenSSL error queue after SSL_do_handshake.
        const int error = SSL_get_error(serverTls, completed);
        if (error == SSL_ERROR_WANT_READ)
        {
            return TlsHandshakeStatus::NeedRead;
        }
        if (error == SSL_ERROR_WANT_WRITE)
        {
            return TlsHandshakeStatus::NeedWrite;
        }
        close(); // TLS alerts/EOF/provider errors never authorize MCS.
        return TlsHandshakeStatus::Invalid;
    }

    // Reuse the existing server-role, cipher, TLS-version and certificate
    // gate; only the same completed SSL can become the MCS record source.
    return onTlsHandshake(serverTls)
               ? TlsHandshakeStatus::Established
               : TlsHandshakeStatus::Invalid;
}

std::size_t PreauthConnectionStream::connectionRequestBytesNeeded()
    const noexcept
{
    if (stage() != PreauthStage::AwaitConnectionRequest)
    {
        return 0;
    }
    return bufferedBytes_ < 4 ? 4 - bufferedBytes_ :
           expectedBytes_ - bufferedBytes_;
}

ConnectionIntakeResult PreauthConnectionStream::consumeConnectionRequest(
    std::span<const std::uint8_t> receivedBytes) noexcept
{
    if (stage() != PreauthStage::AwaitConnectionRequest)
    {
        return {0, ConnectionIntakeStatus::Closed, {}};
    }

    std::size_t bytesConsumed = 0;
    // TCP has no packet boundaries. Read only the bytes required for the
    // four-byte TPKT header, then for the validated complete X.224 CR.
    const auto consumeUntil = [&](std::size_t targetBytes)
    {
        const std::size_t remaining = receivedBytes.size() - bytesConsumed;
        const std::size_t needed = targetBytes - bufferedBytes_;
        const std::size_t copyLength = (std::min)(remaining, needed);
        const auto nextBytes = receivedBytes.subspan(bytesConsumed, copyLength);
        std::copy(nextBytes.begin(), nextBytes.end(),
                  intakeBuffer_.begin() + bufferedBytes_);
        bufferedBytes_ += copyLength;
        bytesConsumed += copyLength;
    };

    if (bufferedBytes_ < 4)
    {
        consumeUntil(4);
        if (bufferedBytes_ < 4)
        {
            return {bytesConsumed, ConnectionIntakeStatus::NeedMore, {}};
        }

        // Validated before buffering the rest: no peer-controlled
        // 16-bit TPKT length can allocate an unbounded receive buffer.
        const auto expected = connectionRequestLength(
            std::span(intakeBuffer_).first(4));
        if (!expected)
        {
            close();
            return {bytesConsumed, ConnectionIntakeStatus::Invalid, {}};
        }
        expectedBytes_ = *expected;
    }

    consumeUntil(expectedBytes_);
    if (bufferedBytes_ != expectedBytes_)
    {
        return {bytesConsumed, ConnectionIntakeStatus::NeedMore, {}};
    }

    const auto parsed = parseConnectionRequest(
        std::span(intakeBuffer_).first(expectedBytes_));
    if (!parsed)
    {
        // Malformed protocol traffic is dropped, not negotiated.
        close();
        return {bytesConsumed, ConnectionIntakeStatus::Invalid, {}};
    }

    const auto reply = session_.onConnectionRequest(parsed);
    clearIntakeBuffer();
    pendingReply_ = reply;
    replyBytesWritten_ = 0;
    replyPending_ = true;
    if (reply.decision != SecurityDecision::Tls)
    {
        // Send the existing standards-defined negotiation failure
        // before closing the underlying socket.
        return {bytesConsumed, ConnectionIntakeStatus::ReplyThenClose, reply};
    }
    // Remaining bytes in this receive belong to TLS; do not consume them
    // as plaintext TPKT or make a session admission decision.
    return {bytesConsumed, ConnectionIntakeStatus::ReplyThenTls, reply};
}

McsIntakeResult PreauthConnectionStream::consumeDecryptedMcsConnectInitial(
    std::span<const std::uint8_t> decryptedBytes) noexcept
{
    if (stage() == PreauthStage::Closed)
    {
        return {0, McsIntakeStatus::Closed};
    }
    if (stage() != PreauthStage::AwaitMcsConnectInitial)
    {
        // Decrypted MCS bytes must never arrive during X.224 or TLS setup.
        close();
        return {0, McsIntakeStatus::Invalid};
    }

    std::size_t bytesConsumed = 0;
    const auto consumeUntil = [&](std::size_t targetBytes)
    {
        const std::size_t available = decryptedBytes.size() - bytesConsumed;
        const std::size_t toCopy =
            (std::min)(available, targetBytes - bufferedBytes_);
        const auto chunk = decryptedBytes.subspan(bytesConsumed, toCopy);
        std::copy(chunk.begin(), chunk.end(),
                  intakeBuffer_.begin() + bufferedBytes_);
        bufferedBytes_ += toCopy;
        bytesConsumed += toCopy;
    };

    if (bufferedBytes_ < 4)
    {
        consumeUntil(4);
        if (bufferedBytes_ < 4)
        {
            return {bytesConsumed, McsIntakeStatus::NeedMore};
        }
        // TPKT is big-endian; validate the declared length BEFORE buffering
        // the rest, even if the TLS provider returns thousands of bytes.
        const std::size_t length =
            (static_cast<std::size_t>(intakeBuffer_[2]) << 8U) |
            intakeBuffer_[3];
        if (intakeBuffer_[0] != 3 || intakeBuffer_[1] != 0 ||
            length < 8 || length > kMaximumInitialMcsTpktBytes)
        {
            close();
            return {bytesConsumed, McsIntakeStatus::Invalid};
        }
        expectedBytes_ = length;
    }

    // Validate the three-byte X.224 Data TPDU before copying the MCS BER.
    if (bufferedBytes_ < 7)
    {
        consumeUntil(7);
        if (bufferedBytes_ < 7)
        {
            return {bytesConsumed, McsIntakeStatus::NeedMore};
        }
        if (intakeBuffer_[4] != 2 || intakeBuffer_[5] != 0xf0 ||
            intakeBuffer_[6] != 0x80)
        {
            close();
            return {bytesConsumed, McsIntakeStatus::Invalid};
        }
    }

    consumeUntil(expectedBytes_);
    if (bufferedBytes_ < expectedBytes_)
    {
        return {bytesConsumed, McsIntakeStatus::NeedMore};
    }

    // The existing MCS/GCC validators borrow input only during this call.
    // This diagnostic NEVER emits an MCS response or admits a session.
    const bool valid = session_.onEncryptedMcsConnectInitial(
        std::span(intakeBuffer_).first(expectedBytes_));
    close();
    return {bytesConsumed, valid ? McsIntakeStatus::EnvelopeValidated
                                 : McsIntakeStatus::Invalid};
}

McsIntakeResult PreauthConnectionStream::consumeMcsConnectInitialFromTls(
    SSL *serverTls) noexcept
{
    if (stage() == PreauthStage::Closed)
    {
        return {0, McsIntakeStatus::Closed};
    }
    // A completed TLS handshake on some OTHER SSL object is not evidence
    // for this connection. The caller owns the active nonblocking SSL/BIO.
    if (stage() != PreauthStage::AwaitMcsConnectInitial ||
        serverTls == nullptr || serverTls != activeServerTls_)
    {
        close();
        return {0, McsIntakeStatus::Invalid};
    }

    // An unchanged SSL pointer is NOT enough: the locally selected
    // certificate can be replaced after handshake completion, including
    // between TLS readiness events with partially buffered MCS data.
    // Reject before consuming any more plaintext from that SSL object.
    security::CredSspTlsCertificateFingerprint currentCertificate{};
    if (!selectedTlsCertificatePinned_ ||
        !security::fingerprintActiveCredSspServerTlsCertificate(
            serverTls, currentCertificate) ||
        CRYPTO_memcmp(currentCertificate.data(),
                      selectedTlsCertificateFingerprint_.data(),
                      currentCertificate.size()) != 0)
    {
        close();
        return {0, McsIntakeStatus::Invalid};
    }

    // Read no further than the NEXT validated TPKT boundary. OpenSSL may
    // decrypt an entire TLS record internally, but subsequent RDP PDUs
    // must remain unread in that SSL instance.
    std::array<std::uint8_t, 512> plaintext{};
    std::size_t consumed = 0;
    while (stage() == PreauthStage::AwaitMcsConnectInitial &&
           consumed < kMaximumInitialMcsTpktBytes)
    {
        const std::size_t target =
            bufferedBytes_ < 4 ? 4 :
            bufferedBytes_ < 7 ? 7 : expectedBytes_;
        const std::size_t toRead = (std::min)(
            plaintext.size(), target - bufferedBytes_);
        if (toRead == 0)
        {
            close();
            return {consumed, McsIntakeStatus::Invalid};
        }

        std::size_t obtained = 0;
        const int ok = SSL_read_ex(serverTls, plaintext.data(), toRead,
                                   &obtained);
        if (ok != 1)
        {
            // SSL_get_error must immediately follow the failed call, on
            // the same thread and with OpenSSL's error queue untouched.
            const int error = SSL_get_error(serverTls, ok);
            if (error == SSL_ERROR_WANT_READ ||
                error == SSL_ERROR_WANT_WRITE)
            {
                return {consumed, McsIntakeStatus::NeedMore};
            }
            // close_notify before the full envelope, an unclean EOF,
            // TLS authentication failure or a provider error: fail closed.
            close();
            return {consumed, McsIntakeStatus::Invalid};
        }
        if (obtained == 0 || obtained > toRead)
        {
            close();
            return {consumed, McsIntakeStatus::Invalid};
        }
        const auto intake = consumeDecryptedMcsConnectInitial(
            std::span(plaintext).first(obtained));
        consumed += intake.bytesConsumed;
        if (intake.bytesConsumed != obtained ||
            intake.status != McsIntakeStatus::NeedMore)
        {
            return {consumed, intake.status};
        }
    }
    close(); // No unbounded looping on malformed encrypted input.
    return {consumed, McsIntakeStatus::Invalid};
}

} // namespace rdp_server::server::transport
