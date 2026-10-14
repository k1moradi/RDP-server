// SPDX-License-Identifier: GPL-3.0-or-later
#include "preauth_session.h"
#include "gcc_conference_create.h"

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
    if (!parsed)
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
    session_.close();
}

bool PreauthConnectionStream::onConnectionReplySent(bool completed) noexcept
{
    if (stage() != PreauthStage::AwaitTls ||
        connectionReplySent_ || !completed)
    {
        close();
        return false;
    }
    connectionReplySent_ = true;
    return true;
}

bool PreauthConnectionStream::onTlsHandshake(const SSL *serverTls) noexcept
{
    if (stage() != PreauthStage::AwaitTls || !connectionReplySent_)
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
    if (!established)
    {
        close();
        return false;
    }
    if (!session_.onTlsHandshake(true))
    {
        close();
        return false;
    }
    return true;
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
        const std::size_t copyLength = std::min(remaining, needed);
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
            std::min(available, targetBytes - bufferedBytes_);
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

} // namespace rdp_server::server::transport
