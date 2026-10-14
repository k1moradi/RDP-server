// SPDX-License-Identifier: GPL-3.0-or-later
#include "preauth_session.h"
#include "gcc_conference_create.h"

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

} // namespace rdp_server::server::transport
