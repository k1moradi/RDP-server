// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "mcs_connect_initial.h"
#include "security_negotiation.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace rdp_server::server::transport
{

// Candidate-only upper limit for the first *decrypted* MCS TPKT, before
// domain/channel allocation. Larger input fails closed before being buffered.
inline constexpr std::size_t kMaximumInitialMcsTpktBytes = 8192;

enum class PreauthStage : std::uint8_t
{
    AwaitConnectionRequest,
    AwaitTls,
    AwaitMcsConnectInitial,
    Closed,
};

// A transport diagnostic, NOT a session authorizer. No method here may
// approve a user, construct a domain, select a desktop or send MCS responses.
// The object stores neither sensitive identifiers nor borrowed packet views.
class PreauthSession final
{
public:
    [[nodiscard]] PreauthStage stage() const noexcept { return stage_; }

    [[nodiscard]] SecurityReply onConnectionRequest(
        const ConnectionParseResult &request) noexcept;

    [[nodiscard]] bool onTlsHandshake(bool completed) noexcept;

    // Successful decoding consumes one envelope but ALWAYS closes the
    // diagnostic; authentication and MCS Connect-Response do not exist yet.
    [[nodiscard]] bool onEncryptedMcsConnectInitial(
        std::span<const std::uint8_t> packet) noexcept;

    void close() noexcept { stage_ = PreauthStage::Closed; }

private:
    PreauthStage stage_{PreauthStage::AwaitConnectionRequest};
};

} // namespace rdp_server::server::transport
