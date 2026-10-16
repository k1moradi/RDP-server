// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "transport/rdp_licensing.h"

#include <cstdint>
#include <span>

namespace rdp_server::server::runtime
{

// Service-lifetime R10 ownership for the already-reviewed R3 licensing
// identity + private-key credential pair. This object does not read paths,
// authorize a user, create a session, bind a listener, or make a licensing
// decision. Callers must provision the input bytes through an independently
// secure configuration/file boundary before configure().
//
// Configuration is one-shot. On success both R3 objects own their required
// snapshots, so caller buffers may be released or overwritten immediately.
// The private-key snapshot is cleansed by RdpLicensingServiceCredential on
// destruction and is never exposed through this wrapper.
class RuntimeLicensingContext final
{
public:
    RuntimeLicensingContext() noexcept = default;

    RuntimeLicensingContext(const RuntimeLicensingContext &) = delete;
    RuntimeLicensingContext &operator=(const RuntimeLicensingContext &) = delete;
    RuntimeLicensingContext(RuntimeLicensingContext &&) = delete;
    RuntimeLicensingContext &operator=(RuntimeLicensingContext &&) = delete;

    [[nodiscard]] bool configure(
        std::uint32_t productVersion,
        std::span<const std::uint8_t> companyNameUtf16,
        std::span<const std::uint8_t> productIdUtf16,
        std::span<const std::uint8_t> serverCertificate,
        std::span<const std::uint8_t> scopeAnsi,
        std::span<const std::uint8_t> privateKeyPem) noexcept;

    [[nodiscard]] bool configured() const noexcept { return configured_; }

    [[nodiscard]]
    const rdp_server::server::transport::RdpServerLicenseIdentity *
    identity() const noexcept
    {
        return configured_ ? &identity_ : nullptr;
    }

    [[nodiscard]]
    const rdp_server::server::transport::RdpLicensingServiceCredential *
    credential() const noexcept
    {
        return configured_ ? &credential_ : nullptr;
    }

private:
    rdp_server::server::transport::RdpServerLicenseIdentity identity_{};
    rdp_server::server::transport::RdpLicensingServiceCredential credential_{};
    bool attempted_{};
    bool configured_{};
};

} // namespace rdp_server::server::runtime
