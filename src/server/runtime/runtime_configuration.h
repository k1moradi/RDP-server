// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <string_view>

namespace rdp_server::server::runtime
{

class RuntimeLicensingContext;

enum class RuntimeConfigurationField : std::size_t
{
    ListenAddress,
    ListenPort,
    TlsCertificate,
    TlsPrivateKey,
    Authentication,
    OsAuthorization,
    MaxConnections,
    LicensingCertificate,
    LicensingPrivateKey,
    LicensingProductVersion,
    LicensingCompanyName,
    LicensingProductId,
    LicensingScope,
    GssServicePrincipal,
    GssKeytab,
    AuthorizedKerberosPrincipal,
    AuthorizedUnixAccount,
    AuthorizedSeat,
    AuthorizedDisplay,
    AuthorizedUid,
    AuthorizedPermissions,
    PamService,
    Count,
};

inline constexpr std::size_t kRuntimeConfigurationFieldCount =
    static_cast<std::size_t>(RuntimeConfigurationField::Count);

struct RuntimeConfigurationCapabilities final
{
    bool linuxSecurity{};
    bool linuxPam{};
};

// Borrowed only for the duration of a configuration visitor callback. The
// secure file reader owns the backing bytes and destroys them when the callback
// returns; callers must snapshot any state they need through existing owners.
class RuntimeConfigurationView final
{
public:
    using Fields =
        std::array<std::string_view, kRuntimeConfigurationFieldCount>;

    // Construction is internal plumbing for the parser; the view itself is
    // still non-owning and must not escape the visitor callback.
    explicit RuntimeConfigurationView(const Fields& fields) noexcept
        : fields_(&fields)
    {
    }

    [[nodiscard]] std::string_view field(
        RuntimeConfigurationField fieldId) const noexcept
    {
        return (*fields_)[static_cast<std::size_t>(fieldId)];
    }

private:
    const Fields* fields_{};
};

using RuntimeConfigurationVisitor =
    bool (*)(const RuntimeConfigurationView&, void*) noexcept;

[[nodiscard]] bool parseRuntimeConfigurationDecimal(
    std::string_view value,
    unsigned minimum,
    unsigned maximum,
    unsigned& parsedValue) noexcept;

// Syntax-only visitor for deterministic tests and callers which already own
// the source bytes. The view must not escape visitor().
[[nodiscard]] bool visitRuntimeConfigurationText(
    std::string_view text,
    RuntimeConfigurationCapabilities capabilities,
    RuntimeConfigurationVisitor visitor,
    void* context) noexcept;

// Secure native file-open policy plus the exact same grammar as the text path.
// The file remains open and its bounded bytes remain alive through visitor().
[[nodiscard]] bool visitRuntimeConfigurationFile(
    const char* path,
    RuntimeConfigurationCapabilities capabilities,
    RuntimeConfigurationVisitor visitor,
    void* context) noexcept;

// Shared R3 licensing provisioning from the same validated configuration view.
[[nodiscard]] bool configureRuntimeLicensingContextFromConfiguration(
    const RuntimeConfigurationView& configuration,
    RuntimeLicensingContext& licensingContext) noexcept;

} // namespace rdp_server::server::runtime
