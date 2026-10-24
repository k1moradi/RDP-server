// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace rdp_server::server::runtime
{

enum class RuntimeBootstrapMaterial : std::uint8_t
{
    TlsIdentity,
    LicensingIdentity,
    Preferences,
    SessionPassword,
};

enum class RuntimeBootstrapStorage : std::uint8_t
{
    PrivateApplicationData,
    NonSecretConfiguration,
    VolatileMemoryOnly,
};

// The default is the shortest safe lifetime. R1 generates endpoint-bound TLS
// identity in process memory and R3 now generates the licensing identity in
// process memory. If licensing is ever persisted, it must use private
// application data. Session Password never gets a persistent default.
[[nodiscard]] constexpr RuntimeBootstrapStorage runtimeBootstrapDefaultStorage(
    const RuntimeBootstrapMaterial material) noexcept
{
    switch (material)
    {
    case RuntimeBootstrapMaterial::TlsIdentity:
    case RuntimeBootstrapMaterial::LicensingIdentity:
    case RuntimeBootstrapMaterial::SessionPassword:
        return RuntimeBootstrapStorage::VolatileMemoryOnly;
    case RuntimeBootstrapMaterial::Preferences:
        return RuntimeBootstrapStorage::NonSecretConfiguration;
    }
    return RuntimeBootstrapStorage::VolatileMemoryOnly;
}

[[nodiscard]] constexpr bool runtimeBootstrapMayPersist(
    const RuntimeBootstrapMaterial material) noexcept
{
    return material != RuntimeBootstrapMaterial::SessionPassword;
}

[[nodiscard]] constexpr RuntimeBootstrapStorage runtimeBootstrapPersistentStorage(
    const RuntimeBootstrapMaterial material) noexcept
{
    switch (material)
    {
    case RuntimeBootstrapMaterial::TlsIdentity:
    case RuntimeBootstrapMaterial::LicensingIdentity:
        return RuntimeBootstrapStorage::PrivateApplicationData;
    case RuntimeBootstrapMaterial::Preferences:
        return RuntimeBootstrapStorage::NonSecretConfiguration;
    case RuntimeBootstrapMaterial::SessionPassword:
        return RuntimeBootstrapStorage::VolatileMemoryOnly;
    }
    return RuntimeBootstrapStorage::VolatileMemoryOnly;
}

// Cross-platform product bootstrap policy. Platform adapters select the OS
// per-user application-data/config roots; they must never derive writable
// state from the executable/extraction directory. This policy grants no R1
// listener, R2 admission, R3 Share or native desktop authority.
struct RuntimeApplicationBootstrapPolicy final
{
    static constexpr std::uint16_t defaultListenPort{3389U};
    static constexpr bool configurationFileRequired{false};
    static constexpr bool expertConfigurationOverrideSupported{true};
    static constexpr bool localIdentityProvisioningAllowedAtStartup{true};
    static constexpr bool tlsIdentityPersistedByDefault{false};
    static constexpr bool licensingIdentityPersistedByDefault{false};
    static constexpr bool explicitSharingRequiredBeforeListen{true};
    static constexpr bool automaticListenerStart{false};
    static constexpr bool sessionPasswordPersisted{false};
    static constexpr bool administratorRequired{false};
    static constexpr bool writesBesideExecutable{false};
    static constexpr bool readOnlyExtractionSupported{true};
    static constexpr bool failClosedOnPathReplacement{true};
    static constexpr bool serviceInstallationAllowed{false};
    static constexpr bool firewallMutationAllowed{false};
    static constexpr bool windowsRdpMutationAllowed{false};
    static constexpr bool macosSystemConfigurationMutationAllowed{false};
};

inline constexpr std::uint16_t kRuntimeDefaultListenPort =
    RuntimeApplicationBootstrapPolicy::defaultListenPort;

static_assert(
    runtimeBootstrapDefaultStorage(RuntimeBootstrapMaterial::SessionPassword) ==
    RuntimeBootstrapStorage::VolatileMemoryOnly);
static_assert(!runtimeBootstrapMayPersist(
    RuntimeBootstrapMaterial::SessionPassword));
static_assert(
    RuntimeApplicationBootstrapPolicy::explicitSharingRequiredBeforeListen);
static_assert(!RuntimeApplicationBootstrapPolicy::automaticListenerStart);

} // namespace rdp_server::server::runtime
