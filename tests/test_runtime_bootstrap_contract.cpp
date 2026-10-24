// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_application_bootstrap.h"

#include <cassert>

int main()
{
    using namespace rdp_server::server::runtime;

    assert(runtimeBootstrapDefaultStorage(RuntimeBootstrapMaterial::TlsIdentity) ==
           RuntimeBootstrapStorage::VolatileMemoryOnly);
    assert(runtimeBootstrapPersistentStorage(RuntimeBootstrapMaterial::TlsIdentity) ==
           RuntimeBootstrapStorage::PrivateApplicationData);
    assert(runtimeBootstrapDefaultStorage(
               RuntimeBootstrapMaterial::LicensingIdentity) ==
           RuntimeBootstrapStorage::VolatileMemoryOnly);
    assert(runtimeBootstrapPersistentStorage(
               RuntimeBootstrapMaterial::LicensingIdentity) ==
           RuntimeBootstrapStorage::PrivateApplicationData);
    assert(runtimeBootstrapDefaultStorage(RuntimeBootstrapMaterial::Preferences) ==
           RuntimeBootstrapStorage::NonSecretConfiguration);
    assert(runtimeBootstrapDefaultStorage(RuntimeBootstrapMaterial::SessionPassword) ==
           RuntimeBootstrapStorage::VolatileMemoryOnly);
    assert(runtimeBootstrapMayPersist(RuntimeBootstrapMaterial::TlsIdentity));
    assert(runtimeBootstrapMayPersist(RuntimeBootstrapMaterial::LicensingIdentity));
    assert(runtimeBootstrapMayPersist(RuntimeBootstrapMaterial::Preferences));
    assert(!runtimeBootstrapMayPersist(RuntimeBootstrapMaterial::SessionPassword));

    static_assert(kRuntimeDefaultListenPort == 3389U);
    static_assert(!RuntimeApplicationBootstrapPolicy::configurationFileRequired);
    static_assert(
        RuntimeApplicationBootstrapPolicy::expertConfigurationOverrideSupported);
    static_assert(
        RuntimeApplicationBootstrapPolicy::localIdentityProvisioningAllowedAtStartup);
    static_assert(!RuntimeApplicationBootstrapPolicy::tlsIdentityPersistedByDefault);
    static_assert(
        !RuntimeApplicationBootstrapPolicy::licensingIdentityPersistedByDefault);
    static_assert(
        RuntimeApplicationBootstrapPolicy::explicitSharingRequiredBeforeListen);
    static_assert(!RuntimeApplicationBootstrapPolicy::automaticListenerStart);
    static_assert(!RuntimeApplicationBootstrapPolicy::sessionPasswordPersisted);
    static_assert(!RuntimeApplicationBootstrapPolicy::administratorRequired);
    static_assert(!RuntimeApplicationBootstrapPolicy::writesBesideExecutable);
    static_assert(RuntimeApplicationBootstrapPolicy::readOnlyExtractionSupported);
    static_assert(RuntimeApplicationBootstrapPolicy::failClosedOnPathReplacement);
    static_assert(!RuntimeApplicationBootstrapPolicy::serviceInstallationAllowed);
    static_assert(!RuntimeApplicationBootstrapPolicy::firewallMutationAllowed);
    static_assert(!RuntimeApplicationBootstrapPolicy::windowsRdpMutationAllowed);
    static_assert(
        !RuntimeApplicationBootstrapPolicy::macosSystemConfigurationMutationAllowed);
    return 0;
}
