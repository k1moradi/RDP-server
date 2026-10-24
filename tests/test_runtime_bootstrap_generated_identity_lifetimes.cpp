// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_application_bootstrap.h"

int main()
{
    using namespace rdp_server::server::runtime;

    static_assert(
        runtimeBootstrapDefaultStorage(RuntimeBootstrapMaterial::TlsIdentity) ==
        RuntimeBootstrapStorage::VolatileMemoryOnly);
    static_assert(
        runtimeBootstrapDefaultStorage(
            RuntimeBootstrapMaterial::LicensingIdentity) ==
        RuntimeBootstrapStorage::VolatileMemoryOnly);

    // Persistence is an explicit future policy choice, never the default.
    static_assert(runtimeBootstrapMayPersist(RuntimeBootstrapMaterial::TlsIdentity));
    static_assert(
        runtimeBootstrapMayPersist(RuntimeBootstrapMaterial::LicensingIdentity));
    static_assert(
        runtimeBootstrapPersistentStorage(RuntimeBootstrapMaterial::TlsIdentity) ==
        RuntimeBootstrapStorage::PrivateApplicationData);
    static_assert(
        runtimeBootstrapPersistentStorage(
            RuntimeBootstrapMaterial::LicensingIdentity) ==
        RuntimeBootstrapStorage::PrivateApplicationData);

    static_assert(!RuntimeApplicationBootstrapPolicy::tlsIdentityPersistedByDefault);
    static_assert(
        !RuntimeApplicationBootstrapPolicy::licensingIdentityPersistedByDefault);
    return 0;
}
