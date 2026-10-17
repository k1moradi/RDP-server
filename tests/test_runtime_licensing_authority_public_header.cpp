// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/runtime_licensing_authority.h"

#include <cassert>

int main()
{
    using rdp_server::server::runtime::RuntimeLicensingAuthority;
    using rdp_server::server::runtime::RuntimeLicensingAuthorityState;

    RuntimeLicensingAuthority authority;
    assert(authority.state() == RuntimeLicensingAuthorityState::NotConfigured);
    assert(!authority.configured());
    assert(!authority.issuerVerified());
    return 0;
}
