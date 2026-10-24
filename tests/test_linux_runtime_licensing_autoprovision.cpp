// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/runtime/linux_runtime_host_control.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>

using namespace rdp_server::server::runtime;

int main()
{
    LinuxRuntimeHostControl host;
    const RuntimeHostStatus initial = host.status();

    // Automatic R3 provisioning is constructor-owned and fail-closed. A
    // generator failure is the bounded InternalFailure product state.
    assert(initial.lastError != RuntimeHostError::InternalFailure);

    // Construction is preparation only: no R1 listener or R2/native authority
    // may be created merely because the application has a licensing identity.
    assert(!initial.listenerAvailable);
    assert(initial.stage == RuntimeHostStage::Stopped);

    const RuntimeHostResult start = host.startSharing();
    assert(!start.succeeded());
    assert(!host.status().listenerAvailable);
    return 0;
}
