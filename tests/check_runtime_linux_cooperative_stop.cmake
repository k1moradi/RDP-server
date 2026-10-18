# SPDX-License-Identifier: GPL-3.0-or-later
# Production R10 source contract. Never send real signals or open TCP/X11.
if(NOT DEFINED RDP_RUNTIME_ENTRYPOINT_SOURCE OR
   "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" STREQUAL "")
    message(FATAL_ERROR "Missing R10 entrypoint source")
endif()
file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" source)
foreach(needle IN ITEMS
    "volatile std::sig_atomic_t gLinuxServeStopSignal = 0;"
    "gLinuxServeStopSignal = 1;"
    "ScopedLinuxServeTerminationHandlers terminationHandlers;"
    "::sigaction(SIGINT, &replacement, &oldInterrupt_)"
    "::sigaction(SIGTERM, &replacement, &oldTerminate_)"
    "::sigaction(SIGTERM, &oldTerminate_, nullptr)"
    "::sigaction(SIGINT, &oldInterrupt_, nullptr)"
    "while (!linuxServeStopRequested())"
    "if (linuxServeStopRequested())"
    "nativeOwner.desktop->retireAfterAuthorizationLoss();"
    "connection.revoke();")
    string(FIND "${source}" "${needle}" pos)
    if(pos EQUAL -1)
        message(FATAL_ERROR "Missing R10 Stop boundary: ${needle}")
    endif()
endforeach()
string(FIND "${source}" "runSerializedLinuxCandidate(" start)
string(FIND "${source}" "runLinuxPersonalDesktopServe(" finish)
if(start EQUAL -1 OR finish EQUAL -1 OR NOT start LESS finish)
    message(FATAL_ERROR "Cannot isolate serialized candidate")
endif()
math(EXPR span "${finish} - ${start}")
string(SUBSTRING "${source}" ${start} ${span} candidate)
string(REGEX MATCHALL "!linuxServeStopRequested[(][)]" gates "${candidate}")
list(LENGTH gates gate_count)
if(NOT gate_count EQUAL 13)
    message(FATAL_ERROR "Expected Stop on all 13 handshake loops: ${gate_count}")
endif()
string(FIND "${candidate}" "while (connection.ready() && nativeOwner.desktop->valid()) {" owner)
string(FIND "${candidate}" "if (linuxServeStopRequested()) {" stop)
string(FIND "${candidate}" "nativeOwner.desktop->retireAfterAuthorizationLoss();" retire REVERSE)
string(FIND "${candidate}" "connection.revoke();" revoke REVERSE)
if(owner EQUAL -1 OR stop EQUAL -1 OR retire EQUAL -1 OR revoke EQUAL -1
   OR NOT owner LESS stop OR NOT stop LESS retire OR NOT retire LESS revoke)
    message(FATAL_ERROR "Stop must retire native input before R3/R1 revoke")
endif()
foreach(forbidden IN ITEMS "SSL_read_ex" "XTestFake")
    string(FIND "${candidate}" "${forbidden}" pos)
    if(NOT pos EQUAL -1)
        message(FATAL_ERROR "Stop cannot duplicate transport/native ownership")
    endif()
endforeach()
