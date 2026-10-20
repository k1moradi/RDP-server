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
string(FIND "${candidate}"
    "const auto retireNativeCandidate = [&]() noexcept {" retire_helper)
string(FIND "${candidate}"
    "while (connection.ready() && nativeOwner.desktop->valid()) {" owner)
if(retire_helper EQUAL -1 OR owner EQUAL -1 OR
   NOT retire_helper LESS owner)
    message(FATAL_ERROR "Cannot isolate native terminal retirement helper")
endif()
math(EXPR helper_length "${owner} - ${retire_helper}")
string(SUBSTRING "${candidate}" ${retire_helper}
    ${helper_length} retire_helper_source)
set(retire_tokens
    "nativeOwner.desktop->retireAfterAuthorizationLoss()"
    "connection.revoke()")
set(previous_position -1)
foreach(token IN LISTS retire_tokens)
    string(FIND "${retire_helper_source}" "${token}" token_position)
    if(token_position EQUAL -1 OR token_position LESS_EQUAL previous_position)
        message(FATAL_ERROR
            "Terminal helper must retire native input before R3/R1 revoke: ${token}")
    endif()
    set(previous_position ${token_position})
endforeach()

string(FIND "${candidate}" "if (linuxServeStopRequested()) {" stop)
string(FIND "${candidate}" "retireNativeCandidate();" cleanup REVERSE)
if(stop EQUAL -1 OR cleanup EQUAL -1 OR
   NOT owner LESS stop OR NOT stop LESS cleanup)
    message(FATAL_ERROR
        "Cooperative Stop must reach the ordered terminal retirement helper")
endif()

# The CLI composition owns its listener outside the serialized candidate. This
# preserves native -> connection -> listener lifetime. HostControl's separate
# owner-authority -> accepted-connection -> listener ordering is pinned by the
# bounded GUI scheduler guard until R10X moves this native owner into HostControl.
string(FIND "${source}"
    "rdp_server::server::runtime::RuntimeConfigurationCapabilities"
    serve_end)
if(serve_end LESS_EQUAL finish)
    message(FATAL_ERROR "Cannot isolate Linux serve listener lifetime")
endif()
math(EXPR serve_length "${serve_end} - ${finish}")
string(SUBSTRING "${source}" ${finish} ${serve_length} serve_source)
string(FIND "${serve_source}"
    "LinuxListenerOwner listener{listenerDescriptor};" listener_owner)
string(FIND "${serve_source}"
    "while (!linuxServeStopRequested())" serve_loop)
string(FIND "${serve_source}"
    "pollNonblockingTcpAcceptBatch(" accept_poll)
if(listener_owner EQUAL -1 OR serve_loop EQUAL -1 OR accept_poll EQUAL -1 OR
   NOT listener_owner LESS serve_loop OR NOT serve_loop LESS accept_poll)
    message(FATAL_ERROR
        "Listener RAII owner must outlive every serialized candidate callback")
endif()
foreach(forbidden IN ITEMS "SSL_read_ex" "XTestFake")
    string(FIND "${candidate}" "${forbidden}" pos)
    if(NOT pos EQUAL -1)
        message(FATAL_ERROR "Stop cannot duplicate transport/native ownership")
    endif()
endforeach()
