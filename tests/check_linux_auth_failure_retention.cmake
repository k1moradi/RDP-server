# SPDX-License-Identifier: GPL-3.0-or-later
# R7/R2 source contract: a failed remote authentication retires only that
# accepted client. It must not revoke the configured Session Password or close
# the local listener; explicit Stop/revoke/session-security policy owns those
# wider lifetimes.
if(NOT DEFINED RDP_LINUX_HOST_CONTROL_SOURCE OR
   "${RDP_LINUX_HOST_CONTROL_SOURCE}" STREQUAL "")
    message(FATAL_ERROR "RDP_LINUX_HOST_CONTROL_SOURCE is required")
endif()

file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireAcceptedClient("
    retire_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::pollAcceptedClientReadiness()"
    retire_end)
if(retire_begin EQUAL -1 OR retire_end EQUAL -1 OR
   NOT retire_begin LESS retire_end)
    message(FATAL_ERROR "Cannot isolate accepted-client retirement boundary")
endif()
math(EXPR retire_length "${retire_end} - ${retire_begin}")
string(SUBSTRING "${host_source}" ${retire_begin}
    ${retire_length} retire_source)

foreach(required IN ITEMS
    "acceptedClient_->revoke();"
    "clearAcceptedClient();"
    "clientDisconnected_ = hadAcceptedClient && listener_.valid();"
    "stage_ = listener_.valid()"
    "RuntimeHostStage::ListenerAvailable"
    "lastError_ = error;")
    string(FIND "${retire_source}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "Accepted-client authentication retirement lost required token: ${required}")
    endif()
endforeach()

foreach(forbidden IN ITEMS
    "retireStoppedRuntime("
    "standalonePasswordCredential_.revoke()"
    "standaloneCredentialGeneration_ = 0U"
    "credentialsConfigured_ = false"
    "listener_.close()")
    string(FIND "${retire_source}" "${forbidden}" position)
    if(NOT position EQUAL -1)
        message(FATAL_ERROR
            "Per-peer authentication failure widened host teardown: ${forbidden}")
    endif()
endforeach()
