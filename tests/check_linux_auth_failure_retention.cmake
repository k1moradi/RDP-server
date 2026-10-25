# SPDX-License-Identifier: GPL-3.0-or-later
# R7/R2 source contract: a failed remote authentication retires only that
# accepted client. It must not revoke the configured Session Password or close
# the local listener; explicit Stop/revoke/session-security policy owns those
# wider lifetimes.
if(NOT DEFINED RDP_LINUX_HOST_CONTROL_SOURCE OR
   "${RDP_LINUX_HOST_CONTROL_SOURCE}" STREQUAL "" OR
   NOT DEFINED RDP_LINUX_CONNECTION_SOURCE OR
   "${RDP_LINUX_CONNECTION_SOURCE}" STREQUAL "")
    message(FATAL_ERROR
        "RDP_LINUX_HOST_CONTROL_SOURCE and RDP_LINUX_CONNECTION_SOURCE are required")
endif()

file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_LINUX_CONNECTION_SOURCE}" connection_source)
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
    "RuntimeHostError retainedError = error;"
    "lastError_ = retainedError;")
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

# The acceptor is cleansed on terminal failure, so cache only the redacted
# envelope before reset. Isolate the standalone CredSSP function before checking
# order so unrelated resets elsewhere in the connection cannot satisfy/fail it.
string(FIND "${connection_source}"
    "LinuxCredSspStepResult LinuxRuntimeConnection::advanceStandaloneCredSsp() noexcept"
    credssp_begin)
string(FIND "${connection_source}"
    "LinuxCredSspStepResult LinuxRuntimeConnection::onCredSspIoReady() noexcept"
    credssp_end)
if(credssp_begin EQUAL -1 OR credssp_end EQUAL -1 OR
   NOT credssp_begin LESS credssp_end)
    message(FATAL_ERROR "Cannot isolate standalone CredSSP connection path")
endif()
math(EXPR credssp_length "${credssp_end} - ${credssp_begin}")
string(SUBSTRING "${connection_source}" ${credssp_begin}
    ${credssp_length} credssp_source)

foreach(required IN ITEMS
    "const auto captureNegotiationEnvelope = [this]() noexcept"
    "standaloneNegotiationEnvelope_ ="
    "captureNegotiationEnvelope();"
    "standaloneCredSspAcceptor_.reset();")
    string(FIND "${credssp_source}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "Authentication diagnostic envelope lifetime lost required token: ${required}")
    endif()
endforeach()

foreach(required IN ITEMS
    "snapshot.standaloneNegotiationEnvelope ="
    "standaloneNegotiationEnvelope_;")
    string(FIND "${connection_source}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "Acceptance diagnostic snapshot lost cached envelope: ${required}")
    endif()
endforeach()

string(FIND "${credssp_source}"
    "captureNegotiationEnvelope();" capture_position)
string(FIND "${credssp_source}"
    "standaloneCredSspAcceptor_.reset();" reset_position)
if(capture_position EQUAL -1 OR reset_position EQUAL -1 OR
   NOT capture_position LESS reset_position)
    message(FATAL_ERROR
        "Authentication diagnostic envelope must be captured before CredSSP reset")
endif()
