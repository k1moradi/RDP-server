# SPDX-License-Identifier: GPL-3.0-or-later
foreach(required_variable IN ITEMS
        RDP_LINUX_HOST_CONTROL_HEADER
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_LINUX_CONNECTION_HEADER
        RDP_CONSOLE_ADMISSION_HEADER
        RDP_GUI_WINDOW_SOURCE)
    if(NOT DEFINED ${required_variable})
        message(FATAL_ERROR "Missing ${required_variable}")
    endif()
endforeach()

file(READ "${RDP_LINUX_HOST_CONTROL_HEADER}" host_header)
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_LINUX_CONNECTION_HEADER}" connection_header)
file(READ "${RDP_CONSOLE_ADMISSION_HEADER}" admission_header)
file(READ "${RDP_GUI_WINDOW_SOURCE}" gui_window_source)

foreach(required IN ITEMS
        "enum class ConfiguredAuthenticationMode"
        "StandalonePassword,"
        "standaloneCredentialGeneration_"
        "buildAuthenticationSelection")
    string(FIND "${host_header}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R10 HostControl is missing standalone selector state: ${required}")
    endif()
endforeach()

foreach(required IN ITEMS
        "selectedStandaloneCredentialReady()"
        "standalonePasswordCredential_.visit("
        "observation.generation != standaloneCredentialGeneration_"
        "RAND_bytes("
        "currentWindowsFileTime()"
        "selection.mode = LinuxRuntimeAuthenticationMode::StandalonePassword"
        "selection.standaloneCredentialOwner = &standalonePasswordCredential_"
        "selection.standaloneCredentialGeneration ="
        "acceptedClient_->issueStandaloneAdmission()")
    string(FIND "${host_source}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R10 HostControl standalone path is missing fail-closed selector evidence: ${required}")
    endif()
endforeach()

string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::acceptClientOnce(" accept_start)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::advanceAcceptedClientOnce()" advance_start)
if(accept_start EQUAL -1 OR advance_start EQUAL -1 OR
   NOT accept_start LESS advance_start)
    message(FATAL_ERROR "Unable to isolate R10 accepted-client selector")
endif()
math(EXPR accept_length "${advance_start} - ${accept_start}")
string(SUBSTRING "${host_source}" ${accept_start} ${accept_length} accept_slice)

foreach(required IN ITEMS
        "buildAuthenticationSelection(authenticationSelection)"
        "&ownerSharingAuthority_, authenticationSelection")
    string(FIND "${accept_slice}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "Accepted client does not consume the explicit authentication selector: ${required}")
    endif()
endforeach()

string(FIND "${accept_slice}"
    "&authAttempts_, &ownerSharingAuthority_);" default_constructor)
if(NOT default_constructor EQUAL -1)
    message(FATAL_ERROR
        "Accepted-client path still falls back to the default OS-account constructor")
endif()

foreach(required IN ITEMS
        "enum class LinuxRuntimeAuthenticationMode"
        "ExistingOsAccount,"
        "StandalonePassword,"
        "standaloneCredentialOwner"
        "standaloneCredentialGeneration"
        "standaloneChallenge"
        "issueStandaloneAdmission()")
    string(FIND "${connection_header}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "Lower-level LinuxRuntimeConnection selector contract missing: ${required}")
    endif()
endforeach()


foreach(required IN ITEMS
        "issueStandaloneCurrentOwner("
        "const ConsoleIdentityPolicy *policy_{}")
    string(FIND "${admission_header}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R2 standalone-native admission contract missing: ${required}")
    endif()
endforeach()

# Product exposure is governed by the separate owner-acceptance capability
# gate. This selector contract only pins that the GUI can forward an explicitly
# exposed Session Password into the production path; it must not duplicate
# authentication policy here.
foreach(required_gui IN ITEMS
        "host_.configureStandalonePassword("
        "sessionPassword_"
        "sessionPasswordConfirm_")
    string(FIND "${gui_window_source}" "${required_gui}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "GUI lost production standalone forwarding surface: ${required_gui}")
    endif()
endforeach()

message(STATUS
    "Standalone authentication uses exact credential generation plus R2 current-owner admission without GSS/keytab fallback")
