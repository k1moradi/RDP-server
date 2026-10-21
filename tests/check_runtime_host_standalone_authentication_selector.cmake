# SPDX-License-Identifier: GPL-3.0-or-later
foreach(required_variable IN ITEMS
        RDP_LINUX_HOST_CONTROL_HEADER
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_LINUX_CONNECTION_HEADER
        RDP_GUI_WINDOW_SOURCE)
    if(NOT DEFINED ${required_variable})
        message(FATAL_ERROR "Missing ${required_variable}")
    endif()
endforeach()

file(READ "${RDP_LINUX_HOST_CONTROL_HEADER}" host_header)
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_LINUX_CONNECTION_HEADER}" connection_header)
file(READ "${RDP_GUI_WINDOW_SOURCE}" gui_window_source)

foreach(required IN ITEMS
        "ConfiguredAuthenticationMode::StandalonePassword"
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
        "Kind::StandalonePassword")
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
        "standaloneChallenge")
    string(FIND "${connection_header}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "Lower-level LinuxRuntimeConnection selector contract missing: ${required}")
    endif()
endforeach()

# The public product UI remains non-collecting until a genuine Microsoft-client
# run accepts this exact production path.
foreach(forbidden IN ITEMS
        "standalonePassword"
        "passwordConfirmation")
    string(FIND "${gui_window_source}" "${forbidden}" position)
    if(NOT position EQUAL -1)
        message(FATAL_ERROR
            "Public GUI unexpectedly exposes standalone password input: ${forbidden}")
    endif()
endforeach()

message(STATUS
    "R10 selects standalone authentication explicitly with exact-generation fencing and no OS-account fallback")
