# SPDX-License-Identifier: GPL-3.0-or-later
foreach(required_variable IN ITEMS
        RDP_LINUX_HOST_CONTROL_HEADER
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_LINUX_CONNECTION_HEADER
        RDP_LINUX_CONNECTION_SOURCE)
    if(NOT DEFINED ${required_variable})
        message(FATAL_ERROR "Missing ${required_variable}")
    endif()
endforeach()

file(READ "${RDP_LINUX_HOST_CONTROL_HEADER}" host_header)
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_LINUX_CONNECTION_HEADER}" connection_header)
file(READ "${RDP_LINUX_CONNECTION_SOURCE}" connection_source)

foreach(required_text IN ITEMS
        "CurrentOwnerSharingAuthority"
        "ownerSharingAuthority_{}")
    string(FIND "${host_header}" "${required_text}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
            "Linux HostControl no longer owns R2 host authority: ${required_text}")
    endif()
endforeach()

string(FIND "${host_source}" "ownerSharingAuthority_.revoke(reason);" r2_revoke)
string(FIND "${host_source}" "listener_.close();" listener_close)
if(r2_revoke EQUAL -1 OR listener_close EQUAL -1 OR
   NOT r2_revoke LESS listener_close)
    message(FATAL_ERROR
        "Linux HostControl must revoke R2 authority before retiring the R1 listener")
endif()

string(FIND "${host_source}" "ownerSharingAuthority_.requestConsent({" consent_request)
if(consent_request EQUAL -1)
    message(FATAL_ERROR
        "Linux HostControl must marshal permission intent to the production R2 authority")
endif()

string(FIND "${connection_header}"
    "CurrentOwnerSharingAuthority" connection_authority_parameter)
string(FIND "${connection_source}"
    "broker_.emplace(*policy, ownerSharingAuthority);" broker_handoff)
if(connection_authority_parameter EQUAL -1 OR broker_handoff EQUAL -1)
    message(FATAL_ERROR
        "LinuxRuntimeConnection must forward the host R2 authority into the admission broker")
endif()
