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

string(REGEX MATCHALL
    "CurrentOwnerSharingAuthority[ \t\r\n]+ownerSharingAuthority_"
    owner_authority_members "${host_header}")
list(LENGTH owner_authority_members owner_authority_member_count)
if(NOT owner_authority_member_count EQUAL 1)
    message(FATAL_ERROR
        "Linux HostControl must own exactly one CurrentOwnerSharingAuthority")
endif()
string(FIND "${host_header}" "ownerEvidence_" owner_evidence)
string(FIND "${host_header}" "ownerSharingAuthority_" owner_authority)
if(owner_evidence EQUAL -1 OR owner_authority EQUAL -1 OR
   NOT owner_evidence LESS owner_authority)
    message(FATAL_ERROR
        "Linux HostControl native owner evidence must outlive its R2 authority")
endif()

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
string(REGEX MATCH
    "broker_[.]emplace[(][ \t\r\n]*[*]policy[ \t\r\n]*,[ \t\r\n]*ownerSharingAuthority[ \t\r\n]*[)]"
    broker_handoff "${connection_source}")
if(connection_authority_parameter EQUAL -1 OR broker_handoff STREQUAL "")
    message(FATAL_ERROR
        "LinuxRuntimeConnection must forward the host R2 authority into the admission broker")
endif()
