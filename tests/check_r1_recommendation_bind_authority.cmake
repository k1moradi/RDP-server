# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_RUNTIME_HOST_CONTROL_HEADER
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_LAN_LISTENER_SOURCE)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_RUNTIME_HOST_CONTROL_HEADER}" host_header)
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_LAN_LISTENER_SOURCE}" listener_source)

foreach(required_text IN ITEMS
        "RuntimeHostRecommendedEndpoint"
        "assessRuntimeSelectedLanEndpoint("
        "recommendRuntimePrivateLanEndpoint(")
    string(FIND "${host_header}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "HostControl recommendation boundary missing: ${required_text}")
    endif()
endforeach()

string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::startSharing()" transaction_begin)
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireNativeDesktop()" transaction_end)
if(transaction_begin LESS 0 OR transaction_end LESS_EQUAL transaction_begin)
    message(FATAL_ERROR "Unable to isolate Linux HostControl Start transaction")
endif()
math(EXPR transaction_length "${transaction_end} - ${transaction_begin}")
string(SUBSTRING "${host_source}" ${transaction_begin}
    ${transaction_length} transaction_source)

set(start_ordered_tokens
    "ownerSharingAuthority_.authorizes("
    "assessRuntimeSelectedLanEndpoint("
    "enumerateLocalInterfaces()"
    "resolveCurrentLinuxNativeLanInterface("
    "tlsContext_->identityStatus()"
    "openLanListener({"
    "tlsContext_->boundIdentityStatus("
    "configurePersonalDesktopPrivateLan("
    "listener_ = std::move(candidate)")
set(previous_position -1)
foreach(token IN LISTS start_ordered_tokens)
    string(FIND "${transaction_source}" "${token}" token_position)
    if(token_position LESS 0)
        message(FATAL_ERROR "Start-time R1 bind token missing: ${token}")
    endif()
    if(token_position LESS_EQUAL previous_position)
        message(FATAL_ERROR "Start-time R1 bind order regressed at: ${token}")
    endif()
    set(previous_position ${token_position})
endforeach()

foreach(required_text IN ITEMS
        "nativeIdentity->nativeName"
        "selection_.localAddress"
        "selection_.port")
    string(FIND "${transaction_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "Exact recommended endpoint is not forwarded to R1: ${required_text}")
    endif()
endforeach()

string(FIND "${transaction_source}"
    "recommendRuntimePrivateLanEndpoint(" ranking_in_start)
if(NOT ranking_in_start EQUAL -1)
    message(FATAL_ERROR "Recommendation ranking entered the Start authority transaction")
endif()

string(FIND "${listener_source}"
    "bool findInterfaceAddress(" selection_begin)
string(FIND "${listener_source}"
    "LanListenerError socketFailure()" selection_end)
if(selection_begin LESS 0 OR selection_end LESS_EQUAL selection_begin)
    message(FATAL_ERROR "Unable to isolate native interface/address selection")
endif()
math(EXPR selection_length "${selection_end} - ${selection_begin}")
string(SUBSTRING "${listener_source}" ${selection_begin}
    ${selection_length} selection_source)

foreach(required_text IN ITEMS
        "adapter->OperStatus != IfOperStatusUp"
        "name != adapter->AdapterName"
        "IFF_UP | IFF_RUNNING"
        "name != entry->ifa_name"
        "std::memcmp(left, right, size) != 0")
    string(FIND "${selection_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "Native exact/up interface check missing: ${required_text}")
    endif()
endforeach()

string(FIND "${listener_source}"
    "LanListenerResult openLanListener(" listener_begin)
string(FIND "${listener_source}"
    "} // namespace rdp_server::server::transport" listener_end)
if(listener_begin LESS 0 OR listener_end LESS_EQUAL listener_begin)
    message(FATAL_ERROR "Unable to isolate R1 LAN listener open")
endif()
math(EXPR listener_length "${listener_end} - ${listener_begin}")
string(SUBSTRING "${listener_source}" ${listener_begin}
    ${listener_length} listener_open_source)

set(listener_ordered_tokens
    "::inet_pton"
    "if (!allowedAddress(wanted))"
    "findInterfaceAddress(request.interfaceName, wanted, selection)"
    "::socket"
    "::bind(socket, reinterpret_cast<const sockaddr *>(&selection.address)"
    "::getsockname"
    "result.listener.interfaceStillMatches()")
set(previous_position -1)
foreach(token IN LISTS listener_ordered_tokens)
    string(FIND "${listener_open_source}" "${token}" token_position)
    if(token_position LESS 0)
        message(FATAL_ERROR "R1 listener bind token missing: ${token}")
    endif()
    if(token_position LESS_EQUAL previous_position)
        message(FATAL_ERROR "R1 listener bind order regressed at: ${token}")
    endif()
    set(previous_position ${token_position})
endforeach()

string(FIND "${listener_source}"
    "selection.interfaceIndex == interfaceIndex_" exact_index_check)
if(exact_index_check LESS 0)
    message(FATAL_ERROR "Post-bind exact interface-index continuity check missing")
endif()
