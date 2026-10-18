# SPDX-License-Identifier: GPL-3.0-or-later
if(NOT DEFINED RDP_RUNTIME_CONNECTION_SOURCE OR
   RDP_RUNTIME_CONNECTION_SOURCE STREQUAL "")
    message(FATAL_ERROR "RDP_RUNTIME_CONNECTION_SOURCE is required")
endif()

file(READ "${RDP_RUNTIME_CONNECTION_SOURCE}" runtime_source)

function(require_call_between start_marker end_marker required_call forbidden_call)
    string(FIND "${runtime_source}" "${start_marker}" start_index)
    if(start_index EQUAL -1)
        message(FATAL_ERROR "missing runtime marker: ${start_marker}")
    endif()

    string(FIND "${runtime_source}" "${end_marker}" end_index)
    if(end_index EQUAL -1 OR end_index LESS_EQUAL start_index)
        message(FATAL_ERROR
            "missing/invalid runtime end marker after ${start_marker}: ${end_marker}")
    endif()

    math(EXPR body_length "${end_index} - ${start_index}")
    string(SUBSTRING "${runtime_source}" ${start_index} ${body_length} body)

    string(FIND "${body}" "${required_call}" required_index)
    if(required_index EQUAL -1)
        message(FATAL_ERROR
            "required authorization call missing from ${start_marker}")
    endif()

    string(FIND "${body}" "${forbidden_call}" forbidden_index)
    if(NOT forbidden_index EQUAL -1)
        message(FATAL_ERROR
            "forbidden lease-only revalidation remains in ${start_marker}")
    endif()
endfunction()

set(bare_revalidate
    "broker_->revalidate(*lease_, acceptor_, connection_)")
set(protected_transition
    "broker_->authorizeR3ProtectedTransition(")

# Connect Initial is the only legitimate lease-only read: R3 has not yet
# stored admission/session generations, so the protected R3 fence cannot run.
require_call_between(
    "LinuxRuntimeConnection::advancePostAdmissionMcsConnectInitial("
    "LinuxRuntimeConnection::advancePostAdmissionMcsConnectResponseWrite("
    "${bare_revalidate}"
    "${protected_transition}")

# Every read after admitted Connect Initial must fence the exact stored R3
# admission/session generations before R1 may return another plaintext byte.
require_call_between(
    "LinuxRuntimeConnection::advancePostAdmissionMcsErectDomain("
    "LinuxRuntimeConnection::postAdmissionMcsPolicyMatches("
    "${protected_transition}"
    "${bare_revalidate}")
require_call_between(
    "LinuxRuntimeConnection::advancePersonalDesktopClientLicensingIntake("
    "LinuxRuntimeConnection::advancePersonalDesktopValidClientWrite("
    "${protected_transition}"
    "${bare_revalidate}")
require_call_between(
    "LinuxRuntimeConnection::advancePersonalDesktopShareActivation("
    "LinuxRuntimeConnection::beginPersonalDesktopShareActivation("
    "${protected_transition}"
    "${bare_revalidate}")
require_call_between(
    "LinuxRuntimeConnection::advancePersonalDesktopGraphicsDynamicVirtualChannel("
    "LinuxRuntimeConnection::authorizePersonalDesktopApplicationTraffic("
    "${protected_transition}"
    "${bare_revalidate}")

string(REGEX MATCHALL
    "broker_->revalidate\\(\\*lease_, acceptor_, connection_\\)"
    bare_calls "${runtime_source}")
list(LENGTH bare_calls bare_call_count)
if(NOT bare_call_count EQUAL 1)
    message(FATAL_ERROR
        "expected exactly one pre-R3-binding lease-only read, found ${bare_call_count}")
endif()
