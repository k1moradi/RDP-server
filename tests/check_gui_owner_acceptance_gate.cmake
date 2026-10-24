# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_DESKTOP_WINDOW_SOURCE
        RDP_HOST_CONTROL_SOURCE
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_RUNTIME_HOST_CONTROL_HEADER
        RDP_DESKTOP_ENTRYPOINT_SOURCE
        RDP_ROOT_CMAKE)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_DESKTOP_WINDOW_SOURCE}" window_source)
file(READ "${RDP_HOST_CONTROL_SOURCE}" host_control_source)
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" linux_host_source)
file(READ "${RDP_RUNTIME_HOST_CONTROL_HEADER}" runtime_header)
file(READ "${RDP_DESKTOP_ENTRYPOINT_SOURCE}" entrypoint_source)
file(READ "${RDP_ROOT_CMAKE}" root_cmake)

foreach(required_text IN ITEMS
        "option(RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI"
        "ownerAcceptancePasswordUiEnabled()"
        "!defined(NDEBUG) || defined(RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI)"
        "snapshot.credentialCapabilities.standalonePassword"
        "sessionPassword_"
        "sessionPasswordConfirm_"
        "Local address: "
        "Connect to: "
        "snapshot.listenerReady && !snapshot.lanAddress.isEmpty()"
        "copy_->setEnabled(snapshot.listenerReady && !address.isEmpty())")
    string(FIND "${root_cmake}\n${window_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "owner-acceptance/release GUI gate lost required token: ${required_text}")
    endif()
endforeach()

string(FIND "${runtime_header}"
    "kStandalonePasswordProductCapabilityApproved = true" release_gate)
if(release_gate LESS 0)
    message(FATAL_ERROR
        "standalone-password product capability must be defined in runtime header")
endif()

string(FIND "${host_control_source}"
    "runtime_.configureStandaloneApplicationPassword(" production_forward)
string(FIND "${linux_host_source}"
    "standalonePasswordCredential_.configure(" production_owner)
if(production_forward LESS 0 OR production_owner LESS 0)
    message(FATAL_ERROR
        "acceptance UI must forward into the exact production standalone credential owner")
endif()

foreach(forbidden_text IN ITEMS
        "MockStandalone"
        "TestStandalone"
        "FakeStandalone")
    string(FIND "${window_source}\n${host_control_source}\n${linux_host_source}"
        "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "acceptance surface introduced test-only authentication: ${forbidden_text}")
    endif()
endforeach()
string(FIND "${entrypoint_source}" "startSharing(" startup_listener)
if(NOT startup_listener EQUAL -1)
    message(FATAL_ERROR
        "normal application startup must not invoke listener Start")
endif()

string(FIND "${window_source}" "void DesktopWindow::requestStart()" request_start_begin)
string(FIND "${window_source}" "void DesktopWindow::requestStop()" request_start_end)
if(request_start_begin LESS 0 OR request_start_end LESS 0 OR
   NOT request_start_begin LESS request_start_end)
    message(FATAL_ERROR "requestStart function boundary unavailable")
endif()
math(EXPR request_start_length "${request_start_end} - ${request_start_begin}")
string(SUBSTRING "${window_source}" ${request_start_begin}
    ${request_start_length} request_start_source)

string(FIND "${request_start_source}"
    "host_.configureStandalonePassword(" credential_step)
string(FIND "${request_start_source}"
    "host_.requestHostPermission(" permission_step)
string(FIND "${request_start_source}"
    "host_.start(currentHostRequest())" start_step)
if(credential_step LESS 0 OR permission_step LESS 0 OR start_step LESS 0 OR
   NOT credential_step LESS permission_step OR
   NOT permission_step LESS start_step)
    message(FATAL_ERROR
        "Sharing intent must orchestrate credential -> owner permission -> endpoint/listener")
endif()

message(STATUS
    "Owner acceptance is compile-time gated, production-backed and listener-authoritative")
