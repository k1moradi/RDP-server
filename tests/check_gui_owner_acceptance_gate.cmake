# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_DESKTOP_WINDOW_SOURCE
        RDP_HOST_CONTROL_SOURCE
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_RUNTIME_HOST_CONTROL_HEADER
        RDP_DESKTOP_ENTRYPOINT_SOURCE
        RDP_ROOT_CMAKE
        RDP_CI_WORKFLOW)
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
file(READ "${RDP_CI_WORKFLOW}" ci_workflow)

foreach(required_text IN ITEMS
        "option(RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI"
        "ownerAcceptancePasswordUiEnabled()"
        "!defined(NDEBUG) || defined(RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI)"
        "snapshot.credentialCapabilities.standalonePassword"
        "standalonePasswordConfigurationAvailable"
        "snapshot.credentialEditingAllowed"
        "standaloneVisible && snapshot.credentialEditingAllowed"
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
    "runtimeProductCredentialEditingAllowed(" editability_policy)
if(editability_policy LESS 0)
    message(FATAL_ERROR
        "R10 product status must own credential editability lifecycle semantics")
endif()

string(FIND "${runtime_header}"
    "kStandalonePasswordProductCapabilityApproved = false" release_gate)
if(release_gate LESS 0)
    message(FATAL_ERROR
        "public standalone-password product capability must remain false before real Microsoft-client qualification")
endif()
string(FIND "${runtime_header}"
    "kStandalonePasswordProductCapabilityApproved = true" premature_release_gate)
if(NOT premature_release_gate EQUAL -1)
    message(FATAL_ERROR
        "owner acceptance must not promote the public Release standalone-password capability")
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
    "const HostStatus permissionSnapshot = host_.status();" permission_refresh_step)
string(FIND "${request_start_source}"
    "host_.requestHostPermission(" permission_step)
string(FIND "${request_start_source}"
    "host_.start(currentHostRequest())" start_step)
if(credential_step LESS 0 OR permission_refresh_step LESS 0 OR
   permission_step LESS 0 OR start_step LESS 0 OR
   NOT credential_step LESS permission_refresh_step OR
   NOT permission_refresh_step LESS permission_step OR
   NOT permission_step LESS start_step)
    message(FATAL_ERROR
        "Sharing intent must orchestrate credential -> authoritative permission refresh -> owner permission -> endpoint/listener")
endif()


# Public packaging and owner acceptance are different intents. Pin both so an
# owner candidate cannot accidentally inherit public Release semantics, and a
# public archive cannot accidentally inherit the prequalification surface.
string(FIND "${ci_workflow}" "  r7-macos-portable-gui:" mac_public_begin)
string(FIND "${ci_workflow}"
    "      - name: R6 verify explicit owner-acceptance UI parity on macOS"
    mac_acceptance_begin)
string(FIND "${ci_workflow}" "  r7-macos-session-sanitizers:" mac_public_end)
string(FIND "${ci_workflow}" "  r5-linux-gui-zip:" linux_public_begin)
string(FIND "${ci_workflow}"
    "  r9-portable-gui-bootstrap-acceptance:" linux_acceptance_begin)
if(mac_public_begin LESS 0 OR mac_acceptance_begin LESS 0 OR
   mac_public_end LESS 0 OR linux_public_begin LESS 0 OR
   linux_acceptance_begin LESS 0 OR
   NOT mac_public_begin LESS mac_acceptance_begin OR
   NOT mac_acceptance_begin LESS mac_public_end OR
   NOT linux_public_begin LESS linux_acceptance_begin)
    message(FATAL_ERROR "owner-acceptance packaging job boundaries unavailable")
endif()

math(EXPR mac_public_length
    "${mac_acceptance_begin} - ${mac_public_begin}")
string(SUBSTRING "${ci_workflow}" ${mac_public_begin}
    ${mac_public_length} mac_public_source)
math(EXPR mac_acceptance_length
    "${mac_public_end} - ${mac_acceptance_begin}")
string(SUBSTRING "${ci_workflow}" ${mac_acceptance_begin}
    ${mac_acceptance_length} mac_acceptance_source)
math(EXPR linux_public_length
    "${linux_acceptance_begin} - ${linux_public_begin}")
string(SUBSTRING "${ci_workflow}" ${linux_public_begin}
    ${linux_public_length} linux_public_source)
string(SUBSTRING "${ci_workflow}" ${linux_acceptance_begin}
    -1 linux_acceptance_source)

foreach(public_source IN ITEMS mac_public_source linux_public_source)
    string(FIND "${${public_source}}"
        "-DCMAKE_BUILD_TYPE=Release" public_release)
    string(FIND "${${public_source}}"
        "-DRDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=OFF" public_acceptance_off)
    string(FIND "${${public_source}}"
        "-DRDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=ON" public_acceptance_on)
    if(public_release LESS 0 OR public_acceptance_off LESS 0 OR
       NOT public_acceptance_on EQUAL -1)
        message(FATAL_ERROR
            "public Linux/macOS GUI packaging must be explicit Release + owner-acceptance OFF")
    endif()
endforeach()

foreach(acceptance_source IN ITEMS mac_acceptance_source linux_acceptance_source)
    string(FIND "${${acceptance_source}}"
        "-DCMAKE_BUILD_TYPE=Release" acceptance_release)
    string(FIND "${${acceptance_source}}"
        "-DRDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=ON" acceptance_on)
    string(FIND "${${acceptance_source}}"
        "gui.offscreen-owner-acceptance-editor-properties"
        acceptance_property_test)
    if(acceptance_release LESS 0 OR acceptance_on LESS 0 OR
       acceptance_property_test LESS 0)
        message(FATAL_ERROR
            "Linux/macOS owner acceptance must use explicit Release + acceptance UI and run the editor-property regression")
    endif()
endforeach()

message(STATUS
    "Owner acceptance is compile-time gated, cross-platform build-parity checked, production-backed and listener-authoritative")
