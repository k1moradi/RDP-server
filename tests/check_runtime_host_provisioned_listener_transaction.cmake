# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_LINUX_HOST_CONTROL_HEADER
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_GUI_HOST_CONTROL_SOURCE
        RDP_GUI_WINDOW_SOURCE
        RDP_ROOT_CMAKE)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_LINUX_HOST_CONTROL_HEADER}" host_header)
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_GUI_HOST_CONTROL_SOURCE}" gui_host_source)
file(READ "${RDP_GUI_WINDOW_SOURCE}" gui_window_source)
file(READ "${RDP_ROOT_CMAKE}" root_cmake)

foreach(required_text IN ITEMS
        "LinuxRuntimeSecurityConfiguration& securityConfiguration"
        "const RuntimeServerTlsContext& tlsContext"
        "const LinuxRuntimeAdmissionConfiguration& admissionConfiguration"
        "const RuntimeLicensingContext& licensingContext"
        "serviceCredentialsReady() const noexcept")
    string(FIND "${host_header}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "HostControl provisioning seam missing: ${required_text}")
    endif()
endforeach()

foreach(required_text IN ITEMS
        "RDP_SERVER_HAVE_LINUX_HOST_SECURITY=1"
        "target_link_libraries(rdp-server-linux-host-control PUBLIC"
        "rdp-server-linux-runtime-security")
    string(FIND "${root_cmake}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "HostControl production linkage missing: ${required_text}")
    endif()
endforeach()

set(ordered_tokens
    "if (!credentialsConfigured_ || !serviceCredentialsReady())"
    "if (!ownerSharingAuthority_.authorizes("
    "const auto current = assessRuntimeSelectedLanEndpoint("
    "const RuntimeTlsIdentityStatus unboundIdentity"
    "openLanListener({"
    "boundIdentity.boundIdentityMatchesGeneration("
    "deploymentPolicy_->configurePersonalDesktopPrivateLan("
    "listener_ = std::move(candidate);")
set(previous_position -1)
foreach(token IN LISTS ordered_tokens)
    string(FIND "${host_source}" "${token}" token_position)
    if(token_position LESS 0)
        message(FATAL_ERROR "HostControl transaction token missing: ${token}")
    endif()
    if(token_position LESS_EQUAL previous_position)
        message(FATAL_ERROR "HostControl transaction order regressed at: ${token}")
    endif()
    set(previous_position ${token_position})
endforeach()

string(FIND "${host_source}"
    "stage_ = RuntimeHostStage::ListenerAvailable;" publication_stage)
if(publication_stage LESS previous_position)
    message(FATAL_ERROR "Listener stage published before candidate ownership")
endif()

string(FIND "${gui_host_source}" "!snapshot.nativeDesktopReady"
    forbidden_adapter_gate)
if(NOT forbidden_adapter_gate EQUAL -1)
    message(FATAL_ERROR "Qt adapter still requires post-accept native owner before Start")
endif()
string(FIND "${gui_window_source}" "if (!state.captureInputReady)"
    forbidden_window_gate)
if(NOT forbidden_window_gate EQUAL -1)
    message(FATAL_ERROR "Desktop window still requires post-accept native owner before Start")
endif()
