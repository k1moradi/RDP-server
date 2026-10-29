# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_LINUX_HOST_CONTROL_HEADER
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_GUI_MAIN_SOURCE)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_LINUX_HOST_CONTROL_HEADER}" host_header)
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_GUI_MAIN_SOURCE}" gui_main)

foreach(required_text IN ITEMS
        "RuntimeHostResult serviceOnce() noexcept"
        "serviceAcceptedClientPreAdmissionOnce()"
        "RuntimeAcceptedClientPreauthServiceTiming acceptedToTls{}"
        "std::unique_ptr<LinuxRuntimeConnection> acceptedClient_"
        "AuthenticationAttemptLimiter authAttempts_"
        "GraphicsReady,")
    string(FIND "${host_header}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "accepted-client HostControl owner missing: ${required_text}")
    endif()
endforeach()

string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::acceptClientOnce("
    scheduler_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::serviceOnce() noexcept"
    scheduler_end)
if(scheduler_begin LESS 0 OR scheduler_end LESS_EQUAL scheduler_begin)
    message(FATAL_ERROR "unable to isolate accepted-client scheduler")
endif()
math(EXPR scheduler_length "${scheduler_end} - ${scheduler_begin}")
string(SUBSTRING "${host_source}" ${scheduler_begin}
    ${scheduler_length} scheduler_source)

set(ordered_tokens
    "acceptNonblockingTcpConnection(listener_.nativeSocket())"
    "permitsPrivateLanTransportCandidate(peerAddress)"
    "reservePeerAuthenticationAttempt(peerAddress, now)"
    "std::make_unique<LinuxRuntimeConnection>"
    "&ownerSharingAuthority_"
    "stage_ = RuntimeHostStage::ClientAuthenticating"
    "advancePreAdmission("
    "case Step::CredentialsVerified:"
    "acceptedClient_->issueAdmission(*request)"
    "acceptedClientPhase_ = AcceptedClientPhase::McsConnectInitial"
    "advancePostAdmissionMcsConnectInitial("
    "advancePostAdmissionMcsClientInfo("
    "advancePersonalDesktopClientLicensingIntake("
    "startPersonalDesktopShareActivation("
    "stage_ = RuntimeHostStage::ShareActivated"
    "startPersonalDesktopGraphicsDynamicVirtualChannel("
    "advancePersonalDesktopGraphicsDynamicVirtualChannel("
    "acceptedClientPhase_ = AcceptedClientPhase::GraphicsReady")
set(previous_position -1)
foreach(token IN LISTS ordered_tokens)
    string(FIND "${scheduler_source}" "${token}" token_position)
    if(token_position LESS 0)
        message(FATAL_ERROR "accepted-client scheduler token missing: ${token}")
    endif()
    if(token_position LESS_EQUAL previous_position)
        message(FATAL_ERROR "accepted-client scheduler order regressed at: ${token}")
    endif()
    set(previous_position ${token_position})
endforeach()

foreach(required_text IN ITEMS
        "pollSocketReadinessOnce("
        "std::chrono::milliseconds{0}"
        "serviceAcceptedClientPreAdmissionOnce()"
        "preAdmissionNativeMaintenanceRequired()"
        "validateRuntimeOwnerOnce()"
        "if (result.succeeded() && result.retryable"
        "result = pollAcceptedClientReadiness()"
        "preAdmissionTransportActive || listener_.interfaceStillMatches()"
        "if (!listener_.interfaceStillMatches())"
        "ownerSharingAuthority_.authorizes("
        "authorizePersonalDesktopApplicationTraffic("
        "snapshot.graphicsReady ="
        "acceptedClientPhase_ == AcceptedClientPhase::GraphicsReady")
    string(FIND "${host_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "bounded scheduler safety gate missing: ${required_text}")
    endif()
endforeach()

string(FIND "${host_source}"
    "LinuxRuntimeHostControl::serviceAcceptedClientPreAdmissionOnce() noexcept"
    preauth_service_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::advanceAcceptedClientOnce() noexcept"
    preauth_service_end)
if(preauth_service_begin LESS 0 OR
   preauth_service_end LESS_EQUAL preauth_service_begin)
    message(FATAL_ERROR "unable to isolate pre-auth no-starvation scheduler")
endif()
math(EXPR preauth_service_length
    "${preauth_service_end} - ${preauth_service_begin}")
string(SUBSTRING "${host_source}" ${preauth_service_begin}
    ${preauth_service_length} preauth_service_source)
set(preauth_ordered_tokens
    "RuntimeHostResult result = advanceAcceptedClientOnce()"
    "if (result.succeeded() && result.retryable"
    "preAdmissionNativeMaintenanceRequired()"
    "const RuntimeHostResult owner = validateRuntimeOwnerOnce()"
    "result = pollAcceptedClientReadiness()")
set(previous_position -1)
foreach(token IN LISTS preauth_ordered_tokens)
    string(FIND "${preauth_service_source}" "${token}" token_position)
    if(token_position LESS 0 OR token_position LESS_EQUAL previous_position)
        message(FATAL_ERROR
            "pre-auth scheduling order regressed at: ${token}")
    endif()
    set(previous_position ${token_position})
endforeach()

foreach(forbidden_text IN ITEMS
        "pollNonblockingTcpAcceptBatch("
        "runSerializedLinuxCandidate("
        "std::thread")
    string(FIND "${host_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "HostControl introduced forbidden scheduler owner: ${forbidden_text}")
    endif()
endforeach()

string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireStoppedRuntime(" retire_start)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::stopSharing()" retire_end)
if(retire_start LESS 0 OR retire_end LESS_EQUAL retire_start)
    message(FATAL_ERROR "unable to isolate HostControl retirement")
endif()
math(EXPR retire_length "${retire_end} - ${retire_start}")
string(SUBSTRING "${host_source}" ${retire_start} ${retire_length} retire_source)
set(retire_tokens
    "ownerSharingAuthority_.revoke(reason)"
    "retireNativeDesktop()"
    "acceptedClient_->revoke()"
    "listener_.close()")
set(previous_position -1)
foreach(token IN LISTS retire_tokens)
    string(FIND "${retire_source}" "${token}" token_position)
    if(token_position LESS 0 OR token_position LESS_EQUAL previous_position)
        message(FATAL_ERROR "Stop/Revoke retirement order regressed at: ${token}")
    endif()
    set(previous_position ${token_position})
endforeach()

foreach(required_text IN ITEMS
        "QTimer runtimeServiceTimer"
        "kLinuxRuntimeServiceWaitMilliseconds"
        "runtimeServiceTimer.setSingleShot(true)"
        "serviceLinuxRuntimeBoundedBurst("
        "burst.immediateReschedule"
        "runtime.serviceOnce()"
        "QTimer statusRefreshTimer"
        "statusRefreshTimer.setInterval(250)"
        "window.refresh()")
    string(FIND "${gui_main}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "Qt owner-thread service tick missing: ${required_text}")
    endif()
endforeach()

foreach(forbidden_text IN ITEMS
        "runSerializedLinuxCandidate"
        "std::thread")
    string(FIND "${gui_main}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "GUI introduced duplicate runtime owner: ${forbidden_text}")
    endif()
endforeach()
