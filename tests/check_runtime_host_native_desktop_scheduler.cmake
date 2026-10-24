# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

foreach(required_var IN ITEMS
        RDP_LINUX_HOST_CONTROL_HEADER
        RDP_LINUX_HOST_CONTROL_SOURCE
        RDP_X11_DESKTOP_SOURCE
        RDP_ROOT_CMAKE)
    if(NOT DEFINED ${required_var})
        message(FATAL_ERROR "missing ${required_var}")
    endif()
endforeach()

file(READ "${RDP_LINUX_HOST_CONTROL_HEADER}" host_header)
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
file(READ "${RDP_X11_DESKTOP_SOURCE}" x11_desktop_source)
file(READ "${RDP_ROOT_CMAKE}" root_cmake)

foreach(required_text IN ITEMS
        "std::unique_ptr<LinuxHostNativeDesktopState> nativeDesktop_"
        "RuntimeHostResult initializeNativeDesktop() noexcept"
        "RuntimeHostResult serviceNativeDesktopOnce() noexcept"
        "void retireNativeDesktop() noexcept")
    string(FIND "${host_header}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "R10X HostControl lifetime missing: ${required_text}")
    endif()
endforeach()

foreach(required_text IN ITEMS
        "selection.display()"
        "visitNativeDesktopSelection("
        "candidate->admissionGeneration"
        "candidate->sessionGeneration"
        "snapshot.nativeDesktopReady ="
        "snapshot.nativeDesktopInitializing ="
        "dispatchAuthenticatedSlowPathTpkt(")
    string(FIND "${host_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "R10X R2-selected owner missing: ${required_text}")
    endif()
endforeach()

string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::serviceNativeDesktopOnce() noexcept"
    service_begin)
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::clearAcceptedClient() noexcept"
    service_end)
if(service_begin LESS 0 OR service_end LESS_EQUAL service_begin)
    message(FATAL_ERROR "unable to isolate bounded R10X post-Share service")
endif()
math(EXPR service_length "${service_end} - ${service_begin}")
string(SUBSTRING "${host_source}" ${service_begin} ${service_length}
    service_source)

foreach(required_text IN ITEMS
        "authorizePersonalDesktopApplicationTraffic("
        "registerNativeChange()"
        "::poll("
        "pollDescriptors.size()), 0)"
        "unregisterNativeChange("
        "dispatchNativeChangeReady("
        "releaseNativeChangeWithoutDispatch("
        "kHostX11EventBudget"
        "processEvents("
        "advancePersonalDesktopPostShareApplicationRead("
        "advancePersonalDesktopGraphicsDynamicVirtualChannel("
        "beginPersonalDesktopGraphicsSurfaceReconfiguration("
        "preflightPersonalDesktopGraphicsFramePublication("
        "nativeGeometryIsCurrent("
        "consumeR4Frame("
        "const bool terminalTransportEvent ="
        "(socketEvents & POLLNVAL)")
    string(FIND "${service_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "R10X bounded production step missing: ${required_text}")
    endif()
endforeach()

foreach(forbidden_text IN ITEMS
        "runSerializedLinuxCandidate("
        "pollNonblockingTcpAcceptBatch("
        "std::this_thread::sleep"
        "QEventLoop")
    string(FIND "${service_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR "R10X introduced blocking/duplicate owner: ${forbidden_text}")
    endif()
endforeach()

string(FIND "${service_source}"
    "(socketEvents & (POLLERR | POLLNVAL))" preemptive_pollerr)
if(NOT preemptive_pollerr EQUAL -1)
    message(FATAL_ERROR
        "R10X must let R1 classify POLLERR/POLLHUP instead of pre-cancelling")
endif()

string(FIND "${host_source}" "case Kind::ClipboardStaticChannel:" clipboard_case)
string(FIND "${host_source}" "dispatchAuthenticatedTpkt(" clipboard_dispatch)
if(clipboard_case LESS 0 OR clipboard_dispatch LESS clipboard_case)
    message(FATAL_ERROR
        "R10X clipboard route must remain behind the shared dormant R8 owner")
endif()

string(FIND "${service_source}"
    "nativeChange->admissionGeneration !=" admission_generation)
string(FIND "${service_source}"
    "nativeChange->sessionGeneration !=" session_generation)
string(FIND "${service_source}" "processEvents(" x11_events)
string(FIND "${service_source}" "consumeR4Frame(" frame_borrow)
if(admission_generation LESS 0 OR session_generation LESS 0 OR
   x11_events LESS 0 OR frame_borrow LESS 0 OR
   NOT admission_generation LESS x11_events OR
   NOT session_generation LESS x11_events OR
   NOT x11_events LESS frame_borrow)
    message(FATAL_ERROR "R10X stale native generation fence is misordered")
endif()

string(FIND "${service_source}" "observeNativeGeometry(" geometry_observe)
string(FIND "${service_source}" "nativeGeometryIsCurrent(" geometry_first)
string(FIND "${service_source}"
    "beginPersonalDesktopGraphicsSurfaceReconfiguration(" remap)
string(FIND "${service_source}"
    "preflightPersonalDesktopGraphicsFramePublication(" preflight)
string(FIND "${service_source}" "nativeGeometryIsCurrent(" geometry_last REVERSE)
if(geometry_observe LESS 0 OR geometry_first LESS 0 OR remap LESS 0 OR
   preflight LESS 0 OR geometry_last LESS 0 OR
   NOT geometry_observe LESS geometry_first OR
   NOT geometry_first LESS remap OR
   NOT remap LESS preflight OR
   NOT preflight LESS geometry_last OR
   NOT geometry_last LESS frame_borrow)
    message(FATAL_ERROR "R10X RandR/remap/frame freshness order regressed")
endif()

# Ordinary Stop must destroy the complete R5 owner. Terminal desktop
# retirement suppresses native input cleanup and removes the XTEST controller,
# capture/damage/framebuffer resources and XCB owner before replacement.
string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireNativeDesktop() noexcept"
    retire_native_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::initializeNativeDesktop() noexcept"
    retire_native_end)
if(retire_native_begin LESS 0 OR retire_native_end LESS_EQUAL retire_native_begin)
    message(FATAL_ERROR "unable to isolate R5 native desktop retirement")
endif()
math(EXPR retire_native_length
    "${retire_native_end} - ${retire_native_begin}")
string(SUBSTRING "${host_source}" ${retire_native_begin}
    ${retire_native_length} retire_native_source)
foreach(required_text IN ITEMS
        "desktop->retireAfterAuthorizationLoss()"
        "nativeDesktop_.reset()")
    string(FIND "${retire_native_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "R5 Stop must terminally destroy native owner state: ${required_text}")
    endif()
endforeach()

string(FIND "${x11_desktop_source}"
    "X11DesktopResources::retireAfterAuthorizationLoss() noexcept"
    x11_retire_begin)
string(FIND "${x11_desktop_source}"
    "X11DesktopResources::fail(" x11_retire_end)
if(x11_retire_begin LESS 0 OR x11_retire_end LESS_EQUAL x11_retire_begin)
    message(FATAL_ERROR "unable to isolate X11 authorization-loss retirement")
endif()
math(EXPR x11_retire_length "${x11_retire_end} - ${x11_retire_begin}")
string(SUBSTRING "${x11_desktop_source}" ${x11_retire_begin}
    ${x11_retire_length} x11_retire_source)
string(FIND "${x11_retire_source}"
    "cancelNativeResources(InputRetirementMode::SuppressNativeInput)"
    suppress_native_input)
if(suppress_native_input LESS 0)
    message(FATAL_ERROR
        "authorization loss must suppress XTEST cleanup before owner destruction")
endif()

string(FIND "${x11_desktop_source}"
    "X11DesktopResources::cancelGeometryBoundResources("
    cancel_geometry_begin)
string(FIND "${x11_desktop_source}"
    "X11DesktopResources::rebuildGeometryBoundResources("
    cancel_geometry_end)
if(cancel_geometry_begin LESS 0 OR
   cancel_geometry_end LESS_EQUAL cancel_geometry_begin)
    message(FATAL_ERROR "unable to isolate geometry-bound R5 teardown")
endif()
math(EXPR cancel_geometry_length
    "${cancel_geometry_end} - ${cancel_geometry_begin}")
string(SUBSTRING "${x11_desktop_source}" ${cancel_geometry_begin}
    ${cancel_geometry_length} cancel_geometry_source)
set(native_child_retirement_tokens
    "input_->retireWithoutNativeInput()"
    "input_.reset()"
    "damage_.reset()"
    "capture_.reset()")
set(previous -1)
foreach(token IN LISTS native_child_retirement_tokens)
    string(FIND "${cancel_geometry_source}" "${token}" position)
    if(position LESS 0 OR position LESS_EQUAL previous)
        message(FATAL_ERROR
            "R5 native input/capture retirement order regressed at: ${token}")
    endif()
    set(previous ${position})
endforeach()

# Fresh X11 ownership remains post-authentication only.
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::initializeNativeDesktop() noexcept"
    initialize_native_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::serviceNativeDesktopOnce() noexcept"
    initialize_native_end)
math(EXPR initialize_native_length
    "${initialize_native_end} - ${initialize_native_begin}")
string(SUBSTRING "${host_source}" ${initialize_native_begin}
    ${initialize_native_length} initialize_native_source)
foreach(required_text IN ITEMS
        "acceptedClient_ == nullptr"
        "acceptedClientPhase_ != AcceptedClientPhase::GraphicsReady"
        "nativeDesktop_ != nullptr"
        "visitNativeDesktopSelection("
        "candidate->admissionGeneration == 0U"
        "candidate->sessionGeneration == 0U"
        "nativeDesktop_ = std::move(candidate)")
    string(FIND "${initialize_native_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "fresh post-authentication R5 construction gate missing: ${required_text}")
    endif()
endforeach()

string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireAcceptedClient(" retire_client_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::pollAcceptedClientReadiness()"
    retire_client_end)
if(retire_client_begin LESS 0 OR retire_client_end LESS_EQUAL retire_client_begin)
    message(FATAL_ERROR "unable to isolate listener-preserving client retirement")
endif()
math(EXPR retire_client_length
    "${retire_client_end} - ${retire_client_begin}")
string(SUBSTRING "${host_source}" ${retire_client_begin}
    ${retire_client_length} retire_client_source)
string(FIND "${retire_client_source}" "retireNativeDesktop()" native_retire)
string(FIND "${retire_client_source}" "acceptedClient_->revoke()" client_revoke)
string(FIND "${retire_client_source}" "listener_.close()" disconnect_close)
if(native_retire LESS 0 OR client_revoke LESS 0 OR
   NOT native_retire LESS client_revoke OR NOT disconnect_close EQUAL -1)
    message(FATAL_ERROR "disconnect must retire native/client and preserve listener")
endif()

string(FIND "${host_source}"
    "void LinuxRuntimeHostControl::retireStoppedRuntime(" stop_begin)
string(FIND "${host_source}"
    "RuntimeHostResult LinuxRuntimeHostControl::stopSharing()" stop_end)
if(stop_begin LESS 0 OR stop_end LESS_EQUAL stop_begin)
    message(FATAL_ERROR "unable to isolate Stop/Revoke retirement")
endif()
math(EXPR stop_length "${stop_end} - ${stop_begin}")
string(SUBSTRING "${host_source}" ${stop_begin} ${stop_length} stop_source)
set(stop_tokens
    "ownerSharingAuthority_.revoke(reason)"
    "retireNativeDesktop()"
    "acceptedClient_->revoke()"
    "listener_.close()")
set(previous -1)
foreach(token IN LISTS stop_tokens)
    string(FIND "${stop_source}" "${token}" position)
    if(position LESS 0 OR position LESS_EQUAL previous)
        message(FATAL_ERROR "R10X Stop order regressed at: ${token}")
    endif()
    set(previous ${position})
endforeach()

foreach(required_build_text IN ITEMS
        "rdp-server-linux-x11-desktop"
        "RDP_SERVER_HAVE_LINUX_X11_DESKTOP=1"
        "rdp-server-linux-x11-authorized-input"
        "RDP_SERVER_HAVE_LINUX_X11_AUTHORIZED_INPUT=1")
    string(FIND "${root_cmake}" "${required_build_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR "R10X HostControl build edge missing: ${required_build_text}")
    endif()
endforeach()

message(STATUS
    "R10X HostControl: one R2-selected X11 owner, zero-wait bounded post-Share service, ordered retirement")
