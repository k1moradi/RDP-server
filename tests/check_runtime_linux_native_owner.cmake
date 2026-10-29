# SPDX-License-Identifier: GPL-3.0-or-later
foreach(required_argument IN ITEMS
        RDP_RUNTIME_ENTRYPOINT_SOURCE
        RDP_ROOT_CMAKE)
    if(NOT DEFINED ${required_argument} OR "${${required_argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_argument}")
    endif()
endforeach()

file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)
file(READ "${RDP_ROOT_CMAKE}" root_cmake)

foreach(required_runtime_text IN ITEMS
        "LinuxAuthorizedX11DesktopOwner"
        "selection.display()"
        "visitNativeDesktopSelection"
        "registerNativeChange"
        "::poll("
        "nativePoll.data(), static_cast<nfds_t>(nativePoll.size())"
        "unregisterNativeChange"
        "dispatchNativeChangeReady"
        "retireAfterAuthorizationLoss"
        "releaseNativeChangeWithoutDispatch"
        "nativeOwner.desktop->retireAfterAuthorizationLoss()")
    string(FIND "${runtime_source}" "${required_runtime_text}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R10 native owner composition is missing: ${required_runtime_text}")
    endif()
endforeach()

foreach(required_build_text IN ITEMS
        "TARGET rdp-server-linux-x11-desktop"
        "rdp-server-linux-x11-desktop"
        "RDP_SERVER_HAVE_LINUX_X11_DESKTOP=1")
    string(FIND "${root_cmake}" "${required_build_text}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "Production runtime is not conditionally linked to R5: ${required_build_text}")
    endif()
endforeach()

# Native construction is permitted only after the production Graphics path
# is ready and the exact R2 lease/application authority has been revalidated.
string(FIND "${runtime_source}"
    "if (!graphicsControlReady || !connection.hasAdmissionLease()" authority_gate)
string(FIND "${runtime_source}"
    "LinuxAuthorizedX11DesktopOwner nativeOwner{}" native_owner_construct)
string(FIND "${runtime_source}"
    "visitNativeDesktopSelection(" native_owner_visit)
if(authority_gate EQUAL -1 OR native_owner_construct EQUAL -1 OR
   native_owner_visit EQUAL -1 OR
   NOT authority_gate LESS native_owner_construct OR
   NOT native_owner_construct LESS native_owner_visit)
    message(FATAL_ERROR
        "R4/R5 native framebuffer owner must remain downstream of Graphics readiness and R2 authority")
endif()

# The native poll may be wrapped across lines; both the syscall and its
# exact existing pollfd array are mandatory (no second hidden poll owner).
string(FIND "${runtime_source}" "::poll(" system_poll)
string(FIND "${runtime_source}"
    "nativePoll.data(), static_cast<nfds_t>(nativePoll.size())" native_poll_array)
if(system_poll EQUAL -1 OR native_poll_array EQUAL -1 OR
   system_poll GREATER native_poll_array)
    message(FATAL_ERROR
        "R10 must use the real borrowed native pollfd array")
endif()

string(FIND "${runtime_source}"
    "startPersonalDesktopGraphicsFramePublication" frame_publication)
if(NOT frame_publication EQUAL -1)
    message(FATAL_ERROR
        "Native-owner increment must not fabricate R4/R3 frame publication")
endif()
