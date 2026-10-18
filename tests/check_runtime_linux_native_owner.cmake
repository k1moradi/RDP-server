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
        "::poll(nativePoll.data()"
        "unregisterNativeChange"
        "dispatchNativeChangeReady"
        "retireAfterAuthorizationLoss"
        "nativeOwner.desktop->disconnect()")
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

string(FIND "${runtime_source}"
    "startPersonalDesktopGraphicsFramePublication" frame_publication)
if(NOT frame_publication EQUAL -1)
    message(FATAL_ERROR
        "Native-owner increment must not fabricate R4/R3 frame publication")
endif()
