# SPDX-License-Identifier: GPL-3.0-or-later
if(NOT DEFINED RDP_RUNTIME_ENTRYPOINT_SOURCE OR
   RDP_RUNTIME_ENTRYPOINT_SOURCE STREQUAL "")
    message(FATAL_ERROR "Missing RDP_RUNTIME_ENTRYPOINT_SOURCE")
endif()

file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)

foreach(required_text IN ITEMS
        "startPersonalDesktopGraphicsDynamicVirtualChannel"
        "advancePersonalDesktopGraphicsDynamicVirtualChannel"
        "GraphicsStep::Ready"
        "authorizePersonalDesktopApplicationTraffic"
        "DRDYNVC capabilities, Graphics CREATE and RDPGFX CAPS are now composed"
        "LinuxAuthorizedX11DesktopOwner"
        "visitNativeDesktopSelection")
    string(FIND "${runtime_source}" "${required_text}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R10 serve loop is missing required post-Share Graphics control composition: ${required_text}")
    endif()
endforeach()

string(FIND "${runtime_source}"
    "startPersonalDesktopClearCodecFramePublication" frame_publication)
string(FIND "${runtime_source}"
    "visitNativeDesktopSelection" native_selection)
if(frame_publication EQUAL -1 OR
   native_selection EQUAL -1 OR
   frame_publication LESS native_selection)
    message(FATAL_ERROR
        "R10 must publish only after R2-selected X11 owner composition")
endif()

# R10 may now hand off to the genuine R2-selected native owner before
# retirement. This guard still forbids frame publication; the dedicated
# native-owner composition CTest owns the later poll/revocation details.
