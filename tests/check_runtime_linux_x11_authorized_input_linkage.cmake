# SPDX-License-Identifier: GPL-3.0-or-later
foreach(required_argument IN ITEMS RDP_ROOT_CMAKE RDP_RUNTIME_ENTRYPOINT_SOURCE)
    if(NOT DEFINED ${required_argument} OR "${${required_argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_argument}")
    endif()
endforeach()

file(READ "${RDP_ROOT_CMAKE}" root_cmake)
file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)

foreach(required IN ITEMS
        "TARGET rdp-server-linux-x11-authorized-input"
        "target_link_libraries(rdp-server PRIVATE"
        "rdp-server-linux-x11-authorized-input"
        "RDP_SERVER_HAVE_LINUX_X11_AUTHORIZED_INPUT=1")
    string(FIND "${root_cmake}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R10 production target is missing landed R5 input dependency: ${required}")
    endif()
endforeach()

# Linkage is not dispatch authority. Until R10 owns the single post-Share R1
# complete-TPKT router, calling the native bridge from main would misroute
# Graphics/clipboard traffic or create a second reader.
string(FIND "${runtime_source}"
    "dispatchAuthenticatedSlowPathTpkt" dispatch_position)
if(NOT dispatch_position EQUAL -1)
    message(FATAL_ERROR
        "R10 must not dispatch native input before post-Share TPKT routing exists")
endif()

message(STATUS
    "R10 production server links the protected R5 input bridge; dispatch remains fail-closed")
