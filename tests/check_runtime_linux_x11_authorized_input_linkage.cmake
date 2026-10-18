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

# The live R10 dispatch is guarded by the R2/R3 single-TPKT classifier,
# explicit route-kind switch and R5's protected event-by-event gateway.
foreach(required IN ITEMS
        "advancePersonalDesktopPostShareApplicationRead"
        "RdpPostShareTpktRouteKind"
        "Kind::SlowPathInput"
        "dispatchAuthenticatedSlowPathTpkt")
    string(FIND "${runtime_source}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R10 lacks authenticated classified input dispatch: ${required}")
    endif()
endforeach()

message(STATUS
    "R10 routes authenticated slow-path input through the sole R1 reader/R5 bridge")
