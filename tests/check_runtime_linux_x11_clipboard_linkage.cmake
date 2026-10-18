# SPDX-License-Identifier: GPL-3.0-or-later
foreach(required_argument IN ITEMS RDP_ROOT_CMAKE RDP_RUNTIME_ENTRYPOINT_SOURCE)
    if(NOT DEFINED ${required_argument} OR "${${required_argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_argument}")
    endif()
endforeach()

file(READ "${RDP_ROOT_CMAKE}" root_cmake)
file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)

string(FIND "${root_cmake}"
    "# R8 production dependency readiness only." linkage_begin)
string(FIND "${root_cmake}"
    "RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD=1" linkage_end)
if(linkage_begin EQUAL -1 OR linkage_end EQUAL -1 OR
   NOT linkage_begin LESS linkage_end)
    message(FATAL_ERROR
        "R8 production clipboard dependency block is missing")
endif()

math(EXPR linkage_length "${linkage_end} - ${linkage_begin}")
string(SUBSTRING "${root_cmake}" ${linkage_begin} ${linkage_length}
    linkage_block)
foreach(required IN ITEMS
        "TARGET rdp-server-linux-runtime-security"
        "TARGET rdp-server-linux-x11-desktop"
        "TARGET rdp-server-linux-x11-clipboard"
        "TARGET rdp-server-r8-r3-clipboard"
        "target_link_libraries(rdp-server PRIVATE"
        "rdp-server-r8-r3-clipboard"
        "rdp-server-linux-x11-clipboard")
    string(FIND "${linkage_block}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R8 production target is missing clipboard dependency: ${required}")
    endif()
endforeach()

# Linkage is build readiness only. Until R10 owns one persistent post-Share
# complete-TPKT/TLS router and the same live X11/logind owner, main must not
# construct R8/native clipboard state or dispatch through the protected route.
foreach(forbidden IN ITEMS
        "X11ClipboardAdapter"
        "R3ClipboardTransferBridge"
        "visitPersonalDesktopClipboardChannel("
        "dispatchPersonalDesktopClipboardTpkt("
        "queuePersonalDesktopClipboardPdu("
        "pendingPersonalDesktopClipboardWrite("
        "completePersonalDesktopClipboardWrite("
        "publishCurrentRemoteOffer(")
    string(FIND "${runtime_source}" "${forbidden}" position)
    if(NOT position EQUAL -1)
        message(FATAL_ERROR
            "R8 clipboard runtime use is premature before persistent routing: ${forbidden}")
    endif()
endforeach()

message(STATUS
    "R8 bridge and X11 clipboard adapter are production-linked; live use remains fail-closed")
