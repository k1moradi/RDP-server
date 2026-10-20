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

# R8 is prepared in the production runtime but remains hard-disabled until the
# first real Windows App video/input/Stop acceptance is recorded. The prepared
# route must use the existing R2/R3 gateways, the one X11 owner and the sole R1
# TLS writer; first clipboard acceptance is Unicode text only.
foreach(required IN ITEMS
        "kLinuxProductionClipboardActivationApproved = false"
        "LinuxPreparedClipboardOwner"
        "PresentationScope::UnicodeTextOnly"
        "dispatchPersonalDesktopClipboardTpkt("
        "queuePersonalDesktopClipboardPdu("
        "advancePersonalDesktopClipboardTlsWrite("
        "recordAcceptedWriteReceipt("
        "processEvents(")
    string(FIND "${runtime_source}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R8 prepared production route is missing: ${required}")
    endif()
endforeach()

foreach(forbidden IN ITEMS
        "publishCompletedFile("
        "publishCompletedFiles("
        "beginFileSizeRequest("
        "beginFileRangeRequest("
        "PasteKind::Png")
    string(FIND "${runtime_source}" "${forbidden}" position)
    if(NOT position EQUAL -1)
        message(FATAL_ERROR
            "R8 first-acceptance runtime must remain text-only: ${forbidden}")
    endif()
endforeach()

message(STATUS
    "R8 production route is prepared, Unicode-text-only and activation-gated off")
