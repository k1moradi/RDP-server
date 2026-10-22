# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

if(NOT DEFINED RDP_MAC_INPUT_CONTROLLER_SOURCE)
    message(FATAL_ERROR "RDP_MAC_INPUT_CONTROLLER_SOURCE is required")
endif()

file(READ "${RDP_MAC_INPUT_CONTROLLER_SOURCE}" source)

foreach(required IN ITEMS
        "AXIsProcessTrustedWithOptions(nullptr)"
        "CGPreflightListenEventAccess()"
        "accessibilityTrusted && inputMonitoringTrusted")
    string(FIND "${source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
            "missing macOS native input readiness fragment: ${required}")
    endif()
endforeach()

foreach(forbidden IN ITEMS
        "CGRequestListenEventAccess"
        "kAXTrustedCheckOptionPrompt")
    string(FIND "${source}" "${forbidden}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "native input readiness must remain non-prompting: ${forbidden}")
    endif()
endforeach()
