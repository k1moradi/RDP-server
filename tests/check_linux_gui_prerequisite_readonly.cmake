# SPDX-License-Identifier: GPL-3.0-or-later
if(NOT DEFINED RDP_LINUX_PREREQUISITE_SOURCE)
    message(FATAL_ERROR "RDP_LINUX_PREREQUISITE_SOURCE is required")
endif()

file(READ "${RDP_LINUX_PREREQUISITE_SOURCE}" source)

foreach(required IN ITEMS
        "QProcessEnvironment::systemEnvironment"
        "QLibrary"
        "loginctl"
        "show-session"
        "QProcess::nullDevice"
        "kLogindTimeoutMilliseconds")
    string(FIND "${source}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "Linux prerequisite probe lost required read-only token: ${required}")
    endif()
endforeach()

foreach(forbidden IN ITEMS
        "xcb_connect"
        "X11DesktopResources"
        "X11InputController"
        "X11SharedMemoryCapture"
        "xcb_test_fake_input"
        "openLanListener"
        "startSharing("
        "requestHostPermission"
        "requestConsent")
    string(FIND "${source}" "${forbidden}" position)
    if(NOT position EQUAL -1)
        message(FATAL_ERROR
            "Linux prerequisite probe gained forbidden side-effect token: ${forbidden}")
    endif()
endforeach()
