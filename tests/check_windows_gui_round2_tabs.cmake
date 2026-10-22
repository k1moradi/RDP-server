# SPDX-License-Identifier: GPL-3.0-or-later
if(NOT DEFINED RDP_WINDOWS_GUI_SOURCE)
    message(FATAL_ERROR "RDP_WINDOWS_GUI_SOURCE is required")
endif()

file(READ "${RDP_WINDOWS_GUI_SOURCE}" windows_gui_source)

foreach(required_text IN ITEMS
        "#include <QTabWidget>"
        "window.findChild<QTabWidget*>(\"settingsTabs\")"
        "window.findChildren<QStackedWidget*>()"
        "tabs->isAncestorOf(stack)"
        "tabs->count() != 2"
        "unexpectedStack")
    string(FIND "${windows_gui_source}" "${required_text}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
            "Windows Round 2 offline verifier missing: ${required_text}")
    endif()
endforeach()

foreach(forbidden_text IN ITEMS
        "auto* wizard = window.findChild<QStackedWidget*>();"
        "confirmationField || wizard ||")
    string(FIND "${windows_gui_source}" "${forbidden_text}" found)
    if(NOT found EQUAL -1)
        message(FATAL_ERROR
            "Windows offline verifier still rejects Qt's internal tab stack: ${forbidden_text}")
    endif()
endforeach()
