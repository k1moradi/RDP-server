# SPDX-License-Identifier: GPL-3.0-or-later
if(NOT DEFINED RDP_DESKTOP_WINDOW_HEADER OR
   NOT DEFINED RDP_DESKTOP_WINDOW_SOURCE)
    message(FATAL_ERROR
        "RDP_DESKTOP_WINDOW_HEADER and RDP_DESKTOP_WINDOW_SOURCE are required")
endif()

file(READ "${RDP_DESKTOP_WINDOW_HEADER}" desktop_window_header)
file(READ "${RDP_DESKTOP_WINDOW_SOURCE}" desktop_window_source)
set(combined_source "${desktop_window_header}\n${desktop_window_source}")

foreach(required_token IN ITEMS
        "QTabWidget* tabs_"
        "QWidget* mainTab_"
        "QWidget* advancedTab_"
        "tabs_->setObjectName(\"settingsTabs\")"
        "mainTab_->setObjectName(\"mainTab\")"
        "advancedTab_->setObjectName(\"advancedTab\")"
        "tabs_->addTab(mainTab_, QStringLiteral(\"Main\"))"
        "tabs_->addTab(advancedTab_, QStringLiteral(\"Advanced\"))")
    string(FIND "${combined_source}" "${required_token}" token_position)
    if(token_position EQUAL -1)
        message(FATAL_ERROR
            "GUI Round 2 tab contract missing token: ${required_token}")
    endif()
endforeach()

foreach(forbidden_token IN ITEMS
        "advancedDisclosure"
        "advancedPanel"
        "advancedToggle_"
        "setAdvancedVisible"
        "Advanced ▸"
        "Advanced ▾"
        "QStackedWidget")
    string(FIND "${combined_source}" "${forbidden_token}" token_position)
    if(NOT token_position EQUAL -1)
        message(FATAL_ERROR
            "GUI Round 2 retained forbidden wizard/disclosure token: ${forbidden_token}")
    endif()
endforeach()
