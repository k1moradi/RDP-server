# SPDX-License-Identifier: GPL-3.0-or-later
# The imported ToggleSwitchWidget deliberately has no Q_OBJECT macro. Qt 6.11+
# requires the concrete findChild<T*>() type to have a meta-object, so hidden
# launch checks and fixtures must discover the object through QAbstractButton.
foreach(required_variable IN ITEMS
        RDP_TOGGLE_HEADER
        RDP_WINDOWS_GUI_SOURCE
        RDP_GUI_TEST_SOURCE)
    if(NOT DEFINED ${required_variable})
        message(FATAL_ERROR "${required_variable} is required")
    endif()
endforeach()

file(READ "${RDP_TOGGLE_HEADER}" toggle_header)
file(READ "${RDP_WINDOWS_GUI_SOURCE}" windows_gui_source)
file(READ "${RDP_GUI_TEST_SOURCE}" gui_test_source)

string(FIND "${toggle_header}"
    "class ToggleSwitchWidget final : public QAbstractButton"
    toggle_base_position)
if(toggle_base_position EQUAL -1)
    message(FATAL_ERROR
        "ToggleSwitchWidget must remain a QAbstractButton")
endif()

# Do not solve object-name lookup by adding meta-object machinery to a widget
# that has no signals, slots or properties. A genuine future Q_OBJECT need must
# deliberately revise this contract rather than arrive as a build workaround.
string(FIND "${toggle_header}" "Q_OBJECT" toggle_meta_object_position)
if(NOT toggle_meta_object_position EQUAL -1)
    message(FATAL_ERROR
        "ToggleSwitchWidget unexpectedly gained Q_OBJECT")
endif()

foreach(source_variable IN ITEMS windows_gui_source gui_test_source)
    set(source_text "${${source_variable}}")

    string(REGEX MATCH
        "findChild[ \t\r\n]*<[^>]*ToggleSwitchWidget[^>]*\\*[^>]*>"
        concrete_toggle_lookup
        "${source_text}")
    if(NOT concrete_toggle_lookup STREQUAL "")
        message(FATAL_ERROR
            "${source_variable} reintroduced findChild<ToggleSwitchWidget*>; use QAbstractButton by object name")
    endif()

    string(FIND "${source_text}"
        "findChild<QAbstractButton*>(\"sharingToggle\")"
        base_lookup_position)
    if(base_lookup_position EQUAL -1)
        message(FATAL_ERROR
            "${source_variable} must find sharingToggle through QAbstractButton")
    endif()

    string(FIND "${source_text}" "isCheckable()" checkable_position)
    if(checkable_position EQUAL -1)
        message(FATAL_ERROR
            "${source_variable} must validate sharingToggle checkability through the base API")
    endif()
endforeach()
