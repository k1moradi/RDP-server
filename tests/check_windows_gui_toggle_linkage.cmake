# SPDX-License-Identifier: GPL-3.0-or-later
if(NOT DEFINED RDP_ROOT_CMAKE)
    message(FATAL_ERROR "RDP_ROOT_CMAKE is required")
endif()

file(READ "${RDP_ROOT_CMAKE}" rdp_root_cmake)
string(FIND "${rdp_root_cmake}"
    "add_executable(rdp-server-windows-gui WIN32"
    windows_gui_target_start)
if(windows_gui_target_start EQUAL -1)
    message(FATAL_ERROR "Windows GUI target is missing")
endif()

string(FIND "${rdp_root_cmake}"
    "target_include_directories(rdp-server-windows-gui"
    windows_gui_target_end)
if(windows_gui_target_end EQUAL -1 OR
   windows_gui_target_end LESS windows_gui_target_start)
    message(FATAL_ERROR "Windows GUI target source block is malformed")
endif()

math(EXPR windows_gui_target_length
    "${windows_gui_target_end} - ${windows_gui_target_start}")
string(SUBSTRING "${rdp_root_cmake}"
    ${windows_gui_target_start}
    ${windows_gui_target_length}
    windows_gui_target_block)

foreach(required_source IN ITEMS
        "src/windows/windows_gui_main.cpp"
        "src/gui/desktop_window.cpp"
        "src/gui/host_control.cpp"
        "src/gui/toggle_switch.cpp")
    string(FIND "${windows_gui_target_block}"
        "${required_source}"
        required_source_position)
    if(required_source_position EQUAL -1)
        message(FATAL_ERROR
            "Windows GUI target is missing required dashboard source: ${required_source}")
    endif()
endforeach()
