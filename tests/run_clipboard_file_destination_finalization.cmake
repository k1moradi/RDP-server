# SPDX-License-Identifier: GPL-3.0-or-later
if(NOT DEFINED MACOS_FILE_TEST OR NOT EXISTS "${MACOS_FILE_TEST}")
    message(FATAL_ERROR "missing macOS file-destination test executable")
endif()
if(NOT DEFINED WINDOWS_FILE_TEST OR NOT EXISTS "${WINDOWS_FILE_TEST}")
    message(FATAL_ERROR "missing Windows file-destination test executable")
endif()

execute_process(
    COMMAND "${MACOS_FILE_TEST}"
        macos-file-destination-finalization-generation-replacement
    RESULT_VARIABLE macos_result)
if(NOT macos_result EQUAL 0)
    message(FATAL_ERROR
        "macOS file-destination finalization regression failed: ${macos_result}")
endif()

execute_process(
    COMMAND "${WINDOWS_FILE_TEST}"
        windows-file-destination-finalization-generation-replacement
    RESULT_VARIABLE windows_result)
if(NOT windows_result EQUAL 0)
    message(FATAL_ERROR
        "Windows file-destination finalization regression failed: ${windows_result}")
endif()
