# SPDX-License-Identifier: GPL-3.0-or-later
if(NOT DEFINED RDP_SOURCE_ROOT OR NOT DEFINED RDP_CI_WORKFLOW)
    message(FATAL_ERROR "RDP_SOURCE_ROOT and RDP_CI_WORKFLOW are required")
endif()

file(GLOB_RECURSE application_sources LIST_DIRECTORIES FALSE
    "${RDP_SOURCE_ROOT}/src/*.cpp"
    "${RDP_SOURCE_ROOT}/src/*.h"
    "${RDP_SOURCE_ROOT}/src/*.mm")
foreach(source_file IN LISTS application_sources)
    file(READ "${source_file}" source_text)
    string(FIND "${source_text}" "QColorSpace" qcolor_position)
    if(NOT qcolor_position EQUAL -1)
        message(FATAL_ERROR
            "GUI Round 2 QColorSpace ownership changed; classify application construction before accepting the warning: ${source_file}")
    endif()
    string(FIND "${source_text}" "qInstallMessageHandler" handler_position)
    if(NOT handler_position EQUAL -1)
        message(FATAL_ERROR
            "GUI Round 2 application message handling changed; review warning classification: ${source_file}")
    endif()
endforeach()

file(READ "${RDP_CI_WORKFLOW}" workflow_text)
foreach(forbidden_suppression IN ITEMS
        "QT_LOGGING_RULES"
        "QT_NO_WARNING_OUTPUT")
    string(FIND "${workflow_text}" "${forbidden_suppression}" suppression_position)
    if(NOT suppression_position EQUAL -1)
        message(FATAL_ERROR
            "GUI Round 2 must not globally suppress Qt warning output: ${forbidden_suppression}")
    endif()
endforeach()
