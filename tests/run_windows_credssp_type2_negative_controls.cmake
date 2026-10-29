# SPDX-License-Identifier: GPL-3.0-or-later
# Validate deliberately invalid Type-2 challenges in fresh Microsoft CREDSSP
# processes. These are test-only mutations and never production wire inputs.

if(NOT DEFINED TEST_EXECUTABLE OR TEST_EXECUTABLE STREQUAL "")
    message(FATAL_ERROR "TEST_EXECUTABLE is required")
endif()
if(NOT EXISTS "${TEST_EXECUTABLE}")
    message(FATAL_ERROR "CredSSP test executable not found: ${TEST_EXECUTABLE}")
endif()

execute_process(
    COMMAND "${TEST_EXECUTABLE}" control-target
    RESULT_VARIABLE control_result
    OUTPUT_VARIABLE control_stdout
    ERROR_VARIABLE control_stderr)
if(NOT control_stdout STREQUAL "")
    message("${control_stdout}")
endif()
if(NOT control_stderr STREQUAL "")
    message("${control_stderr}")
endif()
if(NOT "${control_result}" STREQUAL "0")
    message(FATAL_ERROR
        "Production Microsoft CREDSSP control did not reach Type 3")
endif()
set(control_output "${control_stdout}\n${control_stderr}")
string(REGEX MATCH
    "microsoft-credssp target=TERMSRV/RDP-SERVER [^\r\n]*production-type2=accepted[^\r\n]*type3=yes"
    control_row "${control_output}")
if(control_row STREQUAL "")
    message(FATAL_ERROR
        "Production Microsoft CREDSSP control lacks the Type-3 receipt")
endif()

set(negative_modes
    type2-negative-missing-nb-computer
    type2-negative-missing-nb-domain)
set(negative_experiments
    missing-msv-av-nb-computer-name
    missing-msv-av-nb-domain-name)

list(LENGTH negative_modes negative_count)
math(EXPR negative_last "${negative_count} - 1")
foreach(index RANGE 0 ${negative_last})
    list(GET negative_modes ${index} negative_mode)
    list(GET negative_experiments ${index} negative_experiment)
    execute_process(
        COMMAND "${TEST_EXECUTABLE}" "${negative_mode}"
        RESULT_VARIABLE negative_result
        OUTPUT_VARIABLE negative_stdout
        ERROR_VARIABLE negative_stderr)
    if(NOT negative_stdout STREQUAL "")
        message("${negative_stdout}")
    endif()
    if(NOT negative_stderr STREQUAL "")
        message("${negative_stderr}")
    endif()
    if(NOT "${negative_result}" STREQUAL "0")
        message(FATAL_ERROR
            "Microsoft CREDSSP negative control failed for ${negative_experiment}")
    endif()

    set(negative_output "${negative_stdout}\n${negative_stderr}")
    string(REGEX MATCH
        "microsoft-credssp-type2-negative-control experiment=${negative_experiment} [^\r\n]*"
        negative_row "${negative_output}")
    if(negative_row STREQUAL "")
        message(FATAL_ERROR
            "Missing negative-control receipt for ${negative_experiment}")
    endif()
    foreach(required_token
            "challenge-committed=yes"
            "type2-consumed=yes"
            "type3=no"
            "oracle-detected=yes"
            "production-type2-change-authorized=no")
        string(FIND "${negative_row}" "${required_token}" token_offset)
        if(token_offset LESS 0)
            message(FATAL_ERROR
                "Negative-control receipt for ${negative_experiment} lacks ${required_token}")
        endif()
    endforeach()
endforeach()

message(
    "microsoft-credssp-type2-negative-controls "
    "control=TYPE3 invalid-controls=DETECTED status=PASS "
    "process-isolation=per-challenge "
    "production-type2-change-authorized=no")
