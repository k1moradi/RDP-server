# SPDX-License-Identifier: GPL-3.0-or-later
# Run each Microsoft CREDSSP credential-source probe in a fresh process.
# A child crash is a hard failure; never retry or convert it to acceptance.

if(NOT DEFINED TEST_EXECUTABLE OR TEST_EXECUTABLE STREQUAL "")
    message(FATAL_ERROR "TEST_EXECUTABLE is required")
endif()
if(NOT EXISTS "${TEST_EXECUTABLE}")
    message(FATAL_ERROR "CredSSP test executable not found: ${TEST_EXECUTABLE}")
endif()

set(credential_states correct wrong-password empty-password unavailable-no-spnego)
set(credential_modes
    credential-semantic-correct
    credential-semantic-wrong-password
    credential-semantic-empty-password
    credential-semantic-unavailable-no-spnego)

set(physical_sequence_match "no")
set(leading_comparison "none")
set(unavailable_no_spnego_match "inconclusive")
set(all_noncontrol_type3_or_pretype1 "yes")

list(LENGTH credential_states credential_state_count)
math(EXPR credential_state_last "${credential_state_count} - 1")
foreach(index RANGE 0 ${credential_state_last})
    list(GET credential_states ${index} credential_state)
    list(GET credential_modes ${index} credential_mode)
    execute_process(
        COMMAND "${TEST_EXECUTABLE}" "${credential_mode}"
        RESULT_VARIABLE child_result
        OUTPUT_VARIABLE child_stdout
        ERROR_VARIABLE child_stderr)
    if(NOT child_stdout STREQUAL "")
        message("${child_stdout}")
    endif()
    if(NOT child_stderr STREQUAL "")
        message("${child_stderr}")
    endif()
    if(NOT "${child_result}" STREQUAL "0")
        message(FATAL_ERROR
            "Microsoft CREDSSP credential-state=${credential_state} child "
            "failed/crashed with result=${child_result}; no retry permitted")
    endif()

    set(combined_output "${child_stdout}\n${child_stderr}")
    string(REGEX MATCH
        "microsoft-credssp-credential-semantics credential-state=${credential_state} outcome=([A-Z0-9_]+)[^\r\n]*"
        credential_row "${combined_output}")
    if(credential_row STREQUAL "")
        message(FATAL_ERROR
            "Missing complete Microsoft CREDSSP row for credential-state=${credential_state}")
    endif()
    set(outcome "${CMAKE_MATCH_1}")

    string(FIND "${combined_output}"
        "microsoft-credssp-credential-semantics-begin credential-state=${credential_state} process-isolated=yes"
        begin_marker)
    string(FIND "${combined_output}"
        "microsoft-credssp-credential-semantics-end credential-state=${credential_state} status=PASS process-isolated=yes"
        end_marker)
    if(begin_marker LESS 0 OR end_marker LESS 0)
        message(FATAL_ERROR
            "Credential-state=${credential_state} did not complete its isolated process markers")
    endif()

    if(credential_state STREQUAL "correct")
        if(NOT outcome STREQUAL "TYPE3_EMITTED")
            message(FATAL_ERROR
                "Correct Microsoft CREDSSP control did not reach Type 3: ${outcome}")
        endif()
    else()
        if(NOT outcome STREQUAL "TYPE3_EMITTED" AND
           NOT outcome STREQUAL "FAILED_BEFORE_TYPE1")
            set(all_noncontrol_type3_or_pretype1 "no")
        endif()
    endif()

    if(outcome STREQUAL "POST_TYPE2_NO_TYPE3")
        if(physical_sequence_match STREQUAL "no")
            set(leading_comparison "${credential_state}")
        endif()
        set(physical_sequence_match "yes")
    endif()

    if(credential_state STREQUAL "unavailable-no-spnego")
        if(outcome STREQUAL "POST_TYPE2_NO_TYPE3")
            set(unavailable_no_spnego_match "yes")
        elseif(outcome STREQUAL "TYPE3_EMITTED" OR
               outcome STREQUAL "FAILED_BEFORE_TYPE1")
            set(unavailable_no_spnego_match "no")
        endif()
    endif()
endforeach()

execute_process(
    COMMAND "${TEST_EXECUTABLE}" credential-semantic-default-policy
    RESULT_VARIABLE policy_result
    OUTPUT_VARIABLE policy_stdout
    ERROR_VARIABLE policy_stderr)
if(NOT policy_stdout STREQUAL "")
    message("${policy_stdout}")
endif()
if(NOT policy_stderr STREQUAL "")
    message("${policy_stderr}")
endif()
if(NOT "${policy_result}" STREQUAL "0")
    message(FATAL_ERROR
        "Default-credential policy child failed with result=${policy_result}")
endif()
set(policy_output "${policy_stdout}\n${policy_stderr}")
string(FIND "${policy_output}" "credential-state=default-credential outcome=NOT_RUN_POLICY" policy_not_run)
string(FIND "${policy_output}" "hosted-runner-credentials-used=no" policy_no_host_creds)
if(policy_not_run LESS 0 OR policy_no_host_creds LESS 0)
    message(FATAL_ERROR "Hosted default credential policy did not remain NOT_RUN_POLICY")
endif()

message(
    "microsoft-credssp-credential-semantics-summary "
    "status=PASS correct-control=TYPE3 "
    "physical-sequence-match=${physical_sequence_match} "
    "leading-comparison=${leading_comparison} "
    "unavailable-no-spnego-match=${unavailable_no_spnego_match} "
    "all-noncontrol-type3-or-pretype1=${all_noncontrol_type3_or_pretype1} "
    "default-credential=NOT_RUN_POLICY "
    "production-type2-change-authorized=no "
    "process-isolation=per-credential-state")
