# SPDX-License-Identifier: GPL-3.0-or-later
# Compare already-resolved path spellings. Callers decide whether the
# filesystem candidate is allowed to use case-insensitive comparison.
function(rdp_server_paths_equivalent output_variable left_path right_path
         case_insensitive)
    set(normalized_left_path "${left_path}")
    set(normalized_right_path "${right_path}")
    cmake_path(NORMAL_PATH normalized_left_path)
    cmake_path(NORMAL_PATH normalized_right_path)

    if(case_insensitive)
        string(TOLOWER "${normalized_left_path}" normalized_left_path)
        string(TOLOWER "${normalized_right_path}" normalized_right_path)
    endif()

    if(normalized_left_path STREQUAL normalized_right_path)
        set(${output_variable} TRUE PARENT_SCOPE)
    else()
        set(${output_variable} FALSE PARENT_SCOPE)
    endif()
endfunction()
