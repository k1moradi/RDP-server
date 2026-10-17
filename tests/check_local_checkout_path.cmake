# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/validate_local_checkout.cmake")

function(require_path_comparison expected left_path right_path case_insensitive)
    rdp_server_paths_equivalent(
        actual "${left_path}" "${right_path}" "${case_insensitive}")
    if(NOT actual STREQUAL expected)
        message(FATAL_ERROR
            "path comparison mismatch: expected=${expected} actual=${actual} "
            "left=${left_path} right=${right_path} "
            "case_insensitive=${case_insensitive}")
    endif()
endfunction()

require_path_comparison(
    TRUE "/home/dev/rdp-server" "/home/dev/rdp-server" FALSE)
require_path_comparison(
    FALSE "/home/dev/RDP-server" "/home/dev/rdp-server" FALSE)
require_path_comparison(
    TRUE "/Users/dev/RDP-server" "/Users/dev/rdp-server" TRUE)
require_path_comparison(
    TRUE "C:/Users/Dev/RDP-server" "c:/users/dev/rdp-server" TRUE)
require_path_comparison(
    FALSE "C:/Users/Dev/RDP-server" "C:/Users/Dev/other" TRUE)
