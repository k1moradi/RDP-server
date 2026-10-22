# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

if(NOT DEFINED RDP_MAC_NATIVE_OWNER_SOURCE)
    message(FATAL_ERROR "RDP_MAC_NATIVE_OWNER_SOURCE is required")
endif()

file(READ "${RDP_MAC_NATIVE_OWNER_SOURCE}" source)

foreach(required IN ITEMS
        "const std::size_t widthPixels ="
        "static_cast<std::size_t>(frame.widthPixels);"
        "widthPixels >"
        "(std::numeric_limits<std::size_t>::max)() / 4U"
        "const std::size_t rowBytes = widthPixels * 4U;")
    string(FIND "${source}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR
            "missing framebuffer row-size guard fragment: ${required}")
    endif()
endforeach()

string(FIND "${source}" "frame.widthPixels >" legacy_cross_width_compare)
if(NOT legacy_cross_width_compare EQUAL -1)
    message(FATAL_ERROR
        "uint32_t framebuffer width must not be compared directly to size_t max/4")
endif()
