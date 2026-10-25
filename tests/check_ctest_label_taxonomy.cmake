cmake_minimum_required(VERSION 3.22)

if(NOT DEFINED RDP_TEST_REGISTRY OR "${RDP_TEST_REGISTRY}" STREQUAL "")
    message(FATAL_ERROR "RDP_TEST_REGISTRY is required")
endif()

file(READ "${RDP_TEST_REGISTRY}" registry)
string(REGEX MATCHALL "LABELS[ \\t\\r\\n]+\"[^\"]*\"" label_blocks
    "${registry}")
if(NOT label_blocks)
    message(FATAL_ERROR "No CTest LABELS blocks found")
endif()

foreach(label_block IN LISTS label_blocks)
    string(REGEX REPLACE "^[^\"]*\"" "" labels "${label_block}")
    string(REGEX REPLACE "\"$" "" labels "${labels}")
    if(";${labels};" MATCHES ";[rR](10|[1-9])([-_][^;]*)?;")
        message(FATAL_ERROR
            "CTest label contains internal agent ownership taxonomy: ${labels}")
    endif()
endforeach()
