cmake_minimum_required(VERSION 3.22)

if(NOT DEFINED RDP_TEST_REGISTRY OR "${RDP_TEST_REGISTRY}" STREQUAL "")
    message(FATAL_ERROR "RDP_TEST_REGISTRY is required")
endif()

file(READ "${RDP_TEST_REGISTRY}" registry)

# Literal test names must use behavior/domain terminology. Dynamically
# assembled names are checked again from CMake's resolved TESTS registry.
string(REGEX MATCHALL "add_test\\([ \\t\\r\\n]*NAME[ \\t\\r\\n]+[^ \\t\\r\\n\\)]+" name_blocks
    "${registry}")
foreach(name_block IN LISTS name_blocks)
    string(REGEX REPLACE "^.*NAME[ \\t\\r\\n]+\"?" "" test_name "${name_block}")
    string(REGEX REPLACE "\"$" "" test_name "${test_name}")
    if(test_name MATCHES "(^|[._-])[rR](10|[1-9])([._-]|$)")
        message(FATAL_ERROR
            "CTest name contains internal agent ownership taxonomy: ${test_name}")
    endif()
endforeach()

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
