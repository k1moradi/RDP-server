# SPDX-License-Identifier: GPL-3.0-or-later
# Implicit R5 aggregate destruction has no fresh R2 native-authorization
# proof, so held XTEST cleanup must require explicit graceful disconnect.
# Pure source contract: never starts an X server or issues native input.
foreach(required_path IN ITEMS RDP_R5_NATIVE_HEADER RDP_R5_NATIVE_SOURCE)
    if(NOT DEFINED ${required_path} OR "${${required_path}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_path}")
    endif()
endforeach()
file(READ "${RDP_R5_NATIVE_HEADER}" header)
file(READ "${RDP_R5_NATIVE_SOURCE}" source)
string(REGEX REPLACE "[ \t\r\n]+" "" normalized_header "${header}")
string(REGEX REPLACE "[ \t\r\n]+" "" normalized_source "${source}")

foreach(required IN ITEMS
        "voidcancelGeometryBoundResources(InputRetirementModeinputRetirementMode=InputRetirementMode::SuppressNativeInput)noexcept;"
        "voidcancelNativeResources(InputRetirementModeinputRetirementMode=InputRetirementMode::SuppressNativeInput)noexcept;")
    string(FIND "${normalized_header}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "R5 implicit native child cancellation must suppress XTEST: ${required}")
    endif()
endforeach()

# Keep the check scoped to the destructor, not a coincidental occurrence of
# retireAfterAuthorizationLoss elsewhere in the source file.
string(FIND "${normalized_source}"
    "X11DesktopResources::~X11DesktopResources()noexcept{" destructor_start)
string(FIND "${normalized_source}"
    "boolX11DesktopResources::valid()constnoexcept" destructor_end)
if(destructor_start EQUAL -1 OR destructor_end LESS_EQUAL destructor_start)
    message(FATAL_ERROR "R5 native owner destructor boundary not found")
endif()
math(EXPR destructor_length "${destructor_end} - ${destructor_start}")
string(SUBSTRING "${normalized_source}" ${destructor_start}
    ${destructor_length} destructor_body)
string(FIND "${destructor_body}" "retireAfterAuthorizationLoss();" terminal_call)
if(terminal_call EQUAL -1)
    message(FATAL_ERROR "R5 implicit destructor must retire without XTEST")
endif()
foreach(forbidden IN ITEMS
        "disconnect();"
        "cancelNativeResources(InputRetirementMode::ReleaseHeldState);"
        "cancelGeometryBoundResources(InputRetirementMode::ReleaseHeldState);")
    string(FIND "${destructor_body}" "${forbidden}" position)
    if(NOT position EQUAL -1)
        message(FATAL_ERROR "R5 implicit destructor attempted graceful XTEST cleanup: ${forbidden}")
    endif()
endforeach()
# The explicit graceful API remains available but cannot be the RAII fallback.
string(FIND "${normalized_source}"
    "voidX11DesktopResources::disconnect()noexcept" explicit_disconnect)
string(FIND "${normalized_source}"
    "cancelNativeResources(InputRetirementMode::ReleaseHeldState);" explicit_release)
string(FIND "${normalized_source}"
    "voidX11DesktopResources::retireAfterAuthorizationLoss()noexcept" terminal_start)
if(explicit_disconnect EQUAL -1 OR explicit_release LESS explicit_disconnect
   OR terminal_start LESS_EQUAL explicit_release)
    message(FATAL_ERROR "R5 graceful XTEST release escaped explicit disconnect")
endif()
message(STATUS "R5 implicit native owner teardown suppresses XTEST; graceful release explicit")
