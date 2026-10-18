# SPDX-License-Identifier: GPL-3.0-or-later
# Production R5 full-owner failure paths must discard held input without
# posting cleanup XTEST. Source-only; Xvfb tests separately prove the XTEST
# controller's held key/button suppression. No OS admission is synthesized.
foreach(key IN ITEMS RDP_R5_NATIVE_HEADER RDP_R5_NATIVE_SOURCE)
    if(NOT DEFINED ${key} OR "${${key}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${key}")
    endif()
endforeach()
file(READ "${RDP_R5_NATIVE_HEADER}" header)
file(READ "${RDP_R5_NATIVE_SOURCE}" source)
string(REGEX REPLACE "[ \t\r\n]+" "" normalized_header "${header}")
string(REGEX REPLACE "[ \t\r\n]+" "" normalized_source "${source}")

foreach(required IN ITEMS
        "voidcancelNativeResources(InputRetirementModeinputRetirementMode=InputRetirementMode::SuppressNativeInput)noexcept;")
    string(FIND "${normalized_header}" "${required}" pos)
    if(pos EQUAL -1)
        message(FATAL_ERROR "R5 native fatal cleanup is not no-XTEST by default")
    endif()
endforeach()
foreach(required IN ITEMS
        "voidX11DesktopResources::disconnect()noexcept"
        "voidX11DesktopResources::retireAfterAuthorizationLoss()noexcept"
        "cancelNativeResources(InputRetirementMode::SuppressNativeInput);"
        "cancelGeometryBoundResources();"
        "input_->retireWithoutNativeInput();"
        "fail(\"X11desktopeventdispatchfailed\");cancelNativeResources();"
        "fail(\"X11desktopchildresourcefailedduringeventdispatch\");cancelNativeResources();"
        "fail(\"X11desktopresizegeometryisinvalid\");cancelNativeResources();"
        "fail(\"X11desktopcapturegenerationcannotadvance\");cancelNativeResources();")
    string(FIND "${normalized_source}" "${required}" pos)
    if(pos EQUAL -1)
        message(FATAL_ERROR "R5 full-owner error/no-XTEST contract missing: ${required}")
    endif()
endforeach()
string(REGEX MATCHALL
    "cancelNativeResources[(]InputRetirementMode::ReleaseHeldState[)]"
    releases "${normalized_source}")
list(LENGTH releases count)
if(NOT count EQUAL 1)
    message(FATAL_ERROR "Exactly one explicit graceful full-owner release allowed")
endif()
string(FIND "${normalized_source}"
    "voidX11DesktopResources::disconnect()noexcept" graceful_start)
string(FIND "${normalized_source}"
    "cancelNativeResources(InputRetirementMode::ReleaseHeldState);" only_release)
string(FIND "${normalized_source}"
    "voidX11DesktopResources::retireAfterAuthorizationLoss()noexcept"
    terminal_start)
if(NOT graceful_start LESS only_release OR
   NOT only_release LESS terminal_start)
    message(FATAL_ERROR "Full-owner releases must remain inside graceful disconnect")
endif()
message(STATUS "R5 XCB/XShm failure: zero cleanup XTEST, only graceful disconnect releases")
