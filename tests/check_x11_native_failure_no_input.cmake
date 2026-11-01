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
# RandR retains the original XTEST controller and held key/button state.
# Check the rebuild body independently: no graceful input disconnect, native
# release, input recreation or broad terminal cleanup is allowed there.
string(FIND "${normalized_source}"
    "boolX11DesktopResources::rebuildGeometryBoundResources("
    rebuild_start)
string(FIND "${normalized_source}"
    "boolX11DesktopResources::initializePointerPositionTracker("
    rebuild_end)
if(rebuild_start EQUAL -1 OR rebuild_end LESS_EQUAL rebuild_start)
    message(FATAL_ERROR "R5 RandR rebuild bounds cannot be located")
endif()
math(EXPR rebuild_length "${rebuild_end} - ${rebuild_start}")
string(SUBSTRING "${normalized_source}" ${rebuild_start}
    ${rebuild_length} rebuild_body)
foreach(required IN ITEMS
        "pointerPosition_.reset();"
        "damage_->disconnect();"
        "damage_.reset();"
        "capture_->disconnect();"
        "capture_.reset();"
        "if(!input_||!input_->updateBounds(geometry))"
        "captureGeneration_=nextCaptureGeneration;")
    string(FIND "${rebuild_body}" "${required}" pos)
    if(pos EQUAL -1)
        message(FATAL_ERROR "R5 RandR geometry-only rebuild contract missing: ${required}")
    endif()
endforeach()
foreach(forbidden IN ITEMS
        "cancelGeometryBoundResources("
        "input_.emplace("
        "input_.reset();"
        "input_->disconnect();"
        "input_->retireWithoutNativeInput();"
        "cancelNativeResources(InputRetirementMode::ReleaseHeldState);")
    string(FIND "${rebuild_body}" "${forbidden}" pos)
    if(NOT pos EQUAL -1)
        message(FATAL_ERROR "R5 RandR must retain input owner without XTEST cleanup: ${forbidden}")
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
message(STATUS "R5 XCB/XShm failure: no cleanup XTEST; RandR preserves input; only graceful disconnect releases")
