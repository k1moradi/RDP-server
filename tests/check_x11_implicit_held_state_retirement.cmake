# SPDX-License-Identifier: GPL-3.0-or-later
# Production-source chain only: no R2 lease, XTEST post, X server, or ASan claim.
foreach(source_path IN ITEMS RDP_R5_DESKTOP_SOURCE RDP_R5_INPUT_SOURCE)
    if(NOT DEFINED ${source_path} OR NOT EXISTS "${${source_path}}")
        message(FATAL_ERROR "Missing ${source_path}")
    endif()
endforeach()
file(READ "${RDP_R5_DESKTOP_SOURCE}" desktop)
file(READ "${RDP_R5_INPUT_SOURCE}" controller)
string(REGEX REPLACE "[ \t\r\n]+" "" desktop "${desktop}")
string(REGEX REPLACE "[ \t\r\n]+" "" controller "${controller}")

# Scope every requirement to the actual method, not to an unrelated call.
function(method_must_contain source beginning ending fragment)
    string(FIND "${source}" "${beginning}" first)
    string(FIND "${source}" "${ending}" last)
    if(first EQUAL -1 OR last LESS_EQUAL first)
        message(FATAL_ERROR "Cannot isolate ${beginning}")
    endif()
    math(EXPR size "${last} - ${first}")
    string(SUBSTRING "${source}" ${first} ${size} body)
    string(FIND "${body}" "${fragment}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "Missing terminal no-post chain in ${beginning}: ${fragment}")
    endif()
endfunction()

method_must_contain("${desktop}"
    "X11DesktopResources::~X11DesktopResources()noexcept"
    "boolX11DesktopResources::valid()constnoexcept"
    "retireAfterAuthorizationLoss();")
method_must_contain("${desktop}"
    "voidX11DesktopResources::retireAfterAuthorizationLoss()noexcept"
    "voidX11DesktopResources::fail("
    "cancelNativeResources(InputRetirementMode::SuppressNativeInput);")
method_must_contain("${desktop}"
    "voidX11DesktopResources::cancelNativeResources("
    "display_.disconnect();}"
    "cancelGeometryBoundResources(inputRetirementMode);")
method_must_contain("${desktop}"
    "voidX11DesktopResources::cancelGeometryBoundResources("
    "boolX11DesktopResources::rebuildGeometryBoundResources("
    "if(inputRetirementMode==InputRetirementMode::SuppressNativeInput){input_->retireWithoutNativeInput();}else{input_->disconnect();}input_.reset();")
method_must_contain("${controller}"
    "voidX11InputController::retireWithoutNativeInput()noexcept"
    "voidX11InputController::retireState("
    "retireState(")
foreach(field IN ITEMS
    "connection_=nullptr;"
    "activeKeycodes_.fill(XCB_NO_SYMBOL);"
    "pressedButtons_.fill(false);")
    method_must_contain("${controller}"
        "voidX11InputController::retireState("
        "voidX11InputController::fail("
        "${field}")
endforeach()
method_must_contain("${controller}"
    "X11InputController::~X11InputController()noexcept"
    "boolX11InputController::valid()constnoexcept"
    "disconnect();")
method_must_contain("${controller}"
    "voidX11InputController::disconnect()noexcept"
    "voidX11InputController::retireWithoutNativeInput()noexcept"
    "releaseAll();")
method_must_contain("${controller}"
    "voidX11InputController::releaseAll()noexcept"
    "xcb_keycode_tX11InputController::keycodeFor("
    "if(connection_==nullptr||rootWindow_==XCB_WINDOW_NONE||")

# Prevent a future terminal implementation from posting XTEST itself.
foreach(method_start IN ITEMS
    "voidX11InputController::retireWithoutNativeInput()noexcept"
    "voidX11InputController::retireState(")
    if(method_start STREQUAL "voidX11InputController::retireState(")
        set(next_method "voidX11InputController::fail(")
    else()
        set(next_method "voidX11InputController::retireState(")
    endif()
    string(FIND "${controller}" "${method_start}" first)
    string(FIND "${controller}" "${next_method}" last)
    if(first EQUAL -1 OR last LESS_EQUAL first)
        message(FATAL_ERROR "Cannot isolate terminal input method")
    endif()
    math(EXPR size "${last} - ${first}")
    string(SUBSTRING "${controller}" ${first} ${size} body)
    foreach(forbidden IN ITEMS "xcb_test_fake_input(" "releaseAll();")
        string(FIND "${body}" "${forbidden}" found)
        if(NOT found EQUAL -1)
            message(FATAL_ERROR "Terminal input method performs ${forbidden}")
        endif()
    endforeach()
endforeach()

# Input child must be disabled before its RAII destructor and before XCB close.
string(FIND "${desktop}" "voidX11DesktopResources::cancelGeometryBoundResources(" first)
string(FIND "${desktop}" "boolX11DesktopResources::rebuildGeometryBoundResources(" last)
math(EXPR size "${last} - ${first}")
string(SUBSTRING "${desktop}" ${first} ${size} body)
string(FIND "${body}" "input_->retireWithoutNativeInput();" suppress)
string(FIND "${body}" "input_.reset();" reset)
if(suppress EQUAL -1 OR reset LESS_EQUAL suppress)
    message(FATAL_ERROR "Held input child reset precedes terminal no-post retirement")
endif()
string(FIND "${desktop}" "voidX11DesktopResources::cancelNativeResources(" first)
string(SUBSTRING "${desktop}" ${first} -1 body)
string(FIND "${body}" "cancelGeometryBoundResources(inputRetirementMode);" child)
string(FIND "${body}" "display_.disconnect();" parent)
if(child EQUAL -1 OR parent LESS_EQUAL child)
    message(FATAL_ERROR "XCB parent closed before its native children")
endif()
message(STATUS "Production R5 implicit held-state teardown chain is no-post")
