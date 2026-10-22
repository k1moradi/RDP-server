# SPDX-License-Identifier: GPL-3.0-or-later
if(NOT DEFINED RDP_DESKTOP_WINDOW_SOURCE OR
   NOT DEFINED RDP_HOST_CONTROL_SOURCE)
    message(FATAL_ERROR
        "RDP_DESKTOP_WINDOW_SOURCE and RDP_HOST_CONTROL_SOURCE are required")
endif()

file(READ "${RDP_DESKTOP_WINDOW_SOURCE}" desktop_window_source)
file(READ "${RDP_HOST_CONTROL_SOURCE}" host_control_source)

foreach(forbidden_name IN ITEMS startRequested_ stopRequested_)
    string(FIND "${desktop_window_source}"
        "${forbidden_name}"
        forbidden_position)
    if(NOT forbidden_position EQUAL -1)
        message(FATAL_ERROR
            "Dashboard retained removed command-intent state: ${forbidden_name}")
    endif()
endforeach()

string(FIND "${host_control_source}"
    "sharingStage"
    legacy_sharing_stage_position)
if(NOT legacy_sharing_stage_position EQUAL -1)
    message(FATAL_ERROR
        "HostControl retained the retired raw-stage sharing helper")
endif()

string(FIND "${host_control_source}"
    "view.productState == RuntimeProductHostState::Connected"
    connected_projection_position)
if(connected_projection_position EQUAL -1)
    message(FATAL_ERROR
        "Connected-device projection is not gated by authoritative product state")
endif()

string(FIND "${desktop_window_source}"
    "runtimeProductStateMayHost"
    product_lifecycle_position)
if(product_lifecycle_position EQUAL -1)
    message(FATAL_ERROR
        "Dashboard host lifetime is not projected from authoritative product state")
endif()

# Sharing-permission presentation consumes only R10 product facts.
foreach(forbidden_permission_token IN ITEMS
        RuntimeOwnerGrantState
        kConsoleViewPermission
        kConsoleInputPermission
        kConsoleClipboardPermission)
    string(FIND "${desktop_window_source}"
        "${forbidden_permission_token}" permission_token_position)
    if(NOT permission_token_position EQUAL -1)
        message(FATAL_ERROR
            "Dashboard interprets raw sharing-permission token: ${forbidden_permission_token}")
    endif()
endforeach()

string(FIND "${desktop_window_source}"
    "RuntimeSharingPermissionDenial" product_permission_position)
if(product_permission_position EQUAL -1)
    message(FATAL_ERROR
        "Dashboard does not consume R10 sharing-permission product facts")
endif()
