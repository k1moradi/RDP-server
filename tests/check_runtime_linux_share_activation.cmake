# SPDX-License-Identifier: GPL-3.0-or-later
foreach(required_argument IN ITEMS
        RDP_RUNTIME_ENTRYPOINT_SOURCE
        RDP_MCS_SESSION_SOURCE
        RDP_RUNTIME_CONNECTION_HEADER
        RDP_RUNTIME_CONNECTION_SOURCE)
    if(NOT DEFINED ${required_argument} OR "${${required_argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${required_argument}")
    endif()
endforeach()

file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)
file(READ "${RDP_MCS_SESSION_SOURCE}" mcs_source)
file(READ "${RDP_RUNTIME_CONNECTION_HEADER}" connection_header)
file(READ "${RDP_RUNTIME_CONNECTION_SOURCE}" connection_source)

foreach(required_runtime_text IN ITEMS
        "preparePersonalDesktopDemandActiveProfile"
        "startPersonalDesktopShareActivation"
        "advancePersonalDesktopShareActivation"
        "ShareStep::Activated"
        "DemandFeature::DynamicVirtualChannels"
        "DemandFeature::SlowPathInput")
    string(FIND "${runtime_source}" "${required_runtime_text}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R10 serve loop is missing required Share activation composition: ${required_runtime_text}")
    endif()
endforeach()

string(REGEX MATCH
    "case ValidClientStep::Delivered:[^}]*connection\\.revoke\\(\\);[^}]*return true;"
    premature_valid_client_revoke "${runtime_source}")
if(NOT premature_valid_client_revoke STREQUAL "")
    message(FATAL_ERROR
        "Valid Client delivery still revokes before canonical Demand Active/Share")
endif()

foreach(required_mcs_text IN ITEMS
        "connectResponseClientSettings_.requestedWidth"
        "connectResponseClientSettings_.requestedHeight"
        "RdpDemandActivePlatform::LinuxX11"
        "demandActiveProfileProvider_.prepare")
    string(FIND "${mcs_source}" "${required_mcs_text}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR
            "R3 production profile no longer derives canonical admitted geometry: ${required_mcs_text}")
    endif()
endforeach()

string(FIND "${connection_header}"
    "RdpDemandActiveFeature features" feature_argument)
if(feature_argument EQUAL -1)
    message(FATAL_ERROR
        "R10 runtime connection must accept typed feature policy, not raw Share/profile fields")
endif()

foreach(forbidden_text IN ITEMS
        "std::uint32_t shareId"
        "std::uint32_t sessionId"
        "std::span<const std::uint8_t> sourceDescriptor"
        "std::uint16_t capabilityCount")
    string(FIND "${connection_header}" "${forbidden_text}" forbidden_position)
    if(NOT forbidden_position EQUAL -1)
        message(FATAL_ERROR
            "R10 Share start surface regressed to caller-supplied wire identity: ${forbidden_text}")
    endif()
endforeach()


# MS-RDPBCGR permits input immediately after Confirm Active. During connection
# finalization R3 consumes only already-negotiated input and R10 must keep
# reading; it must not dispatch input or mistake it for a server-write trigger.
string(FIND "${connection_source}"
    "case Intake::InputIgnoredUntilActivated:" early_input_case)
if(early_input_case EQUAL -1)
    message(FATAL_ERROR
        "R10 Share scheduler no longer consumes R3 early-input intake")
endif()
