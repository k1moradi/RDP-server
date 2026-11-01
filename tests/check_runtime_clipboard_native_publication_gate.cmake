# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

# Future activation is intentionally disabled. This ordinary source contract
# protects the authorization and R1 receipt order without touching native X11.
if(NOT DEFINED RDP_LINUX_PREPARED_CLIPBOARD_HEADER)
    message(FATAL_ERROR "missing R8 owner source")
endif()
file(READ "${RDP_LINUX_PREPARED_CLIPBOARD_HEADER}" owner_source)

string(FIND "${owner_source}" "bool serviceAfterNetworkDispatch(" dispatch_begin)
string(FIND "${owner_source}" "bool serviceNative(" dispatch_end)
if(dispatch_begin LESS 0 OR dispatch_end LESS_EQUAL dispatch_begin)
    message(FATAL_ERROR "unable to isolate R8 native publication method")
endif()
math(EXPR dispatch_length "${dispatch_end} - ${dispatch_begin}")
string(SUBSTRING "${owner_source}" ${dispatch_begin}
    ${dispatch_length} dispatch_source)

# Preserve one outbound R1/R3 writer. A queued client FORMAT_LIST response is
# not a delivered response: initialization, any partial write, and a fresh R2
# Clipboard-scope visit all gate the sole X11 publication call.
set(previous_position -1)
foreach(required_text IN ITEMS
        "queuePendingApplicationPdu(connection, policy)"
        "if (!bridge_->serverInitializationReady() || writePending_)\n            return true;"
        "if (!connection.visitPersonalDesktopClipboardChannel("
        "policy, bridge_->channelVisitor())"
        "adapter_->publishCurrentRemoteOffer(now)"
        "return adapter_->servicePendingPaste(now);")
    string(FIND "${dispatch_source}" "${required_text}" position)
    if(position LESS 0 OR position LESS_EQUAL previous_position)
        message(FATAL_ERROR
            "native Clipboard publication bypasses ordered receipt/scope fence: ${required_text}")
    endif()
    set(previous_position ${position})
endforeach()

string(FIND "${owner_source}" "bool writePending() const noexcept" native_end)
if(native_end LESS_EQUAL dispatch_end)
    message(FATAL_ERROR "unable to isolate R8 native paste service")
endif()
math(EXPR native_length "${native_end} - ${dispatch_end}")
string(SUBSTRING "${owner_source}" ${dispatch_end}
    ${native_length} native_source)
string(FIND "${native_source}"
    "if (!active() || !bridge_->serverInitializationReady())" native_ready)
string(FIND "${native_source}" "adapter_->servicePendingPaste(now)" native_paste)
if(native_ready LESS 0 OR native_paste LESS_EQUAL native_ready)
    message(FATAL_ERROR "native paste service bypasses initial R1/R3 receipts")
endif()

string(REGEX MATCHALL "publishCurrentRemoteOffer\\("
    publication_calls "${owner_source}")
list(LENGTH publication_calls publication_count)
if(NOT publication_count EQUAL 1)
    message(FATAL_ERROR "expected one R8 native publication owner")
endif()
string(FIND "${owner_source}"
    "kLinuxProductionClipboardActivationApproved = false" production_off)
if(production_off LESS 0)
    message(FATAL_ERROR "native R8 production activation was enabled")
endif()
