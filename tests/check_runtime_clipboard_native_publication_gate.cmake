# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)

# Future activation is intentionally disabled. This ordinary source contract
# protects the authorization and R1 receipt order without touching native X11.
if(NOT DEFINED RDP_LINUX_PREPARED_CLIPBOARD_HEADER OR
   NOT DEFINED RDP_LINUX_HOST_CONTROL_SOURCE OR
   NOT DEFINED RDP_LINUX_RUNTIME_CONNECTION_SOURCE)
    message(FATAL_ERROR "missing R8 owner source")
endif()
file(READ "${RDP_LINUX_PREPARED_CLIPBOARD_HEADER}" owner_source)
file(READ "${RDP_LINUX_RUNTIME_CONNECTION_SOURCE}" connection_source)

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
        "bridge_->discardRouteObservation()"
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
    "!bridge_->serverInitializationReady() ||" native_ready)
string(FIND "${native_source}" "writePending_)" native_write)
string(FIND "${native_source}"
    "connection.visitPersonalDesktopClipboardChannel(" native_scope)
string(FIND "${native_source}"
    "bridge_->discardRouteObservation()" native_discard)
string(FIND "${native_source}" "adapter_->servicePendingPaste(now)" native_paste)
if(native_ready LESS 0 OR native_write LESS_EQUAL native_ready OR
   native_scope LESS_EQUAL native_write OR
   native_discard LESS_EQUAL native_scope OR
   native_paste LESS_EQUAL native_discard)
    message(FATAL_ERROR "native paste service bypasses initial receipt/write/R2 Clipboard-scope/route-consumption fences")
endif()

# R10 owns *when* to prepare each PDU, while R8 requires a fresh R2 visit
# and hands bytes to the original R3/R1 queue/receipt machinery.
file(READ "${RDP_LINUX_HOST_CONTROL_SOURCE}" host_source)
string(FIND "${host_source}" "clipboard.initializationWriteRequired()" schedule_ready)
string(FIND "${host_source}" "clipboard.prepareServerInitializationPdu(" schedule_prepare)
string(FIND "${host_source}" "clipboard.serviceAfterNetworkDispatch(" schedule_queue)
string(FIND "${owner_source}" "bool prepareServerInitializationPdu(" owner_prepare)
string(FIND "${owner_source}" "bridge_->prepareNextServerInitializationPdu()" bridge_prepare)
if(schedule_ready LESS 0 OR schedule_prepare LESS_EQUAL schedule_ready OR
   schedule_queue LESS_EQUAL schedule_prepare OR owner_prepare LESS 0 OR
   bridge_prepare LESS_EQUAL owner_prepare)
    message(FATAL_ERROR "R10/R8 initial Clipboard preparation is not receipt-ordered")
endif()
math(EXPR owner_prepare_length "${bridge_prepare} - ${owner_prepare}")
string(SUBSTRING "${owner_source}" ${owner_prepare}
    ${owner_prepare_length} owner_prepare_source)
string(FIND "${owner_prepare_source}"
    "connection.visitPersonalDesktopClipboardChannel(" preparation_scope)
if(preparation_scope LESS 0)
    message(FATAL_ERROR "R8 initialization preparation lacks fresh R2 scope")
endif()


# R8 must forward only positive R1 accepted-byte receipts into the bridge.
# Zero-byte scheduler probes and TLS WANT results retain write ownership and
# cannot clear writePending_ or advance the initialization stage.
string(FIND "${owner_source}" "bool advanceTlsWrite(" receipt_begin)
string(FIND "${owner_source}" "void retire() noexcept" receipt_end)
if(receipt_begin LESS 0 OR receipt_end LESS_EQUAL receipt_begin)
    message(FATAL_ERROR "unable to isolate R8 accepted-byte receipt handoff")
endif()
math(EXPR receipt_length "${receipt_end} - ${receipt_begin}")
string(SUBSTRING "${owner_source}" ${receipt_begin}
    ${receipt_length} receipt_source)
set(previous_position -1)
foreach(required_text IN ITEMS
        "if (result.acceptedBytes != 0U &&"
        "!bridge_->recordAcceptedWriteReceipt("
        "switch (result.status)"
        "case Step::NeedRead:"
        "case Step::NeedWrite:"
        "case Step::Delivered:"
        "writePending_ = false;")
    string(FIND "${receipt_source}" "${required_text}" position)
    if(position LESS 0 OR position LESS_EQUAL previous_position)
        message(FATAL_ERROR
            "R8 accepted-byte receipt handoff lost zero/WANT/delivery ordering: ${required_text}")
    endif()
    set(previous_position ${position})
endforeach()

# Pin R1's producer side too: WANT/no-readiness paths return zero bytes with a
# Pending receipt, while Delivered follows positive TLS bytes and R3 completion.
string(FIND "${connection_source}"
    "LinuxRuntimeConnection::advancePersonalDesktopClipboardTlsWrite("
    connection_receipt_begin)
string(FIND "${connection_source}"
    "void LinuxRuntimeConnection::revoke() noexcept" connection_receipt_end)
if(connection_receipt_begin LESS 0 OR
   connection_receipt_end LESS_EQUAL connection_receipt_begin)
    message(FATAL_ERROR "unable to isolate production R1 Clipboard writer")
endif()
math(EXPR connection_receipt_length
    "${connection_receipt_end} - ${connection_receipt_begin}")
string(SUBSTRING "${connection_source}" ${connection_receipt_begin}
    ${connection_receipt_length} connection_receipt_source)
foreach(required_text IN ITEMS
        "return {0U, Outcome::Pending, Step::NeedRead};"
        "return {0U, Outcome::Pending, Step::NeedWrite};"
        "const auto io = connection_.writeTlsApplicationData(payload);"
        "const auto receipt = completePersonalDesktopClipboardWrite("
        "return {io.bytes, receipt, Step::Delivered, offeredBytes,")
    string(FIND "${connection_receipt_source}" "${required_text}" found)
    if(found LESS 0)
        message(FATAL_ERROR
            "R1 Clipboard zero/WANT/Delivered receipt contract missing: ${required_text}")
    endif()
endforeach()

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
