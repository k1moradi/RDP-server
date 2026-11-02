# SPDX-License-Identifier: GPL-3.0-or-later
# R10 production scheduler contract: no second TLS/TPKT reader and no live
# admission fixture. Fail closed if main stops keeping the R2/R3/R5 owner.
foreach(argument IN ITEMS RDP_RUNTIME_ENTRYPOINT_SOURCE
        RDP_RUNTIME_CONNECTION_HEADER RDP_RUNTIME_CONNECTION_SOURCE
        RDP_RUNTIME_HOST_CONTROL_SOURCE)
    if(NOT DEFINED ${argument} OR "${${argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${argument}")
    endif()
endforeach()
file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)
file(READ "${RDP_RUNTIME_CONNECTION_HEADER}" connection_header)
file(READ "${RDP_RUNTIME_CONNECTION_SOURCE}" connection_source)
file(READ "${RDP_RUNTIME_HOST_CONTROL_SOURCE}" host_control_source)

foreach(needed IN ITEMS
        "while (connection.ready() && nativeOwner.desktop->valid())"
        "registerNativeChange()"
        "unregisterNativeChange(*nativeChange)"
        "releaseNativeChangeWithoutDispatch("
        "dispatchNativeChangeReady(*nativeChange)"
        "::poll("
        "nativePoll.data(), static_cast<nfds_t>(nativePoll.size())"
        "nativeSocketPollDescriptor()"
        "bufferedTlsApplicationReadReady()"
        "advancePersonalDesktopPostShareApplicationRead("
        "Kind::GraphicsDynamicVirtualChannel"
        "Kind::SlowPathInput"
        "consumeR4Frame("
        "startPersonalDesktopClearCodecFramePublication("
        "frameWritePending = true"
        "retireAfterAuthorizationLoss()")
    string(FIND "${runtime_source}" "${needed}" index)
    if(index EQUAL -1)
        message(FATAL_ERROR "Missing R10 production loop boundary: ${needed}")
    endif()
endforeach()
foreach(needed IN ITEMS
        "releaseNativeChangeWithoutDispatch("
        "nativeSocketPollDescriptor() const noexcept"
        "bufferedTlsApplicationReadReady() const noexcept")
    string(FIND "${connection_header}" "${needed}" index)
    if(index EQUAL -1)
        message(FATAL_ERROR "Missing R10 borrowed owner API: ${needed}")
    endif()
endforeach()
foreach(needed IN ITEMS
        "readTlsApplicationData("
        "personalGraphicsDvcFrameReader_.consume("
        "classifyPersonalDesktopPostShareTpkt("
        "consumeR3PersonalDesktopGraphicsFrameAcknowledge("
        "connection_.nativeSocket()")
    string(FIND "${connection_source}" "${needed}" index)
    if(index EQUAL -1)
        message(FATAL_ERROR "Missing existing R1/R2/R3 backing: ${needed}")
    endif()
endforeach()
# Guard both halves of the native watcher call: the real R10 scheduler
# wraps arguments across lines, while the R5 pre-dispatch guard independently
# checks unregistration and retirement before X11/TLS callbacks.
string(FIND "${runtime_source}" "releaseNativeChangeWithoutDispatch(" release_call)
string(FIND "${runtime_source}" "connection.unregisterNativeChange(*nativeChange)" unregister_call)
if(release_call EQUAL -1 OR unregister_call EQUAL -1 OR
   release_call LESS unregister_call)
    message(FATAL_ERROR
        "R10 post-Share native borrow is not retired after unregistration")
endif()

# The publication borrow context must remain stack-owned without casting
# away constness to satisfy a callback ABI.
string(FIND "${runtime_source}" "const_cast<LinuxFramePublicationContext" bad_borrow)
if(NOT bad_borrow EQUAL -1)
    message(FATAL_ERROR "R10 must not cast away native frame borrow constness")
endif()
# R10 may call exactly the established R1-owned TLS application reader.
string(FIND "${runtime_source}" "SSL_read_ex" extra_tls_reader)
if(NOT extra_tls_reader EQUAL -1)
    message(FATAL_ERROR "R10 main must never introduce a second TLS reader")
endif()

# R10/R4 64-frame ACK credit must be preflighted before the R5 XShm borrow.
# A deferred frame may neither consume an ID nor encode/arm an R1 writer.
function(normalize_linux_frame_credit_source source result)
    # Ignore comments and formatting: commented-out gates must not pass.
    string(REGEX REPLACE "/\\*([^*]|\\*+[^*/])*\\*+/" " "
        without_blocks "${source}")
    string(REGEX REPLACE "//[^\n]*" " " without_comments
        "${without_blocks}")
    string(REGEX REPLACE "[ \t\r\n]+" " " normalized "${without_comments}")
    set(${result} "${normalized}" PARENT_SCOPE)
endfunction()

function(check_linux_frame_credit_before_native_borrow source result)
    normalize_linux_frame_credit_source("${source}" normalized)
    string(REGEX MATCH
        "if[ ]*\\([ ]*!frameWritePending[ ]*&&[ ]*postIoNow[ ]*>=[ ]*nextCapture[ ]*\\)[ ]*\\{"
        capture_branch "${normalized}")
    if(capture_branch STREQUAL "")
        set(${result} "missing post-Share capture branch" PARENT_SCOPE)
        return()
    endif()
    string(FIND "${normalized}" "${capture_branch}" capture_offset)
    string(SUBSTRING "${normalized}" ${capture_offset} -1 schedule)
    # Scope to the frame success path, excluding the legitimate prior
    # R3 DELETE/CREATE/MAP writer arming on reconfiguration.
    string(REGEX MATCH
        "\\+\\+[ ]*nextFrameId[ ]*;[ ]*frameWritePending[ ]*=[ ]*true[ ]*;"
        success_tail "${schedule}")
    if(success_tail STREQUAL "")
        set(${result} "missing frame-ID/write commitment" PARENT_SCOPE)
        return()
    endif()
    string(FIND "${schedule}" "${success_tail}" success_offset)
    string(SUBSTRING "${schedule}" 0 ${success_offset} frame_path)

    string(REGEX MATCH
        "if[ ]*\\([ ]*nextFrameId[ ]*==[ ]*0U[ ]*\\)[ ]*\\{[ ]*break[ ]*;[ ]*\\}"
        frame_id_guard "${frame_path}")
    string(REGEX MATCH
        "connection[ ]*\\.[ ]*preflightPersonalDesktopGraphicsFramePublication[ ]*\\("
        credit_preflight "${frame_path}")
    string(REGEX MATCH
        "nativeOwner[ ]*\\.[ ]*desktop[ ]*->[ ]*consumeR4Frame[ ]*\\("
        native_borrow "${frame_path}")
    string(REGEX MATCH
        "if[ ]*\\([ ]*readiness[ ]*==[ ]*Readiness::DeferredForFrameAcknowledge[ ]*\\)[ ]*\\{[^{}]*\\}"
        deferred_branch "${frame_path}")
    string(REGEX MATCH
        "if[ ]*\\([ ]*readiness[ ]*!=[ ]*Readiness::Ready"
        ready_gate "${frame_path}")
    if(frame_id_guard STREQUAL "" OR credit_preflight STREQUAL "" OR
       deferred_branch STREQUAL "" OR ready_gate STREQUAL "" OR
       native_borrow STREQUAL "")
        set(${result} "missing frame-ID/preflight/defer/Ready/borrow gate" PARENT_SCOPE)
        return()
    endif()
    string(FIND "${frame_path}" "${frame_id_guard}" id_offset)
    string(FIND "${frame_path}" "${credit_preflight}" preflight_offset)
    string(FIND "${frame_path}" "${deferred_branch}" deferred_offset)
    string(FIND "${frame_path}" "${ready_gate}" ready_offset)
    string(FIND "${frame_path}" "${native_borrow}" borrow_offset)
    if(NOT id_offset LESS preflight_offset OR
       NOT preflight_offset LESS deferred_offset OR
       NOT deferred_offset LESS ready_offset OR
       NOT ready_offset LESS borrow_offset)
        set(${result} "credit preflight/defer/Ready must precede native borrow" PARENT_SCOPE)
        return()
    endif()
    string(REGEX MATCH "continue[ ]*;[ ]*\\}$"
        terminal_continue "${deferred_branch}")
    if(terminal_continue STREQUAL "")
        set(${result} "deferred ACK credit must terminate with continue" PARENT_SCOPE)
        return()
    endif()
    math(EXPR before_borrow_length "${borrow_offset} - ${id_offset}")
    string(SUBSTRING "${frame_path}" ${id_offset} ${before_borrow_length}
        pre_borrow)
    string(REGEX MATCH
        "frameWritePending[ ]*=[ ]*true|\\+\\+[ ]*nextFrameId|startPersonalDesktopClearCodecFramePublication[ ]*\\(|consumeR4Frame[ ]*\\("
        premature_frame_work "${pre_borrow}")
    if(NOT premature_frame_work STREQUAL "")
        set(${result} "write/ID/encoder/native work before credit-approved borrow" PARENT_SCOPE)
        return()
    endif()
    # The frame callback remains scoped to the synchronous native borrow;
    # failure breaks before any ID/write commitment.
    string(SUBSTRING "${schedule}" ${borrow_offset} -1 after_borrow)
    string(REGEX MATCH
        "X11R4BgraFrameConsumer[ ]*\\{[ ]*&frameContext[ ]*,[ ]*&publishLinuxCapturedFrame[ ]*\\}"
        original_consumer "${after_borrow}")
    string(REGEX MATCH
        "\\{[ ]*break[ ]*;[ ]*\\}[ ]*\\+\\+[ ]*nextFrameId[ ]*;[ ]*frameWritePending[ ]*=[ ]*true[ ]*;"
        successful_consumption "${after_borrow}")
    if(original_consumer STREQUAL "" OR successful_consumption STREQUAL "")
        set(${result} "borrow callback/failure must precede frame-ID/write commitment" PARENT_SCOPE)
        return()
    endif()
    set(${result} "" PARENT_SCOPE)
endfunction()

check_linux_frame_credit_before_native_borrow("${runtime_source}" contract_error)
if(NOT contract_error STREQUAL "")
    message(FATAL_ERROR "R10 ACK-credit pre-borrow contract: ${contract_error}")
endif()

# Exercise three negative controls in the existing registered source CTest;
# no duplicate CTest, client, physical X11 session or alternate writer.
normalize_linux_frame_credit_source("${runtime_source}" normalized_runtime)
string(REGEX MATCH
    "if[ ]*\\([ ]*readiness[ ]*==[ ]*Readiness::DeferredForFrameAcknowledge[ ]*\\)[ ]*\\{[^{}]*\\}"
    original_deferred "${normalized_runtime}")
string(REGEX MATCH
    "connection[ ]*\\.[ ]*preflightPersonalDesktopGraphicsFramePublication[ ]*\\("
    original_preflight "${normalized_runtime}")
if(original_deferred STREQUAL "" OR original_preflight STREQUAL "")
    message(FATAL_ERROR "R10 frame-credit negative control has no source anchor")
endif()
string(REGEX REPLACE "continue[ ]*;" "" removed_continue "${original_deferred}")
string(REPLACE "${original_deferred}" "${removed_continue}"
    no_continue_source "${normalized_runtime}")
string(REPLACE "${original_preflight}"
    "nativeOwner.desktop->consumeR4Frame(geometry); ${original_preflight}"
    early_borrow_source "${normalized_runtime}")
string(REPLACE "${original_deferred}"
    "frameWritePending = true; ${original_deferred}"
    early_writer_source "${normalized_runtime}")
foreach(mutation IN ITEMS no_continue early_borrow early_writer)
    check_linux_frame_credit_before_native_borrow(
        "${${mutation}_source}" negative_error)
    if(negative_error STREQUAL "")
        message(FATAL_ERROR "R10 frame-credit guard accepted ${mutation} mutation")
    endif()
endforeach()


# The Linux GUI HostControl has a separate post-Share scheduler. Unlike the
# serve-loop continue above, its ACK-credit deferral returns from one tick.
# Limit frame-only checks to after R3 DELETE/CREATE/MAP reconfiguration:
# those control writes legitimately arm graphicsWritePending before this gate.
function(check_linux_host_control_credit_fence source result)
    normalize_linux_frame_credit_source("${source}" normalized)
    string(REGEX MATCH
        "if[ ]*\\([ ]*nativeDesktop_[ ]*->[ ]*nextFrameId[ ]*==[ ]*0U[ ]*\\)"
        frame_id_guard "${normalized}")
    if(frame_id_guard STREQUAL "")
        set(${result} "missing HostControl frame-ID guard" PARENT_SCOPE)
        return()
    endif()
    string(FIND "${normalized}" "${frame_id_guard}" frame_offset)
    string(SUBSTRING "${normalized}" ${frame_offset} -1 schedule)
    string(REGEX MATCH
        "\\+\\+[ ]*nativeDesktop_[ ]*->[ ]*nextFrameId[ ]*;[ ]*nativeDesktop_[ ]*->[ ]*graphicsWritePending[ ]*=[ ]*true[ ]*;[ ]*nativeDesktop_[ ]*->[ ]*framePublicationPending[ ]*=[ ]*true[ ]*;"
        commitment "${schedule}")
    if(commitment STREQUAL "")
        set(${result} "missing HostControl frame commitment" PARENT_SCOPE)
        return()
    endif()
    string(FIND "${schedule}" "${commitment}" commitment_offset)
    string(SUBSTRING "${schedule}" 0 ${commitment_offset} frame_path)
    string(REGEX MATCH
        "acceptedClient_[ ]*->[ ]*preflightPersonalDesktopGraphicsFramePublication[ ]*\\("
        credit_preflight "${frame_path}")
    string(REGEX MATCH
        "if[ ]*\\([ ]*readiness[ ]*==[ ]*Readiness::DeferredForFrameAcknowledge[ ]*\\)[ ]*\\{[^{}]*return[ ]*\\{[ ]*RuntimeHostError::None[ ]*,[ ]*true[ ]*\\}[ ]*;[ ]*\\}"
        deferred_exit "${frame_path}")
    string(REGEX MATCH
        "if[ ]*\\([ ]*readiness[ ]*!=[ ]*Readiness::Ready"
        ready_gate "${frame_path}")
    string(REGEX MATCH
        "nativeDesktop_[ ]*->[ ]*desktop[ ]*->[ ]*nativeGeometryIsCurrent[ ]*\\("
        current_geometry "${frame_path}")
    string(REGEX MATCH
        "nativeDesktop_[ ]*->[ ]*desktop[ ]*->[ ]*consumeR4Frame[ ]*\\("
        native_borrow "${frame_path}")
    if(credit_preflight STREQUAL "" OR deferred_exit STREQUAL "" OR
       ready_gate STREQUAL "" OR current_geometry STREQUAL "" OR
       native_borrow STREQUAL "")
        set(${result} "missing HostControl credit/defer/Ready/geometry/borrow gate" PARENT_SCOPE)
        return()
    endif()
    string(FIND "${frame_path}" "${credit_preflight}" preflight_offset)
    string(FIND "${frame_path}" "${deferred_exit}" deferred_offset)
    string(FIND "${frame_path}" "${ready_gate}" ready_offset)
    string(FIND "${frame_path}" "${current_geometry}" geometry_offset)
    string(FIND "${frame_path}" "${native_borrow}" borrow_offset)
    if(NOT preflight_offset LESS deferred_offset OR
       NOT deferred_offset LESS ready_offset OR
       NOT ready_offset LESS geometry_offset OR
       NOT geometry_offset LESS borrow_offset)
        set(${result} "HostControl credit/defer/Ready/geometry must precede native borrow" PARENT_SCOPE)
        return()
    endif()
    string(SUBSTRING "${frame_path}" 0 ${borrow_offset} before_borrow)
    string(REGEX MATCH
        "consumeR4Frame[ ]*\\(|startPersonalDesktopClearCodecFramePublication[ ]*\\(|authorizeR3PersonalDesktopClearCodecFramePublication[ ]*\\(|reserve[A-Za-z0-9_]*Frame[ ]*\\(|\\+\\+[ ]*nativeDesktop_[ ]*->[ ]*nextFrameId|nativeDesktop_[ ]*->[ ]*(graphicsWritePending|framePublicationPending)[ ]*=[ ]*true"
        premature_work "${before_borrow}")
    if(NOT premature_work STREQUAL "")
        set(${result} "HostControl native/encoder/reservation/ID/writer before approved borrow" PARENT_SCOPE)
        return()
    endif()
    # The original synchronous callback must fail/retire before the frame ID
    # increment and sole Graphics writer arming.
    string(SUBSTRING "${schedule}" ${borrow_offset} -1 after_borrow)
    string(REGEX MATCH
        "X11R4BgraFrameConsumer[ ]*\\{[ ]*&frameContext[ ]*,[ ]*&publishHostCapturedFrame[ ]*\\}[ ]*\\)[ ]*\\)[ ]*return[ ]*retireClient[ ]*\\([ ]*RuntimeHostError::GraphicsUnavailable[ ]*\\)[ ]*;[ ]*\\+\\+[ ]*nativeDesktop_[ ]*->[ ]*nextFrameId"
        failure_before_commit "${after_borrow}")
    if(failure_before_commit STREQUAL "")
        set(${result} "HostControl callback/failure must precede ID and Graphics writer" PARENT_SCOPE)
        return()
    endif()
    set(${result} "" PARENT_SCOPE)
endfunction()

check_linux_host_control_credit_fence("${host_control_source}" host_contract_error)
if(NOT host_contract_error STREQUAL "")
    message(FATAL_ERROR "R10 HostControl ACK-credit pre-borrow: ${host_contract_error}")
endif()

# Mutate the actual HostControl source: an omitted terminal return, early XShm
# borrow, early TLS writer or premature ClearCodec start must each fail.
normalize_linux_frame_credit_source("${host_control_source}" normalized_host)
string(REGEX MATCH
    "if[ ]*\\([ ]*readiness[ ]*==[ ]*Readiness::DeferredForFrameAcknowledge[ ]*\\)[ ]*\\{[^{}]*return[ ]*\\{[ ]*RuntimeHostError::None[ ]*,[ ]*true[ ]*\\}[ ]*;[ ]*\\}"
    original_host_deferred "${normalized_host}")
string(REGEX MATCH
    "acceptedClient_[ ]*->[ ]*preflightPersonalDesktopGraphicsFramePublication[ ]*\\("
    original_host_preflight "${normalized_host}")
if(original_host_deferred STREQUAL "" OR original_host_preflight STREQUAL "")
    message(FATAL_ERROR "R10 HostControl mutation controls lack source anchors")
endif()
string(REGEX REPLACE "return[ ]*\\{[ ]*RuntimeHostError::None[ ]*,[ ]*true[ ]*\\}[ ]*;" ""
    removed_host_return "${original_host_deferred}")
string(REPLACE "${original_host_deferred}" "${removed_host_return}"
    host_no_return_source "${normalized_host}")
string(REPLACE "${original_host_preflight}"
    "nativeDesktop_->desktop->consumeR4Frame(geometry); ${original_host_preflight}"
    host_early_borrow_source "${normalized_host}")
string(REPLACE "${original_host_deferred}"
    "nativeDesktop_->graphicsWritePending = true; ${original_host_deferred}"
    host_early_writer_source "${normalized_host}")
string(REPLACE "${original_host_preflight}"
    "acceptedClient_->startPersonalDesktopClearCodecFramePublication(); ${original_host_preflight}"
    host_early_encoder_source "${normalized_host}")
foreach(mutation IN ITEMS host_no_return host_early_borrow host_early_writer host_early_encoder)
    check_linux_host_control_credit_fence("${${mutation}_source}" negative_error)
    if(negative_error STREQUAL "")
        message(FATAL_ERROR "R10 HostControl credit guard accepted ${mutation} mutation")
    endif()
endforeach()
