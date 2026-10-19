# SPDX-License-Identifier: GPL-3.0-or-later
# R5 production source guard for R10's persistent, R2-selected XCB owner.
# This is offline source-contract evidence, never native admission or XTEST.
if(NOT DEFINED RDP_RUNTIME_ENTRYPOINT_SOURCE OR
   "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" STREQUAL "")
    message(FATAL_ERROR "Missing production runtime source")
endif()
file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)

# Inspect only the serialized live scheduler, not a helper or legacy one-shot
# native poll. The final no-XTEST retirement is deliberately after the loop.
string(FIND "${runtime_source}"
    "while (connection.ready() && nativeOwner.desktop->valid())" owner_loop)
string(FIND "${runtime_source}"
    "if (!connection.unregisterNativeChange(*nativeChange))" unregistration)
string(FIND "${runtime_source}"
    "nativeOwner.desktop->processEvents(" native_dispatch)
string(FIND "${runtime_source}"
    "nativeOwner.desktop->retireAfterAuthorizationLoss();"
    terminal_retirement REVERSE)
if(owner_loop EQUAL -1 OR unregistration EQUAL -1 OR
   native_dispatch EQUAL -1 OR terminal_retirement EQUAL -1 OR
   NOT owner_loop LESS unregistration OR
   NOT unregistration LESS native_dispatch OR
   NOT native_dispatch LESS terminal_retirement)
    message(FATAL_ERROR
        "R5 persistent XCB owner must unregister R2 watch before dispatch and retire without native input")
endif()

math(EXPR span_length "${terminal_retirement} - ${unregistration}")
string(SUBSTRING "${runtime_source}" ${unregistration} ${span_length}
    owner_handoff)
foreach(required IN ITEMS
        "connection.authorizePersonalDesktopApplicationTraffic("
        "nativeOwner.desktop->processEvents("
        "nativeWorkMayRemain = moreX11Events"
        "(x11Events & POLLIN) != 0"
        "128U, &moreX11Events"
        "ConnectionStatus::Ok"
        "nativeOwner.desktop->captureGeneration() == 0U"
        "connection.advancePersonalDesktopPostShareApplicationRead("
        "nativeOwner.desktop->consumeR4Frame("
        "nativeOwner.desktop->retireAfterAuthorizationLoss()")
    string(FIND "${owner_handoff}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "R5 persistent native handoff missing: ${required}")
    endif()
endforeach()

# R2's native-change registration is borrowed only for poll; the scheduler
# must retire it before any native, TLS or Graphics callback.
math(EXPR before_dispatch_length "${native_dispatch} - ${unregistration}")
string(SUBSTRING "${runtime_source}" ${unregistration}
    ${before_dispatch_length} before_dispatch)
foreach(required IN ITEMS
        "connection.dispatchNativeChangeReady(*nativeChange)"
        "connection.releaseNativeChangeWithoutDispatch("
        "connection.authorizePersonalDesktopApplicationTraffic(")
    string(FIND "${before_dispatch}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "R5 watch retirement/pre-dispatch fence missing: ${required}")
    endif()
endforeach()

# Fresh authorization after the XCB drain must precede the first R1 read or
# R4 full-frame borrow, so an expired R2 lease cannot publish stale input.
string(FIND "${owner_handoff}"
    "connection.advancePersonalDesktopPostShareApplicationRead(" tls_read)
string(FIND "${owner_handoff}"
    "nativeOwner.desktop->consumeR4Frame(" frame_borrow)
string(FIND "${owner_handoff}"
    "nativeOwner.desktop->processEvents(" native_events)
string(FIND "${owner_handoff}"
    "connection.authorizePersonalDesktopApplicationTraffic(" pre_authorization)
string(FIND "${owner_handoff}"
    "connection.authorizePersonalDesktopApplicationTraffic("
    post_authorization REVERSE)
if(NOT pre_authorization LESS native_events OR
   NOT native_events LESS post_authorization OR
   NOT post_authorization LESS frame_borrow OR
   NOT native_events LESS tls_read OR
   NOT tls_read LESS frame_borrow)
    message(FATAL_ERROR
        "R5 events, R2 authorization, sole TLS intake and R4 frame borrow are misordered")
endif()
string(REGEX MATCHALL
    "connection[.]authorizePersonalDesktopApplicationTraffic[(]"
    authorizations "${owner_handoff}")
list(LENGTH authorizations authorization_count)
if(NOT authorization_count EQUAL 2)
    message(FATAL_ERROR
        "R5 native callback must have exactly two R2 fences after borrowed-watch unregistration")
endif()

# The X11 callback may not spawn a second native owner, bypass R2 or obtain
# another socket/TLS reader. Publication is allowed only through the new R10
# authenticated R3/R4 pipeline, unlike the prior one-shot handoff.
foreach(forbidden IN ITEMS
        "getenv("
        "XTestFake"
        "X11AuthorizedInputRoute::dispatch("
        "SSL_read_ex"
        "nativeOwner.desktop->disconnect()")
    string(FIND "${owner_handoff}" "${forbidden}" position)
    if(NOT position EQUAL -1)
        message(FATAL_ERROR "R5 persistent owner contains forbidden bypass: ${forbidden}")
    endif()
endforeach()

if(RDP_R5_PERSISTENT_FRAME_GATE)
    # Complete R1/R3-classified input is consumed by R5's existing R2
    # per-event sink; raw input and clipboard trial-dispatch remain forbidden.
    string(FIND "${runtime_source}" "case Kind::SlowPathInput:" slow_path)
    string(FIND "${runtime_source}"
        "X11AuthorizedInputRoute::dispatchAuthenticatedSlowPathTpkt(" input_sink)
    string(FIND "${runtime_source}"
        "case Kind::ClipboardStaticChannel:" clipboard)
    string(FIND "${owner_handoff}" "X11R4BgraFrameConsumer{" callback)
    # R10's native-resize scheduler also sets frameWritePending before capture
    # while it drains DELETE -> CREATE -> MAP. Anchor the publication-pending
    # assertion to the tail beginning at the actual synchronous R4 borrow so
    # that the guard distinguishes remap writes from frame publication.
    if(frame_borrow EQUAL -1)
        set(publication_pending -1)
    else()
        string(SUBSTRING "${owner_handoff}" ${frame_borrow} -1
            frame_publication_tail)
        string(FIND "${frame_publication_tail}"
            "frameWritePending = true" publication_pending)
    endif()
    string(FIND "${runtime_source}"
        "startPersonalDesktopClearCodecFramePublication(" frame_sink)
    if(slow_path EQUAL -1 OR input_sink EQUAL -1 OR clipboard EQUAL -1 OR
       callback EQUAL -1 OR publication_pending EQUAL -1 OR
       frame_sink EQUAL -1 OR
       NOT slow_path LESS input_sink OR NOT input_sink LESS clipboard OR
       NOT tls_read LESS frame_borrow)
        message(FATAL_ERROR
            "R5 persistent input must use R2 gateway and frame publication must use synchronous R4 borrow")
    endif()
    foreach(forbidden IN ITEMS
            "X11AuthorizedInputRoute::dispatch("
            "nativeOwner.desktop->capture("
            "const_cast<LinuxFramePublicationContext"
            "SSL_read_ex")
        string(FIND "${runtime_source}" "${forbidden}" position)
        if(NOT position EQUAL -1)
            message(FATAL_ERROR "R5 persistent bridge bypass: ${forbidden}")
        endif()
    endforeach()
endif()

message(STATUS
    "R5 persistent XCB owner: R2 watch retired, fresh fences, classified input and synchronous borrowed XShm frame")
