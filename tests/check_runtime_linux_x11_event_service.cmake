# SPDX-License-Identifier: GPL-3.0-or-later
# R5 source guard for the production X11 event handoff. No real desktop,
# lease, systemd service, socket listener or XTEST operation is exercised.
if(NOT DEFINED RDP_RUNTIME_ENTRYPOINT_SOURCE OR
   "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" STREQUAL "")
    message(FATAL_ERROR "Missing production runtime source")
endif()
file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)

# Restrict the check to the actual serialized R10 native branch, not a
# synthetic test helper or an unrelated native adapter implementation.
string(FIND "${runtime_source}"
    "if (!connection.unregisterNativeChange(*nativeChange))" unregistration)
string(FIND "${runtime_source}"
    "const ConnectionStatus nativeDispatch =" native_dispatch)
string(FIND "${runtime_source}"
    "nativeOwner.desktop->disconnect();" graceful_retirement)
if(unregistration EQUAL -1 OR native_dispatch EQUAL -1 OR
   graceful_retirement EQUAL -1 OR
   NOT unregistration LESS native_dispatch OR
   NOT native_dispatch LESS graceful_retirement)
    message(FATAL_ERROR
        "R5 XCB dispatch must follow R2 borrowed-watch unregistration and precede native teardown")
endif()

math(EXPR span_length "${graceful_retirement} - ${unregistration}")
string(SUBSTRING "${runtime_source}" ${unregistration} ${span_length}
    owner_handoff)

foreach(required IN ITEMS
        "connection.authorizePersonalDesktopApplicationTraffic("
        "nativeOwner.desktop->processEvents("
        "nativeWorkMayRemain"
        "(x11Events & POLLIN) != 0"
        "nativeDispatch != ConnectionStatus::Ok"
        "nativeOwner.desktop->retireAfterAuthorizationLoss()"
        "captureGeneration() == 0U")
    string(FIND "${owner_handoff}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "R5 native event handoff missing: ${required}")
    endif()
endforeach()

# No caller-controlled display, fake admission, queued frame or input dispatch
# is permitted inside this bounded, no-publication native-service increment.
foreach(forbidden IN ITEMS
        "getenv("
        "startPersonalDesktopGraphicsFramePublication("
        "X11AuthorizedInputRoute::dispatch("
        "consumeR4Frame("
        "XTestFake")
    string(FIND "${owner_handoff}" "${forbidden}" position)
    if(NOT position EQUAL -1)
        message(FATAL_ERROR "R5 native event handoff contains forbidden action: ${forbidden}")
    endif()
endforeach()

# The same production R2 authorizer must appear on both sides of the
# callback. An R2 failure must retire native input without a post-revoke
# held-key/button release before the serialized connection is revoked.
string(REGEX MATCHALL
    "connection[.]authorizePersonalDesktopApplicationTraffic[(]"
    authorizations "${owner_handoff}")
list(LENGTH authorizations authorization_count)
if(NOT authorization_count EQUAL 2)
    message(FATAL_ERROR
        "R5 XCB callback must have exactly two fresh R2 authorization checks")
endif()
string(FIND "${owner_handoff}"
    "nativeOwner.desktop->processEvents(" invocation)
string(FIND "${owner_handoff}"
    "connection.authorizePersonalDesktopApplicationTraffic(" first_authorization)
string(FIND "${owner_handoff}"
    "connection.authorizePersonalDesktopApplicationTraffic("
    last_authorization REVERSE)
if(NOT first_authorization LESS invocation OR
   NOT invocation LESS last_authorization)
    message(FATAL_ERROR
        "R5 native event callback missing pre-/post-dispatch R2 fences")
endif()

message(STATUS
    "R5 sole-owner XCB event servicing is bounded, authority-fenced and no-publication")
