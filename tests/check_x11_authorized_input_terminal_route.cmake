# SPDX-License-Identifier: GPL-3.0-or-later
# R5's legacy direct gateway and the R10 post-Share R2 callback must agree
# that native input failure is terminal. This offline source test cannot
# fabricate a positive authentication/PAM/logind R2 lease or call XTEST.
if(NOT DEFINED RDP_R5_AUTHORIZED_INPUT_SOURCE OR
   "${RDP_R5_AUTHORIZED_INPUT_SOURCE}" STREQUAL "")
    message(FATAL_ERROR "Missing R5 production input route source")
endif()
file(READ "${RDP_R5_AUTHORIZED_INPUT_SOURCE}" source)
string(FIND "${source}" "X11AuthorizedInputRoute::dispatch(" beginning)
string(FIND "${source}" "namespace\n{" ending)
if(beginning EQUAL -1 OR ending EQUAL -1 OR
   NOT beginning LESS ending)
    message(FATAL_ERROR "Missing legacy R5 direct route boundary")
endif()
math(EXPR span "${ending} - ${beginning}")
string(SUBSTRING "${source}" ${beginning} ${span} direct_route)
string(REGEX REPLACE "[ \t\r\n]+" "" normalized "${direct_route}")

# Fresh R2 permission recheck is mandatory before native injection. A
# failure must suppress all XTEST input before revoking the exact R3 lease.
foreach(required IN ITEMS
        "broker.authorizeR3ProtectedTransition("
        "kConsoleInputPermission"
        "if(!desktop.handleAuthorizedInput(expectedNativeGeneration,event)){"
        "desktop.retireAfterAuthorizationLoss();"
        "broker.revokeR3Session(principalProof,session);")
    string(FIND "${normalized}" "${required}" found)
    if(found EQUAL -1)
        message(FATAL_ERROR "R5 direct route missing protected input terminal fence: ${required}")
    endif()
endforeach()
string(FIND "${normalized}" "desktop.disconnect(" graceful)
if(NOT graceful EQUAL -1)
    message(FATAL_ERROR "R5 native injection failure cannot use graceful XTEST disconnect")
endif()
string(FIND "${normalized}"
    "if(!desktop.handleAuthorizedInput(expectedNativeGeneration,event)){" failure)
string(SUBSTRING "${normalized}" ${failure} -1 terminal)
string(FIND "${terminal}" "desktop.retireAfterAuthorizationLoss();" retire)
string(FIND "${terminal}" "broker.revokeR3Session(principalProof,session);" revoke)
string(FIND "${terminal}" "returnfalse;" denied)
if(retire EQUAL -1 OR revoke EQUAL -1 OR denied EQUAL -1 OR
   NOT retire LESS revoke OR NOT revoke LESS denied)
    message(FATAL_ERROR "R5 native failure must retire input, revoke R3, and deny in that order")
endif()
# R10-owned runtime must call the already-existing typed R2-protected
# callback. The file's terminal failures must never reintroduce cleanup.
string(FIND "${source}"
    "X11AuthorizedInputRoute::onAuthenticatedInput(" callback)
string(FIND "${source}"
    "X11AuthorizedInputRoute::dispatchAuthenticatedSlowPathTpkt("
    authenticated)
if(callback EQUAL -1 OR authenticated EQUAL -1 OR
   NOT callback LESS authenticated)
    message(FATAL_ERROR "R5 authenticated R2 callback missing")
endif()
message(STATUS "R5 direct and authenticated input failures use terminal no-XTEST retirement")
