# SPDX-License-Identifier: GPL-3.0-or-later
# R10 production scheduler contract: no second TLS/TPKT reader and no live
# admission fixture. Fail closed if main stops keeping the R2/R3/R5 owner.
foreach(argument IN ITEMS RDP_RUNTIME_ENTRYPOINT_SOURCE
        RDP_RUNTIME_CONNECTION_HEADER RDP_RUNTIME_CONNECTION_SOURCE)
    if(NOT DEFINED ${argument} OR "${${argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing ${argument}")
    endif()
endforeach()
file(READ "${RDP_RUNTIME_ENTRYPOINT_SOURCE}" runtime_source)
file(READ "${RDP_RUNTIME_CONNECTION_HEADER}" connection_header)
file(READ "${RDP_RUNTIME_CONNECTION_SOURCE}" connection_source)

foreach(needed IN ITEMS
        "while (connection.ready() && nativeOwner.desktop->valid())"
        "registerNativeChange()"
        "unregisterNativeChange(*nativeChange)"
        "releaseNativeChangeWithoutDispatch(*nativeChange)"
        "dispatchNativeChangeReady(*nativeChange)"
        "::poll(nativePoll.data()"
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
