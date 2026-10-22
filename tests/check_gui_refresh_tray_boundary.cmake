# SPDX-License-Identifier: GPL-3.0-or-later
if(NOT DEFINED RDP_DESKTOP_WINDOW_SOURCE)
    message(FATAL_ERROR "RDP_DESKTOP_WINDOW_SOURCE is required")
endif()

file(READ "${RDP_DESKTOP_WINDOW_SOURCE}" source)

string(FIND "${source}" "void DesktopWindow::updateTray(" update_start)
string(FIND "${source}" "void DesktopWindow::refresh()" refresh_start)
string(FIND "${source}" "void DesktopWindow::closeEvent(" close_start)
if(update_start EQUAL -1 OR refresh_start EQUAL -1 OR close_start EQUAL -1)
    message(FATAL_ERROR "GUI tray/refresh lifecycle function marker missing")
endif()
if(NOT update_start LESS refresh_start OR NOT refresh_start LESS close_start)
    message(FATAL_ERROR "GUI tray/refresh lifecycle function order is invalid")
endif()

math(EXPR update_length "${refresh_start} - ${update_start}")
math(EXPR refresh_length "${close_start} - ${refresh_start}")
string(SUBSTRING "${source}" ${update_start} ${update_length} update_body)
string(SUBSTRING "${source}" ${refresh_start} ${refresh_length} refresh_body)

foreach(required IN ITEMS
        "traySharing_->setText"
        "trayIcon_->setToolTip"
        "sharingToggleOn(snapshot)")
    string(FIND "${update_body}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "updateTray lost tray-only token: ${required}")
    endif()
endforeach()

foreach(forbidden IN ITEMS
        "const HostStatus snapshot = host_.status()"
        "const bool authoritativeOn = sharingToggleOn(snapshot)"
        "updateTray(snapshot, address)"
        "displayedAddress(snapshot)")
    string(FIND "${update_body}" "${forbidden}" position)
    if(NOT position EQUAL -1)
        message(FATAL_ERROR "updateTray swallowed refresh behavior: ${forbidden}")
    endif()
endforeach()

foreach(required IN ITEMS
        "const HostStatus snapshot = host_.status()"
        "const bool authoritativeOn = sharingToggleOn(snapshot)"
        "sharingToggle_->setChecked(authoritativeOn)"
        "const QString address = displayedAddress(snapshot)"
        "runtimeReadinessStatus_->setText"
        "updateTray(snapshot, address)"
        "quitRequested_ && !authoritativeOn")
    string(FIND "${refresh_body}" "${required}" position)
    if(position EQUAL -1)
        message(FATAL_ERROR "refresh lost lifecycle token: ${required}")
    endif()
endforeach()
