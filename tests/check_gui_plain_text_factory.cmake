# SPDX-License-Identifier: GPL-3.0-or-later
# R7 GUI labels must never parse R10-supplied text before choosing PlainText.
# An end-state Qt property assertion would miss the transient AutoText parse.
if(NOT DEFINED RDP_GUI_SOURCE OR NOT EXISTS "${RDP_GUI_SOURCE}")
    message(FATAL_ERROR "GUI source path unavailable")
endif()

file(READ "${RDP_GUI_SOURCE}" gui_source)
set(required_order
    "auto* result = new QLabel();\n    result->setTextFormat(Qt::PlainText);\n    result->setText(message);")
string(FIND "${gui_source}" "${required_order}" first_plain_text_assignment)
if(first_plain_text_assignment EQUAL -1)
    message(FATAL_ERROR
        "R7 status label must select PlainText before assigning runtime data")
endif()
