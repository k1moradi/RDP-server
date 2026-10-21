# SPDX-License-Identifier: GPL-3.0-or-later
# R7 GUI labels must never parse R10-supplied text before choosing PlainText.
# An end-state Qt property assertion would miss the transient AutoText parse.
if(NOT DEFINED RDP_GUI_SOURCE OR NOT EXISTS "${RDP_GUI_SOURCE}")
    message(FATAL_ERROR "GUI source path unavailable")
endif()

file(READ "${RDP_GUI_SOURCE}" gui_source)

# Inspect only the shared label() helper. It may parent the empty QLabel at
# construction time, but runtime text must not be passed to a QLabel
# constructor because that would invoke AutoText before PlainText is selected.
string(FIND "${gui_source}" "QLabel* label(" label_helper_start)
string(FIND "${gui_source}" "QLabel* heading(" heading_helper_start)
if(label_helper_start EQUAL -1 OR
   heading_helper_start EQUAL -1 OR
   NOT label_helper_start LESS heading_helper_start)
    message(FATAL_ERROR "R7 shared status-label helper was not found")
endif()

math(EXPR label_helper_length
    "${heading_helper_start} - ${label_helper_start}")
string(SUBSTRING "${gui_source}"
    ${label_helper_start} ${label_helper_length} label_helper)

string(REGEX MATCH
    "new[ \t\r\n]+QLabel[ \t\r\n]*\\([^;]*message"
    runtime_text_constructor
    "${label_helper}")
if(NOT runtime_text_constructor STREQUAL "")
    message(FATAL_ERROR
        "R7 status label must not pass runtime text to a QLabel constructor")
endif()

string(FIND "${label_helper}"
    "auto* result = new QLabel(parent);" empty_label_construction)
string(FIND "${label_helper}"
    "result->setTextFormat(Qt::PlainText);" plain_text_selection)
string(FIND "${label_helper}"
    "result->setText(message);" runtime_text_assignment)

if(empty_label_construction EQUAL -1 OR
   plain_text_selection EQUAL -1 OR
   runtime_text_assignment EQUAL -1 OR
   NOT empty_label_construction LESS plain_text_selection OR
   NOT plain_text_selection LESS runtime_text_assignment)
    message(FATAL_ERROR
        "R7 status label must construct empty, select PlainText, then assign runtime data")
endif()
