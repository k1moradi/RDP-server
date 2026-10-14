# SPDX-License-Identifier: GPL-3.0-or-later
# Structural checks only: correctness of policy requires human review.
if(NOT DEFINED RDP_SERVER_SOURCE_ROOT)
    message(FATAL_ERROR "RDP_SERVER_SOURCE_ROOT required")
endif()
set(documents
    AGENTS.md VISION.md README.md coding_standards.md testing_standards.md
    compile.md benchmark.md CODEX_VALIDATION.md CODEX.md agent.md CLAUDE.md
    docs/ROADMAP.md .github/copilot-instructions.md)
foreach(document IN LISTS documents)
    if(NOT EXISTS "${RDP_SERVER_SOURCE_ROOT}/${document}")
        message(FATAL_ERROR "Missing mandatory document: ${document}")
    endif()
endforeach()
foreach(document IN ITEMS CODEX.md agent.md CLAUDE.md .github/copilot-instructions.md)
    file(READ "${RDP_SERVER_SOURCE_ROOT}/${document}" content)
    string(FIND "${content}" "AGENTS.md" match_index)
    if(match_index EQUAL -1)
        message(FATAL_ERROR "${document} must refer to AGENTS.md")
    endif()
endforeach()
