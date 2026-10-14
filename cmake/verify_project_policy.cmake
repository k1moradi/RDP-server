# SPDX-License-Identifier: GPL-3.0-or-later
# Structural checks only: correctness of policy requires human review.
if(NOT DEFINED RDP_SERVER_SOURCE_ROOT)
    message(FATAL_ERROR "RDP_SERVER_SOURCE_ROOT required")
endif()
# Keep agent entrypoints discoverable while locating long-form docs in docs/.
set(documents
    AGENTS.md README.md CODEX.md agent.md CLAUDE.md
    docs/VISION.md docs/ROADMAP.md docs/ARCHITECTURE.md
    docs/coding_standards.md docs/testing_standards.md
    docs/compile.md docs/benchmark.md docs/CODEX_VALIDATION.md
    docs/THIRD_PARTY.md .github/copilot-instructions.md)
set(root_entrypoints AGENTS.md README.md CODEX.md agent.md CLAUDE.md)
file(GLOB root_markdown RELATIVE "${RDP_SERVER_SOURCE_ROOT}"
    "${RDP_SERVER_SOURCE_ROOT}/*.md")
# This runs via cmake -P, which does not inherit the top-level
# cmake_minimum_required() policy version; list(FIND) is policy-independent.
foreach(document IN LISTS root_markdown)
    list(FIND root_entrypoints "${document}" entrypoint_index)
    if(entrypoint_index EQUAL -1)
        message(FATAL_ERROR
            "Move non-entrypoint root documentation to docs/: ${document}")
    endif()
endforeach()
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
