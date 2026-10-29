# Validation evidence

## R9 exact-SHA qualification ledger — 2026-10-29

Source SHA under review: `d9b255bef6ae54952b50ffbca24f4b17ce969d72`.
Primary workflow: `40761365568`.

| Gate | Exact-SHA result |
| --- | --- |
| Linux GUI ZIP | PASS |
| Linux protocol Debug/Release | PASS |
| macOS protocol Debug/Release | PASS |
| Windows MSVC protocol Debug/Release + Microsoft interop artifact | PASS |
| R9 protocol/security sanitizers | PASS |
| Linux/macOS GUI credential parity | PASS |
| Documentation / workflow structure | PASS |
| Windows CLANG64 Release full CTest | PASS, 849/849 |
| Windows native sanitizer selection | PASS, 60/60 |
| Windows firewall snapshot semantic CTest | PASS in Debug and Release |
| Extracted Windows GUI no-socket/native-state smoke | PASS |
| Windows CLANG64 Debug full CTest | FAIL: test #37 `security.windows-credssp-credential-semantic-differential` segfault |
| GUI Round 2 aggregate | FAIL CLOSED because Windows CLANG64 producer failed |
| Manual `r9_credssp_owner_candidate=true` | NOT RUN on ordinary push |

The failing Debug credential test completed the correct, wrong-password and
empty-password Type-3 rows, then terminated before the unavailable/no-SPNEGO
row emitted its first SSPI status. Immediate parent
`c542f861ff8bc35300445ae7c1d91325470708e7`, workflow
`40760910388`, Windows CLANG64 job `123072335370`, passed the same test in
Debug and Release. The reviewed `d9b255b` commit changes only the Windows
firewall smoke plus testing/roadmap documentation, so no authentication-wire
change is attributed to this regression.

Corrective qualification keeps production wire behavior unchanged. Credential
rows are process-isolated with crash-as-failure diagnostics; exact-SHA
interop output is explicitly PARTIAL until every required case completes; the
Windows CLANG64 producer ends with a fail-closed aggregate over required
Debug/Release/GUI/sanitizer steps; and the dispatch-only owner candidate
requires all exact-SHA producers before emitting its manifest.

Corrective descendant local build/full CTest: **NOT RUN** in the connector
environment. Hosted exact-SHA CI and explicit manual candidate dispatch:
**PENDING**.
