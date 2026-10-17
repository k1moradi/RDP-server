## R7 current-display cursor publication authoring receipt (2026-10-16)

**Starting shared main:** `3069b2f1e07198d0e060c1619924f9654ffb8826`.  
**Publication parent after shared-main reconciliation:** `c800ef3cacc59d3cc4bc442f5d3a1c88c01ac555`.  
Exact publication-SHA hosted validation: **PENDING**.

The R7 cursor consumer now has an explicit current-geometry contract:
`MacCursorSnapshot::validFor` / `pixelsFor` synchronously revalidate the
stored geometry generation, topology revision, GUI-session revision and visible
display identity against the caller-owned `NativeDisplayGeometryRefresh`.
No geometry owner is retained and no native cursor sampler, TCC prompt,
capture/input path, R2/R3 authority or R4 pointer publication is exposed.

New production-backed CTests are
`macos.cursor-topology-publication-revocation` and
`macos.cursor-geometry-generation-publication-denials`; the existing
`macos.cursor-session-watch-revocation` remains intact and now traverses the
same checked consumer path. The road-local GCC ASan/UBSan job
registry-preflights and runs all three cursor cases. Synthetic BGRA/geometry
evidence is only a lifetime/freshness regression gate, not macOS 27 native
desktop or Microsoft-client acceptance.

