# RDP-server — living milestone / TODO (main, 2026-10-31)

The original canonical roadmap file at parent `1d95156ea4fd1d1c5a20f4e3754570b44d504299` was empty. The following is the currently evidenced R10 P0 scope, not an assertion that earlier project milestones are complete. Preserve prior plans if recovered from version history.

## R10 macOS protected first-MCS production integration — P0, qualification pending

- [x] **Authored:** one R3 owner per accepted R1 connection; R2-first teardown ordering; explicit CredentialsVerified, Prepared, TransportAdmitted, Admitted and Connect-Response-delivered transitions inside serialized HostControl
- [x] **Authored:** only the genuine macOS evidence-source path may construct the broker; after fresh original consent, proof, native, TLS certificate, listener and credential checks, R2 may complete exactly one R1 transport admission
- [x] **Authored:** only after R2 transport admission, R1 TLS reads one bounded 8192-byte maximum first-MCS TPKT with exact header/packet framing; R2 privately enters R3 and gates Connect-Response receipts
- [x] **Authored:** nonblocking, one R1 writer and protected accepted-byte accounting for Connect-Response; zero progress remains pending; partial accepted bytes continue at the exact R3-owned suffix
- [ ] **Qualification required:** macOS compile, focused/full CTest, R2 receipt fixtures and exact-publication-SHA hosted jobs; no connector-local build/test was run
- [ ] **Native gate:** a genuine macOS physical native-authority lease and real Microsoft client authentication/first MCS have **NOT** been observed or authorized for this task
- [ ] **Next protected increments:** Erect -> Attach/confirm -> ChannelJoin/confirm -> Client Info -> PersonalDesktop licensing -> Demand/Confirm Active -> Share/GraphicsReady; no desktop attach until real Share and native permission
- [ ] **Candidate coordination:** notify Agent 9 and separately qualify any new publication SHA before manual candidate nomination; no candidate is nominated by this increment

The offline R2 real-TLS completion/zero/partial/late-receipt test uses synthetic native proof and does not certify physical Admission. Preserve the macOS no-native-authority denial and first-MCS dormancy tests.
