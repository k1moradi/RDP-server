## R5 evidence validation and pre-auth isolation add no production dependency (2026-10-29)

The expanded macOS evidence collector/validator remains Python standard-library
only and reuses the existing `Python3::Interpreter` test dependency. Its
validation mode reads only an explicitly named private manifest and writes one
redacted JSON summary to stdout. No production target, socket, Keychain/trust
API, Windows App framework, package dependency, install/export surface or
second build root is added.

The Linux isolation increment changes only the existing
`test_linux_runtime_direct_ntlm_lifecycle` production-backed fixture and the
shared CTest registry. It adds no runtime source, compile definition, library or
native dependency. Canonical C++ build/full CTest is **NOT RUN** in this
connector environment; exact-publication CI is **PENDING**.

## Windows credential-oracle diagnostics must use stable target constants (2026-10-27)

When warning cleanup removes a test-only local alias/capture, update every
diagnostic call site in the same function as well. The Windows Microsoft
CredSSP oracle uses the immutable `TargetProfile::PortableServerName`; pass
that enum directly to both the provider call and `printFailure()` rather than
leaving a diagnostic reference to a deleted alias. MSVC and Clang 23 both
compile the entire test graph with errors fatal, so diagnostic-only dead names
block the exact-SHA producer set just like production compile errors.

This is compile hygiene only. It must not change credential-source construction,
Microsoft SSPI/CredSSP outcomes, production TLS/certificate/NTLM/NLA behavior,
or any downstream authority.

## Windows Clang warning-clean test lambdas (2026-10-27)

MSYS2 CLANG64 builds run with `-Werror`, including test-only Microsoft
CredSSP/SSPI fixtures. Do not capture local constants in a lambda when Clang can
use the constant without an odr-use; `-Wunused-lambda-capture` is a real build
failure under the project warning policy. Prefer an empty capture and pass the
stable enum/constant directly at the call site when no runtime capture is
needed. This is compile hygiene only and must not change the credential-source
or protocol behavior being tested.

## Agent 1 post-Type-2 wire observations add no build surface (2026-10-27)

This completion extends existing runtime/transport sources and the existing
`test_linux_runtime_direct_ntlm_lifecycle` target. It adds no library,
dependency, build option or alternate build root. Six behavior-named CTests are
registered in the shared registry. Canonical connector configure/build/CTest:
**NOT RUN**.

## R7 remote-client credential guidance adds no build surface (2026-10-27)

The Main-page credential guidance uses only the existing Qt Widgets `QLabel`
helper and the existing `test_desktop_gui_offline` executable. There is no new
Qt module, native library, runtime service, credential provider, build option or
build root. The dedicated
`gui.offscreen-rdp-client-credential-guidance` CTest uses
`QT_QPA_PLATFORM=offscreen` and the ordinary strict-warning GUI target.

The canonical owner configure/build/full-CTest command and the single
`~/rdp-server/build/` contract are unchanged.

## Agent 6 credential-source oracle adds no production build surface (2026-10-27)

The matrix reuses Windows-only `test_windows_sspi_credssp_interop`, existing
OpenSSL/`secur32` linkage, the existing behavior CTest and the one-`build/`
root. It adds no production source, compile definition, package, socket,
service, trust-store access or install/export surface.

Executed rows use fixed in-memory test material or explicit Schannel-only
no-SPNEGO configuration. The hosted default/process row is policy-only and
performs no credential acquisition. Non-Windows builds do not run the oracle.

## R8 long pre-Type-3 stall reuses the existing runtime test target (2026-10-27)

The long-stall clipboard-dormancy increment changes only the existing
`test_linux_runtime_direct_ntlm_lifecycle` source. It adds a bounded service
hold inside the already-registered
`runtime.linux-direct-ntlm-type2-peer-eof-pre-admission-diagnostics` mode.
No executable, library, dependency, compile definition, CTest registration,
label inventory, production target, install/export surface or build directory
is added. Configure, build and test commands continue to reuse the single
checkout-local `build/` root.

## Agent 4 measured pre-Type-3 graphics dormancy adds no build surface (2026-10-27)

This P2 increment changes only the existing CMake source-contract test and
canonical documentation. It adds no production source, executable, library,
dependency, compile definition, runtime switch, codec target, CTest
registration or build directory. The existing
`runtime.linux-auth-envelope-independent-native-owner` CTest continues to
read the production HostControl/connection sources as data, and the existing
production-backed Type-2/EOF lifecycle remains unchanged.

All configure/build/focused/full commands continue to reuse the one canonical
checkout-local `build/` root.

## Agent 1 explicit TLS-version matrix adds no production build surface (2026-10-27)

The TLS-version matrix reuses the existing Windows-only
`test_windows_sspi_credssp_interop` executable, Agent 6's legacy/modern
Schannel credential profiles, and its existing
`rdp-server-standalone-ntlmv2`, `rdp-server-runtime-tls` and `secur32`
linkage. The three behavior CTests select system/default, TLS-1.2-only and
TLS-1.3-only **test connection** profiles by command mode. No production
library, compile definition, runtime switch, package dependency, socket,
trust-store mutation or second build root is added.

CI reuses the already-registered
`runtime.generated-tls-context-negotiates-tls13` production-context test as
the independent server-side control and writes the three row receipts into the
existing Agent-9 Microsoft interop artifact. Configure/build/focused/full
commands continue to use the one checkout-local `build/` root.

## R10 post-Type-2 timeline diagnostics add no build surface (2026-10-27)

The timeline increment changes only the existing R1 native TCP/BIO owner,
Linux runtime connection/HostControl sources and shared read-only status
structure. R1 exposes one cumulative receive-byte scalar from its already-owned
native receive path; R10 snapshots/differences it without adding a socket,
reader, parser, thread or dependency. Existing C++23 `<chrono>` timing and the
existing CredSSP TSRequest reader provide the remaining observations.

The dedicated
`runtime.linux-direct-ntlm-post-type2-client-data-timeline-diagnostics`
CTest is another mode of the existing
`test_linux_runtime_direct_ntlm_lifecycle` executable. The earlier
`runtime.linux-direct-ntlm-type2-peer-eof-timing-diagnostics` remains
registered. Configure, build, focused tests and full CTest continue to use the
one canonical checkout-local `build/` root. No production target, install or
export surface, compile definition, package dependency, runtime switch or R9
focused-selector count is added.

## Windows NTLM OEM differential reuses the existing SSPI oracle target (2026-10-27)

The OEM-response experiment adds no library, dependency, service, socket,
production compile definition or install/export surface. It is another command
mode of the existing Windows-only `test_windows_sspi_ntlm_interop` executable,
still linked only to `rdp-server-standalone-ntlmv2` and `secur32`. The
central CTest registry adds one behavior-named case, so the primary Microsoft
Windows NTLM/CREDSSP focused matrix enumerates six tests instead of five.
All configuration/build/test work continues to use the single checkout-local
`build/` root.

## R7 Advanced Type-1 profile adds no build surface (2026-10-27)

The GUI consumes the existing R10 redacted Type-1 VERSION diagnostics through
the current desktop-ui/HostControl types. No executable, library, parser,
dependency, compile definition, install/export surface, runtime switch or build
directory is added. The behavior-named
`gui.offscreen-advanced-runtime-type1-structural-profile` case is another mode
of the existing `test_desktop_gui_offline` executable and remains in the
canonical single `build/` root. Concurrent Windows Schannel and macOS owner-
evidence test work remains unchanged and independent.

## Agent 6 modern Schannel CredSSP probe reuses the Windows oracle target (2026-10-27)

The Windows-only `test_windows_sspi_credssp_interop` remains the sole
full-CredSSP oracle executable and keeps its existing
`rdp-server-standalone-ntlmv2`, `rdp-server-runtime-tls` and `secur32`
linkage. Its source opts into the current SDK `SCH_CREDENTIALS` /
`TLS_PARAMETERS` declarations and includes the required Windows native
string declarations; no shipped dependency or production compile definition
is added. The new probe is another ordinary Windows CTest in the same
checkout-local `build/` root.

## macOS Windows App owner-evidence helper adds no production dependency (2026-10-27)

The Agent-5 physical-client evidence increment adds one Python-only read-only
helper, `scripts/macos_windows_app_owner_evidence.py`, and one synthetic
offline unittest registered as
`macos.windows-app-owner-evidence-readonly-manifest`. It reuses the existing
required Python3 interpreter already found by `tests/CMakeLists.txt`; no
production target, library, framework, entitlement, app permission, socket,
Keychain/trust dependency, install/export surface or second build root is
added.

The test constructs only a synthetic `.app/Contents/Info.plist` and temporary
log files. It never launches Windows App, changes trust, reads a private
application directory or performs network I/O. Normal configure/build/full
CTest remains in the canonical single `build/` root.

## Agent 9 owner-candidate qualification reuses existing one-root oracle targets (2026-10-27)

Agent 9 adds no executable, library or production compile definition. It reuses Agent 2's existing Windows NTLM SSPI target, Agent 6's existing Windows full-CREDSSP target, the native certificate-policy targets and the already-registered `runtime.generated-tls-context-negotiates-tls13` case. The normal `protocol` matrix continues to configure, compile and test from the single checkout-local `build/` root.

The exact-SHA workflow retains the modern Schannel probe output and adds only bounded non-secret classification lines to the existing Microsoft interop artifact. The TLS-1.2 physical A/B decision adds no production runtime selector, TLS maximum, packaging surface or permanent setting. Release packaging and the one-build-root policy are unchanged.

## R7 Advanced diagnostics add no build or dependency surface (2026-10-26)

The GUI projection reuses the existing desktop UI, Linux HostControl, Agent-1
established-TLS diagnostics and the current certificate test inventory. It adds
no executable, library, dependency, compile definition, install/export surface,
runtime switch or second build directory. The dedicated
`gui.offscreen-advanced-runtime-security-diagnostics` CTest is another mode
of the existing `test_desktop_gui_offline` executable; all configure/build/
focused/full commands continue to reuse the canonical single `build/` root.

## Agent 5/6 native certificate-policy test targets (2026-10-26)

`test_windows_certificate_policy` is Windows-only and links the existing
`rdp-server-runtime-tls`, `OpenSSL::Crypto` and SDK `crypt32`.
`test_macos_certificate_policy` is macOS-only and links the same runtime TLS
library and OpenSSL crypto plus the existing Security and CoreFoundation
framework handles. Both are test-only; neither is installed or linked into the
server.

The behavior-named CTests are
`security.windows-generated-tls-certificate-policy-profiles` and
`security.macos-generated-tls-certificate-policy-profiles`. Linux adds no
executable or duplicate CTest: Agent 5 consumes the existing
`runtime.linux-direct-ntlm-type2-peer-eof-pre-admission-diagnostics` runtime
gate and strengthens the existing
`runtime.linux-host-control-native-desktop-bounded-post-share` source
contract. The full-CREDSSP matrix keeps its existing executable and linkage;
only non-secret diagnostic output is extended.

All configuration/build/test commands continue to use the canonical single
`build/` root. CI runs the platform certificate-policy CTest verbosely after
the Debug build so trust/name/policy observations are visible for the exact
publication SHA.

## Agent 1 TLS/certificate differential build surface (2026-10-26)

The TLS diagnostic change adds no production target, library, dependency, install/export surface, runtime switch or second build root. Linux runtime security continues to consume OpenSSL through the existing `rdp-server-runtime-tls` owner; the host-control terminal record only projects the established connection's bounded public metadata.

The existing `test_runtime_tls_context` executable gains two behavior cases for test-only CN variants and TLS 1.3 production-context negotiation. The existing Linux runtime-security executable extends `linux-connection-tls-acceptance-diagnostics` for cipher/SNI/CN/SAN metadata. All configure/build/focused/full CTest commands continue to reuse the single checkout-local `build/` root.

## Type-1 structural observer adds no build dependency (2026-10-26)

The Type-1 profile observer extends the existing portable
`rdp-server-standalone-ntlmv2` parser metadata and existing Linux runtime /
Windows full-CREDSSP test targets only. It adds no library, compile definition,
service, socket, generated file or build directory. The new behavior-named
`security.ntlmssp-type1-structural-observation` case is another mode of the
existing `test_standalone_ntlmssp` executable and runs from the canonical
single `build/` root.

## R8 Type-2/EOF retry dormancy uses existing test targets (2026-10-26)

The R8 P2 strengthening adds no executable, library, dependency, compile
definition, CTest registration or build directory. It narrows the existing
`test_linux_runtime_direct_ntlm_lifecycle` Type-2/EOF case to the requested
pre-Type-3 retry boundary and extends the existing CMake-script gate behind
`runtime.linux-host-control-dormant-unicode-clipboard-composition`.
The canonical single `build/` root, clipboard test inventory and all platform
build commands remain unchanged.

## R4 pre-Type-3 graphics dormancy uses the existing source-contract CTest (2026-10-26)

The R4 P2 pre-Type-3 strengthening adds no executable, library, dependency,
compile definition, CTest registration or build directory. It extends the
existing CMake-script gate behind
`runtime.linux-auth-envelope-independent-native-owner`, which reads the
production HostControl/connection sources as data and remains part of ordinary
CTest. The canonical single `build/` root and all platform build commands are
unchanged.

## Windows full-CredSSP oracle uses SSPI stream context (2026-10-26)

The Windows-only `test_windows_sspi_credssp_interop` target keeps the same source, executable, linkage and one-`build/` root. Its Microsoft CREDSSP client now requests `ISC_REQ_STREAM` instead of `ISC_REQ_CONNECTION`; this adds no dependency, socket, service, permission, install/export surface or production compile definition.

The existing `security.windows-credssp-harness-multi-turn-round-progression` CTest pins the context-mode requirement before exercising the shared pump. The exact-SHA Windows protocol lane remains responsible for compiling the harness and then running harness integrity before the fixed-name control and target matrix.

## R9 Windows full-CredSSP harness qualification and result matrix (2026-10-26)

The existing Windows-only `test_windows_sspi_credssp_interop` target keeps its
current test-only linkage: `rdp-server-standalone-ntlmv2`,
`rdp-server-runtime-tls` and Windows `secur32`. The same executable adds two
offline harness-integrity modes for stream-buffer retention and shared-pump
multi-turn progression; add no HostControl, native-desktop, clipboard, socket,
service or shipped dependency.

Windows protocol CI runs those two harness regressions before the five
Microsoft target cases and writes the exact-SHA
`r9-microsoft-interop-results.txt` artifact with separate NTLM fixed-name,
NTLM IP, CREDSSP fixed-name control, CREDSSP IP-SPN and CREDSSP bare-IP rows.
Target-differential status remains `BLOCKED_CONTROL` until the fixed-name
CREDSSP control reaches Type 3. The manual R9 owner-candidate aggregate consumes
that exact-SHA artifact in addition to its existing job prerequisites.

All configuration and test commands continue to reuse the one persistent
`build/` root. Non-Windows builds do not compile the SSPI harness, and no new
install/export surface is introduced.

## R8 Windows full-CredSSP harness linkage isolation (2026-10-26)

The Windows-only `test_windows_sspi_credssp_interop` target remains a
test-only authentication oracle linked to
`rdp-server-standalone-ntlmv2`, `rdp-server-runtime-tls` and `secur32`.
It must not link HostControl, platform-native desktop aggregates or any R8
clipboard target, and its source must not include clipboard/X11/native-owner
interfaces or call native clipboard APIs.

The existing Linux source-contract CTest
`runtime.linux-gui-bootstrap-clipboard-dormancy` now enforces that composition
by reading the Windows harness target/source as data. No new CTest, production
library, shipped dependency, build root or platform permission is introduced;
the one persistent `build/` contract is unchanged.

## Windows Microsoft full-CredSSP target matrix (2026-10-25)

The existing Windows-only `test_windows_sspi_credssp_interop` remains linked
only to the production standalone CredSSP/NTLM component,
`rdp-server-runtime-tls`, OpenSSL already owned by that runtime target, and
the Windows SDK `secur32` import library. It opens no socket and uses the
production generated-IP certificate with memory BIOs.

The executable now has three ordinary CTest command modes: portable
`TERMSRV/RDP-SERVER`, owner-like `TERMSRV/192.168.1.5`, and bare
`192.168.1.5`. The existing native NTLM SSPI tests remain separate and
unchanged. Windows protocol CI enumerates all five NTLM/CredSSP target-oracle
CTest entries before execution and runs them verbosely so exact SSPI status
codes remain in hosted evidence.

No new production library, shipped dependency, build root, service permission,
network access, native desktop or OS-account credential is introduced.

## Windows native CredSSP target-differential oracle linkage (2026-10-25)

Windows protocol tests build `test_windows_sspi_credssp_interop`, linking the
platform `secur32` SSPI implementation with the existing noninstalled
`rdp-server-standalone-ntlmv2` production CredSSP owner and
`rdp-server-runtime-tls` production TLS identity. This is test-only linkage;
no runtime dependency is added and non-Windows builds do not compile the test.

The fixture uses Microsoft's `CREDSSP` package with fixed in-memory test
credentials and manual Schannel certificate validation so the self-signed,
memory-only production test identity requires no host trust-store mutation.
It opens no network socket, performs no domain login, writes no credentials,
and creates no native desktop. Ordinary Windows CTest runs both
`TERMSRV/RDP-SERVER` and `TERMSRV/192.168.1.5` target profiles.

## Windows SSPI Type-2 oracle linkage (2026-10-25)

The noninstalled Windows-only `test_windows_sspi_ntlm_interop` target links
the existing `rdp-server-standalone-ntlmv2` production security component
and the Windows SDK `secur32` import library. No SSPI header or Secur32
dependency enters the portable protocol/security library, Linux or macOS.
The test uses only local explicit test credentials and no network service.

Hosted Windows/MSVC and owner MSYS2 CLANG64/Clang 23 remain independent
compile/runtime evidence gates. Ordinary Windows full CTest includes the
oracle, while the primary Windows protocol job also runs it explicitly after
Debug compilation so Type-2 acceptance is visible before unrelated tests.

## Desktop Username account lookup linkage (2026-10-24)

The shared noninstalled Qt desktop UI resolves only a safe current interactive
account **name** for the Username convenience default. Linux uses the effective
UID through the existing libc `getpwuid_r` boundary. macOS uses
SystemConfiguration's current console-user query. Windows uses the current
process's interactive WTS session and `WTSQuerySessionInformationW`, linking
the system `wtsapi32` import library. Root/system/service identities fail to
an empty suggestion.

These paths read account/session metadata only. No password or credential-store
API is called, no PAM plaintext is recovered, and no login password is cached.
Session Password remains empty at startup, user-entered, and independent. The
helper is UI-only and does not enter the installed protocol SDK or grant native
admission.

## R6 owner-acceptance GUI build-intent parity (2026-10-24)

Linux and macOS owner-acceptance validation must use the same explicit build
intent: `CMAKE_BUILD_TYPE=Release`,
`RDP_SERVER_BUILD_DESKTOP_GUI=ON`, and
`RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=ON`. This exercises the explicit
prequalification mechanism instead of relying on Debug's `!NDEBUG` side of the
same source gate. Ordinary public Linux/macOS GUI packaging remains
`Release` with `RDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=OFF`; do not promote
the public standalone-password capability before its separate Microsoft-client
qualification.

Reuse the one canonical build root. For an owner-acceptance build, configure:
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
  -DRDP_SERVER_BUILD_DESKTOP_GUI=ON \
  -DRDP_SERVER_ENABLE_OWNER_ACCEPTANCE_UI=ON
cmake --build build --config Release --parallel 2
```
Platform-specific Qt/OpenSSL discovery arguments remain those already required
by this document. Reconfiguring the same build root back to a public package
must set the acceptance option explicitly `OFF`.

## OpenSSL 4 generated-subject portability (2026-10-23)

The R1 automatic TLS generator must compile with supported OpenSSL headers where
certificate-owned X509 name access is const. Generated certificate construction
therefore creates its own mutable `X509_NAME` and installs it with setter
APIs; it does not require a compatibility cast, deprecated mutating accessor,
new library, temporary file or platform conditional.

The existing `rdp-server-runtime-tls` linkage and one-build-root commands are
unchanged. Hosted Linux/Windows success cannot substitute for macOS compilation;
the exact-SHA macOS protocol lane must compile this target before R1 automatic
TLS receives cross-platform qualification.

## R1 in-memory automatic TLS identity build boundary (2026-10-23)

The existing noninstalled `rdp-server-runtime-tls` target now owns both
expert file-backed and automatic in-memory identity construction. It adds no
dependency beyond the already-required OpenSSL Crypto/SSL libraries and writes
no generated credential file. The Linux `rdp-server-linux-host-control`
links this target directly so the ordinary no-config GUI can prepare a
selection-bound R1 identity even before the broader R2/R3 production-security
configuration is available. This linkage alone never opens a listener.

The normal one-root build/test command is unchanged. Generated TLS CTests run
offline on every platform against OpenSSL; the Linux HostControl lifecycle case
is native-interface conditional and uses CTest skip status when no eligible
private-LAN interface exists. `--config` file-backed TLS remains an
expert/legacy build path, not a required consumer setup step.

## Production Windows/macOS R10 native-owner linkage (2026-10-22)

When configuring on Windows or macOS, the production `rdp-server` executable
now privately links `rdp-server-runtime-platform-native-desktop`. That target
in turn links the existing R6 Windows desktop aggregate or R5 macOS capture/input
aggregate. The runtime receives
`RDP_SERVER_HAVE_PLATFORM_NATIVE_DESKTOP=1` only on those platforms and owns
one inactive composition object for the process lifetime.

This is build/lifetime composition only: normal help/configuration/startup
refusal paths do not attach R2 authorization or activate native APIs. Linux
build/link behavior is unchanged.

## R5 macOS input readiness adds no new framework dependency (2026-10-21)

The combined Accessibility/Input Monitoring readiness check remains inside
`rdp-server-macos-capture`. It uses the already-linked ApplicationServices
and CoreGraphics frameworks; no new library, daemon, entitlement helper,
background service or SDK export is added. The Input Monitoring path is a
read-only CoreGraphics preflight and never invokes a request API during build
or ordinary CTest.

## R10 noninstalled Windows/macOS platform-native composition target (2026-10-21)

`rdp-server-runtime-platform-native-desktop` is built only on Windows or
macOS. It compiles one shared R10 composition source and privately links the
existing R2 native authorization target plus the matching R6 Windows desktop
or R5 macOS capture aggregate. It is not installed/exported, does not change
the portable protocol SDK, and adds no Linux dependency.

The header is excluded from SDK installation. Windows retains existing
User32/GDI/D3D11/DXGI/WTS dependencies through R6; macOS retains existing
framework dependencies through R5. No new service, daemon, Qt, listener or
background-thread dependency is introduced. Ordinary CTest remains offline
and uses the existing one build root.

## R5 macOS authorized aggregate build boundary (2026-10-21)

On Apple builds, `rdp-server-macos-capture` now also compiles
`mac_native_desktop_owner.cpp` and privately links the noninstalled
`rdp-server-native-desktop-authorization` core. The aggregate reuses the
existing CoreGraphics/AppKit/ApplicationServices/CoreMedia/CoreVideo and
ScreenCaptureKit framework linkage; it adds no transport, GUI or protocol
dependency.

The production ScreenCaptureKit backend and Quartz posting callback remain
Objective-C++ implementation details reachable only through private friend
methods of the aggregate. The public source-level owner still requires a live
R2 authorization object and exact generation; no SDK-installed UID/display/TCC
constructor is introduced. This build composition alone does not enable the
portable macOS test bundle, start a listener or claim native-host acceptance.

## R2 portable native-authorization core build boundary (2026-10-21)

`rdp-server-native-desktop-authorization` is a noninstalled C++23 static
target built on every platform so the common generation/owner-epoch rules can
receive ordinary synthetic CTest coverage. It links no WTS/LSA, Security,
CoreFoundation, TCC, capture or input API. The existing Windows and macOS
native-session evidence targets remain platform-only read-only adapters and are
not pulled into the installed protocol SDK.

The authorization header is excluded from SDK installation alongside
`current_owner_sharing_authority.h` and the platform evidence headers.
Building the core therefore exposes no public hosting API. Native runtime
composition must explicitly link the R2 core plus the matching platform reader
and authenticated-identity implementation; target availability alone is never
authorization.

## R8 dormant clipboard linkage for Linux HostControl (2026-10-20)

When Linux runtime security, the R5 X11 desktop, X11 clipboard adapter and R8/R3
bridge targets all exist, both `rdp-server` and
`rdp-server-linux-host-control` link the same noninstalled R8 clipboard
dependencies and receive `RDP_SERVER_HAVE_LINUX_X11_CLIPBOARD=1`. Missing
native XCB clipboard development files still omit this composition without
affecting the portable SDK.

This build definition only compiles the dormant route. It does not override
`kLinuxProductionClipboardActivationApproved = false`, open a listener, claim
CLIPBOARD or authorize a native session.

## R9 runtime-security sanitizer selector is 41 cases (2026-10-20)

The bounded Linux ASan/UBSan direct runtime-security inventory is **41** cases
after the standalone authentication-selector denial regression joined the
production connection aggregate. Keep the regex, explicit sentinel and
structure-validator count synchronized. If workflow authoring duplicates job
bodies, reconstruct from a known-valid parent rather than deleting arbitrary
fragments from malformed YAML.

## R9 Linux sanitizer clipboard inventory reconciliation (2026-10-29)

The Linux ASan/UBSan job now pins 100 `clipboard`-labelled tests. The R8 P1
interop round adds exactly three reviewed cases to the prior 97-case inventory:
`clipboard.ms-rdpeclip-wire-conformance`,
`clipboard.capability-format-request-interoperability-matrix`, and
`clipboard.x11-incr-error-property-cleanup`. Keep their explicit name checks
and the fixed count synchronized with reviewed behavior-test additions/removals.
Do not hide registry drift by dropping the count assertion or by deleting an
unrelated test.
## R9 Qt macro-safe transitive headers (2026-10-20)

A header reachable from a Qt translation unit must remain valid when Qt
keyword-like macros are active. Avoid identifier names such as bare `slots`
in shared security/runtime headers; use descriptive names such as
`attemptSlots`. Keep a non-Qt compile regression that defines the conflicting
macro while including the production header, so packaging does not become the
first place this class of error appears.

## R9 C++ portability fixes for hosted Clang/GCC (2026-10-20)

In C++ translation units, initialize `sd_bus_error` with C++ aggregate
zero-initialization (`sd_bus_error error{};`). Do not use
`SD_BUS_ERROR_NULL` there: current systemd headers expand it through a C99
compound literal that the bounded Clang sanitizer lane rejects under
`-Werror,-Wc99-extensions`.

Keep the standalone NTLMv2 MD4 owner warning-clean on GCC 13 without disabling
`-Warray-bounds`. Its staging copies remain explicitly bounded and use direct
indexed byte copies; warning suppression, optimization barriers, or a different
CI compiler are not acceptance.

## R10 Linux desktop shared configuration feed (2026-10-20)

When Linux production runtime security is built, the desktop may be launched
with an explicit administrator/owner-provisioned configuration file:

```bash
rdp-server-desktop --config /absolute/or/owner-selected/path/server.conf
```

The desktop reuses the exact secure runtime configuration reader used by the
CLI; it does not maintain a second parser, password file or GUI credential
store. The configuration must satisfy the production Linux security/TLS and R3
licensing provisioning required by the existing runtime owners. Supplying the
file only provisions those service-lifetime owners. The GUI must still receive
explicit existing-OS-account setup and genuine local-owner consent before R10
may publish a LAN listener, and no client/native desktop is accepted merely by
launching with `--config`.

Ordinary GUI-only builds remain valid without GSS/PAM runtime security. On such
builds `--config` is rejected rather than pretending the host is provisioned.

## R10 desktop GUI default and deliberate headless configuration (2026-10-19)

`RDP_SERVER_BUILD_DESKTOP_GUI` defaults ON for ordinary application builds, so Qt 6.4+ Widgets is required and missing Qt must fail visibly. Deliberate protocol-only, production-security and sanitizer builds opt out explicitly in the same canonical build root:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
  -DRDP_SERVER_BUILD_DESKTOP_GUI=OFF
```

The option changes build selection only; ON grants no listener/R2 authority and OFF is not an automatic fallback.

## Qt TLS fingerprint fixed-extent portability (2026-10-19)

For R7 presentation of R1's SHA-256 certificate observation, do not form a
`std::array` non-type template argument through a runtime status object such
as `identity.certificateSha256.size()`. GCC may reject that object-qualified
expression even though the member's type has fixed extent. Derive the extent
from the fixed R1 type (`RuntimeTlsCertificateFingerprint`) with a compile-
time type trait, assert the SHA-256 32-byte contract, and keep the rendered
uppercase colon-separated buffer fixed at 95 characters. The GUI formats the
already-supplied R1 bytes only; it must not hash certificates itself.

## Windows hidden GUI smoke follows the shared R7 credential surface (2026-10-19)

The R6 Windows launcher reuses R7 `DesktopWindow`; its hidden qwindows-backed
offline modes therefore validate the current shared UI, not a retired password
widget. The verifier requires the unsupported application-password action to
exist disabled and both old password-entry QObject names to be absent. A
dedicated `--offline-unsupported-password-test` command is ordinary CTest.
These modes return before the event loop and do not display a window, open a
listener, prompt for credentials or confer R2/R10 authorization. Extracted
portable smoke continues to exercise the same packaged qwindows closure.

## R7 extracted macOS framework identity and signing gate (2026-10-18)

The macOS arm64 PORTABLE-GUI packager runs `macdeployqt` with Cocoa
plugin closure, normalizes staged Mach-O install IDs to `@rpath`,
preserves verified relative symlinks in `Contents/Frameworks`, and
ad-hoc signs the finished .app **before** ZIP creation. The archive
manifest and hashes bind every symlink's target bytes, and the common
verifier accepts only bounded internal framework aliases on macOS.
The native CI extracts with `ditto -x -k`, rejects build-host absolute
Mach-O dependencies using `otool -L`, and requires
`codesign --verify --deep --strict` of the extracted application.
Never fix a failed extracted signature by skipping verification or
re-signing the extracted app. Developer ID signing/notarization and
user-controlled Aqua/normal Finder launch remain distinct owner gates.

## R6 packaged Windows GUI QPA boundary (2026-10-18)

The Windows GUI package requires the native `qwindows.dll` Qt platform
plugin; it does not package `qoffscreen.dll`. The two hidden offline command
modes explicitly select `QT_QPA_PLATFORM=windows`, construct the production
shared window without showing it, and return before entering Qt's event loop.
This keeps native package smoke aligned with the actual double-click runtime
closure and adds no Qt module or deployment dependency.

## R6 Windows PORTABLE-GUI recursive runtime closure (2026-10-18)

The native R9 Windows run exposed that MSYS2/CLANG64 `windeployqt` deploys
Qt modules/plugins but not every non-Qt DLL imported by that Qt build. The R6
builder therefore follows `windeployqt` with CMake
`file(GET_RUNTIME_DEPENDENCIES)`, using the staged GUI plus all staged DLLs
as roots. Search order begins with the staged directory and the selected
`windeployqt` directory, then the configured OpenSSL bin directory when
present and existing PATH entries. API-set forwarders are pre-excluded and
resolved Windows system paths are post-excluded exactly as in the proven
SERVER-TEST dependency resolver. Any unresolved non-system dependency fails
packaging; resolved missing regular PE DLLs are copied app-local before the
manifest is generated. This adds no download, package install, second build
root, network access or runtime activation.

## R6 Windows PORTABLE-GUI builder boundary (2026-10-18)

packaging/windows/gui_bundle.py packages only the already-built RDP-server-GUI.exe plus files staged by a local windeployqt. It does not download dependencies, invoke an installer, mutate PATH, create a service, touch the firewall or start the GUI. It rejects additional EXE/BAT/CMD/PowerShell/MSI helpers, reparse/symlink content, unsafe or case-colliding names, and missing Qt Core/Gui/Widgets or plugins/platforms/qwindows.dll.

The emitted archive follows R9's PORTABLE-GUI manifest/checksum format and writes an adjacent outer SHA-256 receipt. Synthetic cross-host tests do not prove recursive PE imports; R9's native Windows job must run the builder, scan non-system PE/DLL closure and launch the extracted GUI with only archive and OS system paths available.
## R8 post-Share CLIPRDR bridge build boundary (2026-10-18)

`rdp-server-r8-r3-clipboard` is a noninstalled C++23 static target containing
only the R8 application-state bridge. It links the existing portable protocol
target and therefore reuses R3's sole static-VC/MCS framing owner; it adds no
native clipboard, GSS/PAM, socket or OS dependency. The bridge header is
excluded from the installed SDK. `test_r8_r3_clipboard_bridge` is built by
the existing sanitizer job and its five behavior CTests run under the ordinary
clipboard label. No live desktop, clipboard, credentials or service activation
is required.

## CLANG64 WinGDI Rectangle collision and R6 package self-scan (2026-10-17)

MSYS2 CLANG64 parses `wingdi.h` before shared graphics through the Windows
transport/runtime include graph. Because WinGDI exports a global
`Rectangle(HDC,...)` function, bare `Rectangle` in
`gfx_avc420_picture.h` is hidden as a type. The shared field now uses the
elaborated `struct Rectangle` spelling, and the existing WinGDI probe includes
that header after `<windows.h>`.

The Windows lifecycle PowerShell verifier uses no new dependency. Its private-key
and GitHub-token sentinels are concatenated at runtime so the generic SERVER-TEST
payload secret scanner can package the verifier without weakening the scanner.
The resulting contract remains Python/PowerShell standard-library-only.

## R6 Windows SERVER-TEST per-user bundle build boundary (2026-10-17)

R9's packaging prerequisite is resolved at exact SHA
`9a2d09968e741d13bc1c5e76753ecaf1be7557ef`: structure run
`39066363884` and primary run `39066363832` passed, including the aggregate
three-platform SERVER-TEST status. The hosted Windows preview recorded Release
MSVC **19.51.36260.0**, **x86_64**, **PE32+ Windows ABI** and exactly one
non-system runtime dependency, `libcrypto-3-x64.dll`. Windows/System32 and
API-set DLLs remain OS-supplied and are not copied as redistributables.

R6 now treats CMake's resolved non-system dependency list as the package
closure: every listed DLL must be a regular non-symlink `*.dll` with a unique
case-insensitive basename and is copied beside `rdp-server.exe`. Validation
fails if a listed DLL is absent from the archive. The Windows smoke launches
only with the bundle `bin` directory plus `SystemRoot`/System32 on PATH, so
an undeclared hosted-tool DLL cannot accidentally satisfy the test. Future
compiler/runtime changes are therefore manifest-driven rather than hard-coded
to the current OpenSSL name.

The source lifecycle is `packaging/windows/rdp-server-test.ps1`. Packaging
copies it into `platform/windows/` and emits an adjacent lifecycle script plus
SHA-256 for tester convenience. It installs only below
`%LOCALAPPDATA%\RDP-server\server-test`, requires no elevation, creates no
Windows service, firewall rule, scheduled task or autostart entry, and its
Start action never invokes the executable while R2/R10 Windows authority is
unavailable. The canonical local build-root command is unchanged; connector
authoring does not create another project build root.

## R2 production Linux runtime-security build (2026-10-17)

For an explicitly production-capable Linux runtime build, configure with
`-DRDP_SERVER_ENABLE_LINUX_RUNTIME_SECURITY=ON`. This option is independent of
`BUILD_TESTING` and the developer-only `RDP_SERVER_TEST_LINUX_GSSAPI` /
`RDP_SERVER_TEST_LINUX_PAM` selectors. It requires GSSAPI/Kerberos, PAM and
libsystemd; configuration fails instead of silently compiling a non-authorizing
provider when any required dependency is absent. Credentials are not CMake
inputs and must be provisioned separately as restricted runtime files.

The ordinary owner validation command remains unchanged. Live host admission is
a separate explicitly authorized test and is never implied by successful build
or preflight.

## R7 macOS optional LaunchAgent packaging boundary (2026-10-17)

The macOS SERVER-TEST artifact now carries
`tools/macos_test_launch_agent.py`, copied from first-party source after the
ordinary Release CTest. It uses only Python standard-library `plistlib` and
path handling; no new compiler, framework, package, entitlement, signing
identity or service-manager dependency is added. The dedicated offline CTest is
`packaging.macos-user-launch-agent-offline-contract`.

The helper renders only to an explicit review path and refuses direct output to
the user's `~/Library/LaunchAgents/org.rdpserver.server-test.plist`. CI never
calls `launchctl`, TCC, ScreenCaptureKit or Quartz input. Packaging remains
single-architecture according to the actually built Mach-O; no universal
binary is inferred or synthesized.

## R9 Windows SERVER-TEST dependency-resolution boundary (2026-10-17)

Exact-head run `39065727144` at `ef0feac1` passed Linux/macOS SERVER-TEST
smoke but Windows failed before archive creation because recursive CMake runtime
resolution descended into already-resolved `Windows/System32` DLLs and then
encountered optional/protected OS components that are not application
redistributables. The correction sets CMP0207 NEW when available, pre-excludes
Windows API-set forwarders and post-excludes resolved `Windows/` paths; per
CMake's dependency-filter semantics, a post-excluded system DLL is not added and
its dependencies are not recursively resolved. Non-system unresolved DLLs still
fail packaging. `OPENSSL_ROOT_DIR/bin` is searched before generic PATH entries
so the report binds to the OpenSSL installation used by the build rather than an
unrelated hosted-tool DLL with the same name.

The Windows dependency report explicitly states that Windows/System32 and API
set DLLs are OS-supplied and outside the redistributable closure. The bundle
still records every resolved non-system runtime dependency and does not claim
those files are embedded. This changes assurance only; it does not enable
server startup, service installation or deployment.

## R9 SERVER-TEST preview build contract (2026-10-17)

SERVER-TEST packaging reuses the ordinary checkout-local `build/` after the
Release full CTest; it creates only `build/server-test/` and no second CMake
build tree. `scripts/server_test_bundle.py` locates the actual `rdp-server`
target, reads CMake's compiler identity, validates ELF64/PE32+/Mach-O ABI, and
uses CMake `file(GET_RUNTIME_DEPENDENCIES)` in script mode to fail on an
unresolved runtime dependency. The existing protocol CPack/SDK install route is
unchanged.

The cross-platform artifact name is
`rdp-server-test-<version>-<platform>-<architecture>-<short-sha>`.
Linux includes R5's disabled service template; R6 Windows and R7 macOS remain
extraction-only until native serving/install contracts are authorized. No
credential, keytab, certificate private key, desktop content or CI secret is a
build input. Packaging does not start `rdp-server`; the later smoke executes
only offline CLI commands plus the expected failing unconfigured `serve`.

## R6 authority-loss input retirement build note (2026-10-17)

The dedicated Windows input authority-loss CTest reuses the existing
`test_windows_desktop_geometry` executable and injected input callback seam.
It adds no native API, package, build option or build root. The current
`^windows\.(geometry|capture|cursor|input)-` CLANG64 Debug, Release and
ASan/UBSan selector therefore advances from **58** to **59** cases; all three
preflights use the same exact cardinality and sentinel.

## R6 DXGI-to-R4 compatibility build note (2026-10-17)

The production `rdp-server-windows-desktop` target remains independent of
R4/x264: the new generation-carrying callback uses only existing portable
`FramebufferView` and Windows capture-generation types. The existing
`test_windows_desktop_geometry` executable additionally links the noninstalled
`rdp-server-graphics` target so its dedicated compatibility case can execute
the real R4 BGRA-to-NV12 ingestion primitive against a synthetic native mapping.

No new package, Windows SDK/import library, build option or build root is
introduced. Hosted Windows/MSVC and MSYS2 CLANG64/Clang 23 must compile the
expanded fixture. The R6 CLANG64 ASan/UBSan selector expands from 55 to
**58** cases.

## R6 hosted Windows sanitizer build contract (2026-10-17)

After the ordinary hosted MSYS2 CLANG64 Debug and Release gates, CI may
reconfigure the **same** `build/` root back to Debug with Clang 23
`-fsanitize=address,undefined`, `-fno-omit-frame-pointer` and
`-fno-sanitize-recover=all`, plus the matching executable linker sanitizer
flags. It then builds only the existing production-linked
`test_windows_desktop_geometry` target and executes the R6 native selector.

The sanitizer pass adds no owner-local build root and is not part of the
owner's mandatory M1 command. Hosted CI must give sanitizer configure/build/run
their own dependency fence so an unrelated failed full CTest does not skip the
instrumented R6 target. It relies on the CLANG64 compiler-rt shipped with the
verified Clang package; a missing/incompatible runtime must fail visibly
instead of silently dropping instrumentation. No live Windows desktop or input
permission is required.

## R8 native directory-capability build boundary (2026-10-17)

The noninstalled `rdp-server-clipboard-directory-capability` target remains
outside the protocol SDK/package. It compiles the portable binding everywhere
and conditionally compiles only native duplicate/close callbacks: POSIX
`fstat/fcntl/close` on Linux/macOS or Win32 handle metadata,
`DuplicateHandle` and `CloseHandle` on Windows. It adds no filesystem-path,
portal, shell or file-manager dependency.

Ordinary platform CTest registers one native object test for the current OS.
The tests use the existing checkout-local build working directory and anonymous
pipe handles/descriptors only; they do not access a user's clipboard or chosen
filesystem destination. The canonical owner configure/build/CTest command is
unchanged.

## CI workflow policy-test dependency

Ordinary `BUILD_TESTING=ON` configuration requires a Python 3 interpreter for
the repository-local CI workflow structural CTest. No third-party Python package
is required: the validator has deterministic built-in structural checks and
uses PyYAML additionally when it is already installed. Bash, when available, is
used only for `bash -n` syntax validation of workflow block scalars. This adds
no production, SDK or packaged runtime dependency and creates no additional
build root.

## R6/R10 Windows CLANG64 owner-evidence contract (2026-10-17)

R6 and R10 use the same M1 owner-machine contract for Windows compiler
evidence. The owner's required shell is **MSYS2 CLANG64**, not MINGW64,
UCRT64, PowerShell/MSVC or a Linux cross compiler. Before counting a result,
record the exact `git rev-parse HEAD`, `clang++ --version`, `cmake --version`
and these installed packages:

```sh
pacman -Q \
  mingw-w64-clang-x86_64-clang \
  mingw-w64-clang-x86_64-headers \
  mingw-w64-clang-x86_64-crt \
  mingw-w64-clang-x86_64-libc++ \
  mingw-w64-clang-x86_64-cmake \
  mingw-w64-clang-x86_64-openssl
```

The compiler must be Clang 23.x. For the October 2026 evidence window the
CLANG64 repository publishes Clang 23.1.3 with MinGW-w64 Windows headers/CRT
14.0.0.r426.g4564ee4b5 and OpenSSL 3.6.5. These MinGW-w64 headers/import
libraries are the Windows API SDK for this toolchain; do not report a
Microsoft Windows SDK version for a CLANG64 build that does not use it.

The owner's ordinary command remains unchanged and must reuse only
`~/rdp-server/build/`:

```sh
cd ~/rdp-server && git switch main && git pull --ff-only origin main && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON && cmake --build build --config Debug --parallel 2 && ctest --test-dir build -C Debug --output-on-failure
```

For R6 P1, additionally reconfigure that **same** root to Release and rerun the
focused Windows-native selector plus full CTest. A reused cache is acceptable
only when `CMAKE_CXX_COMPILER` still resolves to the CLANG64 `clang++.exe`;
otherwise the result is not Clang 23 evidence. No second build root is allowed.

Hosted CI contains a CLANG64 parity job using the same source graph, single
`build/` root, warnings, R6 selector and Debug/Release configurations. It
pins Ninja only to make the ephemeral generator deterministic and verifies the
actual compiler/package versions before configuration. Hosted parity separates
Clang/MinGW SDK source defects from owner-host configuration defects, but it
does **not** replace the owner's persistent-checkout M1 receipt.

## R2 Linux PAM verifier build boundary (2026-10-16)

The new verifier remains outside the portable SDK and default build graph.
Enable it only together with the existing Linux GSSAPI developer gate:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
  -DRDP_SERVER_TEST_LINUX_GSSAPI=ON \
  -DRDP_SERVER_TEST_LINUX_PAM=ON
```

On Debian/Ubuntu the additional development package is `libpam0g-dev`.
CMake requires both `security/pam_appl.h` and `libpam` when the PAM gate is
enabled. macOS, Windows, the installed protocol SDK and ordinary builds with the
gate off gain no PAM dependency. The verifier target is noninstalled and its
header is explicitly excluded from SDK installation.

The ordinary hosted Linux Debug job and R9 sanitizer job enable the PAM gate.
Release packaging continues through the existing portable configuration and
does not export or package this native verifier. No PAM service file, account
or credential is installed or synthesized by the build.

## R10 offline licensing credential preflight (2026-10-16)

The noninstalled runtime executable accepts one additional offline command:

```bash
rdp-server --check-licensing-credentials /absolute/path/rdp-server.conf
```

The existing 4096-byte whole-file bound remains. The six licensing fields are
optional as a group for legacy checks, but all six are mandatory here:

```text
listen_address=127.0.0.1
listen_port=3389
tls_certificate=/etc/rdp-server/tls.crt
tls_private_key=/etc/rdp-server/tls.key
authentication=required
os_authorization=required
max_connections=4
licensing_certificate=/etc/rdp-server/licensing-certificate.bin
licensing_private_key=/etc/rdp-server/licensing-private-key.pem
licensing_product_version=393217
licensing_company_name=RDP
licensing_product_id=A02
licensing_scope=scope
```

`licensing_product_version` is nonzero decimal `uint32_t`.
`licensing_company_name` and `licensing_product_id` are canonical UTF-8
converted to R3's null-terminated UTF-16LE with a 512-byte encoded bound.
Control characters, malformed/overlong UTF-8 and invalid surrogate encodings
are rejected. `licensing_scope` is printable ASCII and becomes R3's
null-terminated ANSI scope, also within 512 bytes.

The certificate path names a binary RDP `SERVER_CERTIFICATE` version-2
X.509-chain object, not a standalone DER certificate or ordinary TLS PEM file.
R3 requires a coherent root-first chain and an unencrypted PEM RSA private key
matching its terminal leaf. The shared secure snapshot loader enforces the
existing absolute-path, no-symlink/reparse, regular-file,
key-permission/DACL and native-object alias rules. No environment or home
expansion occurs.

Exit 0 means only that configuration, secure file metadata, RDP certificate
encoding and the matching RSA key were accepted by production R10/R3 owners.
Invalid or incomplete provisioning exits 3 with the generic configuration
failure. It does not establish Microsoft licensing trust, issue a license,
authenticate a user, authorize a desktop session or make the service ready to
listen. Ordinary startup still exits 2 with the established refusal.

`--check-config`, `--check-tls-files`, `--check-tls-credentials` and the
supported `--check-linux-security` keep their prior semantics when the
licensing group is absent and do not open licensing credential files.

## R8 Windows completed-file CF_HDROP build boundary (2026-10-16)

No new library or package is added. The existing cross-platform `rdp-server-windows-clipboard` target compiles the completed-file state and bounded DROPFILES serializer everywhere; `_WIN32` continues to compile the real `GlobalAlloc(GMEM_MOVEABLE)`/`SetClipboardData` bridge and link the existing `user32` dependency.

The existing `test_windows_clipboard_file_destination` executable gains `clipboard.windows-completed-file-hdrop-handoff`, so Linux/macOS exercise the portable ownership/serialization state with injected callbacks and Windows also compiles the native branch. R9 already builds this executable before `ctest -L clipboard`; its fail-closed registry preflight now requires the new handoff case. The installed portable SDK remains unchanged.

## R8 macOS file-descriptor destination build boundary (2026-10-16)

The existing noninstalled `rdp-server-macos-clipboard` target now also
compiles `src/platform/macos/mac_clipboard_file_destination.cpp` on every CI
OS. Portable state uses an injected native operation seam; Apple alone compiles
the guarded POSIX descriptor callbacks. No new framework or external package is
required and the installed portable protocol SDK remains unchanged.

`test_macos_clipboard_file_destination` likewise builds on every hosted OS.
Three injected behaviors run everywhere; Apple additionally registers the real
native descriptor case. The R9 Linux/Clang sanitizer job explicitly builds this
target before the shared `ctest -L clipboard` selection, so the portable
state remains sanitizer-covered even though real POSIX callbacks are exercised
only on Apple.

## R8 Windows file destination build boundary (2026-10-16)

`src/windows/windows_clipboard_file_destination.cpp` is part of the existing
noninstalled `rdp-server-windows-clipboard` target. Its receipt/progress state
and injected operation seam compile on every hosted CI OS; the real HANDLE
callbacks compile only under `_WIN32` and add no new external dependency.

`test_windows_clipboard_file_destination` likewise builds on every hosted OS
for deterministic state-machine coverage. Windows registers one additional
real-HANDLE build-root file case. The R9 Linux sanitizer compile list names the
target explicitly before `ctest -L clipboard`. The portable installed SDK
does not export the Windows native header.

## R8 completed-file X11 handoff build boundary (2026-10-16)

The existing Linux-only `rdp-server-linux-x11-clipboard` target now links the
existing noninstalled `rdp-server-linux-clipboard-file-destination` target so
its production XCB owner can consume completed descriptor materializations.
No new package is required beyond the XCB dependency already needed by that
adapter; no D-Bus, GLib/GIO, FUSE or xdg-desktop-portal development dependency
is introduced.

The existing `test_x11_clipboard_adapter` executable gains the dedicated
`clipboard.x11-completed-file-uri-handoff` case and continues to run through
the central clipboard label. R9 already builds both the X11 clipboard and
Linux file-destination test targets before `ctest -L clipboard`, so no
second sanitizer workflow or build root is added. The portable installed SDK,
macOS and Windows target graphs remain unchanged.

## R8 Linux file-descriptor destination build boundary (2026-10-16)

Linux builds the noninstalled
`rdp-server-linux-clipboard-file-destination` target from
`src/platform/linux/linux_clipboard_file_destination.cpp`. It links only the
existing portable protocol target and libc/POSIX syscalls already provided by
the platform; no XCB, FUSE, desktop-portal, D-Bus or file-manager development
package is required.

The corresponding `test_linux_clipboard_file_destination` target is
Linux-only and uses ordinary files under the existing CTest build-root working
directory. The R9 Linux/Clang sanitizer job explicitly builds it before the
shared `ctest -L clipboard` selection. The new platform header remains
noninstalled; the portable SDK and macOS/Windows builds do not gain a Linux
native file-destination API.

## R8 macOS clipboard adapter build boundary (2026-10-16)

The noninstalled `rdp-server-macos-clipboard` target compiles its portable
C++ ownership state on every CI OS, linking only the existing protocol target.
On Apple, the existing Objective-C++ language enablement additionally compiles
`mac_clipboard_adapter.mm` with ARC and links AppKit/Foundation. This target
is deliberately separate from `rdp-server-macos-capture`; Linux/Windows and
the installed protocol SDK gain no AppKit or ScreenCaptureKit dependency.

`test_macos_clipboard_adapter` is likewise compiled on every hosted OS with
synthetic native callbacks. The R9 Linux sanitizer build names that target
explicitly before selecting all clipboard-labelled CTests. The owner's normal
single `~/rdp-server/build` command is unchanged. Hosted Apple compilation
proves the dormant AppKit bridge builds, not that a live pasteboard was read or
written.

## R8 Windows clipboard adapter build boundary (2026-10-16)

The noninstalled `rdp-server-windows-clipboard` target compiles the
production clipboard state machine on every CI OS so its injected lifetime
logic receives broad warning/test coverage. Only `_WIN32` compiles the
dormant User32/GlobalAlloc callback bridge, linking `user32`; Linux/macOS
gain no Windows headers or native runtime dependency. The target links the
existing portable protocol library for `RemoteTransfer` and is not exported
or packaged in the SDK.

`test_windows_clipboard_adapter` uses synthetic native callbacks and never
opens the host clipboard. The owner's normal single `~/rdp-server/build`
command is unchanged; Windows/MSVC and owner MSYS2 CLANG64/Clang23 remain
separate compiler evidence for the native branch.

## R10 Linux explicit service-keytab provisioning (2026-10-16)

The pre-listener Linux runtime security component is currently built only when
the existing `RDP_SERVER_TEST_LINUX_GSSAPI=ON` gate is enabled. This keeps
MIT GSS/Kerberos out of the portable SDK and non-Linux builds while R10
validates the runtime composition. Linux CI already enables that gate for
Debug.

A configured keytab URI must be `FILE:/absolute/path`. R10 opens the path
component-by-component without following symlinks and requires a nonempty
regular file owned by the effective uid with no group/other permissions.
After opening, the runtime retains the descriptor and configures MIT GSS via
`FILE:/proc/self/fd/<n>`; the original pathname is not trusted again for
connection acceptors.

When built with the Linux GSS gate, `rdp-server --check-linux-security FILE`
accepts the original seven runtime fields plus these eight all-or-none fields:

```text
gss_service_principal=TERMSRV/rdp.example.test@EXAMPLE.TEST
gss_keytab=FILE:/absolute/private/service.keytab
authorized_kerberos_principal=alice@EXAMPLE.TEST
authorized_unix_account=alice
authorized_seat=seat0
authorized_display=:0
authorized_uid=1001
authorized_permissions=7
```

When the Linux PAM gate is also enabled, the group has one additional required
administrator-owned field:

```text
pam_service=rdp-server
```

The PAM service name is configuration only: 1..64 ASCII characters, beginning
with an alphanumeric character and containing only alphanumerics, underscore,
hyphen or dot. No password, authentication result or authorization Boolean is
accepted from the configuration file. Without the PAM build gate,
`pam_service` is not part of the supported grammar.

The command also validates the configured TLS server context and confirms that
the explicit GSS acceptor credential can be acquired. It does not need a
client ticket or KDC for that acquisition and it does not start a listener,
authenticate a client or grant OS/session access. Ordinary non-GSS builds keep
the prior CLI surface unchanged.

Default Linux CTests create only synthetic keytab material under
`build/runtime-linux-security-fixtures/`; no host keytab or ticket cache is
read. Production service/keytab installation permissions and lifecycle remain
a later R10 release/service gate.

# Compile standards — one persistent and reusable build directory

## R6 native Windows SendInput build note (2026-10-16)

The existing Windows-only `rdp-server-windows-desktop` target now also
compiles `windows_input_controller.cpp`. The Win32 translation compiles
against `user32!SendInput`, so no new library or package is required beyond
the target's existing `user32` linkage. Its callback factory remains
unexported until genuine R2/R3 Windows admission is available. Ordinary CTests
use the injected
callback seam and never call `SendInput`; no service permission, interactive
desktop, credentials or additional build option is required. Windows/MSVC and
owner MSYS2 CLANG64/Clang23 remain required compiler evidence.


## R6 DXGI pointer-shape build note (2026-10-16)

The noninstalled Windows-only `rdp-server-windows-desktop` target now also
compiles `windows_dxgi_pointer_shape.cpp`. It uses
`IDXGIOutputDuplication::GetFramePointerShape` through the SDK `dxgi`
library already linked for Desktop Duplication; there is no new package,
import library, CMake option or build root. Ordinary CTests use injected
callbacks and do not require a logged-in desktop. Hosted Windows/MSVC and
the owner's MSYS2 CLANG64/Clang23 remain separate compiler gates.





## R6 native Desktop Duplication build note (2026-10-16)

The existing Windows-only `rdp-server-windows-desktop` target now also
compiles `windows_dxgi_duplication_owner.cpp` under the ordinary
project command. It reuses SDK `d3d11` and `dxgi` libraries already
linked by that target; no new package, build directory, test option or
service permission is required. Native resource creation is never run
by default CTests; Windows/MSVC and owner MSYS2 CLANG64/Clang23 both
remain required independent compiler evidence.


**Mandatory:** Follow [AGENTS.md](../AGENTS.md), [VISION.md](VISION.md),
[testing_standards.md](testing_standards.md) and the living
[roadmap/TODO](ROADMAP.md). New verified compilation lessons
belong here rather than in additional build guides.

## Strict local directory contract

The only developer-machine checkout is **`~/rdp-server/`**.
The **single persistent build directory** is
**`~/rdp-server/build/`**, reused by every agent and every task.
Keep all objects, binaries, generated tests, sanitizer outputs, profiles
and logs within it. Nested output directories are allowed *inside*
that root, but never `build-debug`, `build-release`,
`cmake-build-*`, `tests/build`, or /tmp compilation roots.
Never routinely destroy the build cache or another agent's work.
CMake enforces `CMAKE_BINARY_DIR == <checkout>/build` and, outside
GitHub-hosted CI, requires the checkout itself at `~/rdp-server`.
The `GITHUB_ACTIONS=true` CI environment allows a hosted ephemeral
workspace but does not allow another build directory within that checkout.

GitHub-hosted CI cannot persist the owner's home checkout across jobs,
so **each isolated job** uses exactly one ephemeral
`<checkout>/build` and does not commit its output.

## Linux-only first-party XCB connection dependencies (R5)

If pkg-config finds both `xcb` and `xcb-randr`, the default Linux
CMake build compiles `rdp-server-x11-connection` and registers
`x11.display-event-budget-and-readiness`. Debian/Ubuntu provide the
native headers and linkage via `libxcb1-dev` and
`libxcb-randr0-dev`; the existing Linux CI job installs both.
The ordinary owner CMake/CTest one-liner is unchanged. If those
optional native development packages are missing, configure logs
that the native target and its CTest are not compiled/run; do NOT
report native PASS from headless helper checks. Windows/macOS and
the portable protocol library never require XCB. No display server,
credentials or live desktop are required for the native fixture.

## Linux native XShm capture dependencies (R5)

When pkg-config discovers both `xcb` and `xcb-shm`, Linux builds the
noninstalled `rdp-server-linux-xshm` target from the real
`x11_shared_memory_capture.cpp`. Debian/Ubuntu provide these headers and
libraries through `libxcb1-dev` and `libxcb-shm0-dev`, already provisioned
by hosted Linux CI. The ordinary
`x11.capture-native-disconnect-cancellation` case remains headless and starts
from a failed XCB descriptor. When `xvfb-run` is available, the same
production-linked executable also registers
`x11.capture-native-destructor-retirement` against a 1280x720x24 ephemeral
synthetic display. It performs a real MIT-SHM attach/capture, destructor
retirement, same-owner replacement, successful explicit disconnect, and a
second replacement generation. No logged-in desktop or credentials are used.
Missing native development files or Xvfb make only the corresponding optional
cases **NOT RUN**, never PASS. The one-root build command and portable SDK are
unchanged.

## Linux native XFixes cursor development dependencies (R5)

When `pkg-config` discovers both `xcb` and `xcb-xfixes`, the
Linux build compiles `rdp-server-linux-xfixes-cursor` from actual
`x11_cursor_tracker.cpp` and `cursor_image_conversion.cpp`.
On Debian/Ubuntu, install `libxcb1-dev` and
`libxcb-xfixes0-dev`; the existing GitHub Actions Linux job
provisions both. Native case
`x11.cursor-native-connection-denials-and-cancellation` remains headless.
When `xvfb-run` is available, the same production-linked executable also
registers `x11.cursor-native-destructor-retirement` against an ephemeral
synthetic display; it changes only that Xvfb root cursor and verifies XFixes
notification retirement while the borrowed XCB owner stays alive. Absence of
the development headers means native source/test NOT RUN, not PASS; absence of
Xvfb means only the synthetic-display retirement case is NOT RUN. No live
desktop or credentials are required. The owner's single `build/` command
and portable SDK remain unchanged.

## Linux-only native XDamage dependencies (R5)

The first-party `rdp-server-linux-xdamage` target is built when
`pkg-config` finds `xcb` and `xcb-damage`. Debian/Ubuntu
development packages: `libxcb1-dev` and `libxcb-damage0-dev`.
Linux hosted CI installs them. The target compiles the actual
`src/x11/x11_damage_tracker.cpp` plus the existing bounded
`src/core/damage_region.cpp`, with strict C++23 warnings. Its
headless `x11.damage-native-connection-denials-and-cancellation`
CTest requires no X server. When `xvfb-run` is available, the same
production-linked executable also registers
`x11.damage-native-destructor-retirement` against an ephemeral synthetic
display and proves the server-side Damage resource is retired while the
borrowed owner remains alive. If headers/libs are unavailable, these native
cases are not built and must be marked NOT RUN (not PASS); without Xvfb only
the synthetic-display retirement case is NOT RUN. No logged-in session, live
capture or credentials are required. The owner's existing one-root
configure/build/CTest command is unchanged, and XCB remains excluded from
installed portable protocol headers.

## Linux native XTEST and one-XCB owner dependencies (R5)

The XTEST controller needs `libxcb1-dev` plus `libxcb-xtest0-dev`.
Its headless denial/cancellation CTest still uses only a failed XCB descriptor.
When `xvfb-run` is present, `x11.input-native-destructor-held-input-release`
uses only an ephemeral synthetic X server: it holds one key and button through
the production XTEST controller, proves native state is down, destroys the
controller and requires both states to be released while the same XCB owner
stays healthy. This is lifecycle evidence, not authenticated desktop/input
acceptance.
With XCB/RandR, XShm, XFixes, XDamage and XTEST targets all available, CMake
also builds noninstalled `rdp-server-linux-x11-desktop`. The
`x11.desktop-resource-owner-connection-denial` CTest needs no X server.
When `xvfb-run` is present, CTest additionally registers
`x11.desktop-resource-owner-lifecycle`,
`x11.desktop-resource-event-routing`,
`x11.desktop-resource-randr-rebuild`, and
`x11.display-event-failure-defers-owner-teardown` against an ephemeral
1280x720x24 Xvfb server. The lifecycle case adds Xvfb `-noreset` because it
intentionally closes the last XCB client between independent owner generations;
that keeps the synthetic server stable while R5 teardown/recovery is tested.
The routing case generates a real XDamage notification only on that synthetic
root window; the failure case generates
an invalid unchecked core request to verify child-before-parent teardown.
The RandR case disables only the synthetic Xvfb CRTC, resizes its root to
1024x600 through XCB/RandR, verifies geometry-bound XShm/Damage/input
reconstruction keeps the same XCB descriptor, then verifies a new XDamage
notification is routed after the rebuild. The
`x11.desktop-resource-r4-read-boundary` case exercises the aggregate's real
XShm capture, XDamage snapshot/acknowledgement and XFixes cursor
refresh/image/ack path against the same ephemeral synthetic display. Borrowed
frame/cursor views are consumed synchronously before teardown. None inject
keyboard/mouse input or accesses a logged-in desktop.

Hosted Ubuntu installs `xvfb` and `xauth`; local absence means those
optional synthetic-display cases are NOT RUN, not PASS. When the concrete
Linux GSSAPI/R2 target and the one-XCB owner are both enabled, CMake also
builds noninstalled `rdp-server-linux-x11-authorized-input`. Its ordinary
`x11.input-r3-admission-route-denials-and-revocation` Xvfb CTest supplies no
admission lease and therefore cannot reach XTEST; it verifies missing
capability closes R3/R2 and the native owner. Positive input injection remains
outside ordinary CTest. The normal one-root owner command remains unchanged.

## Linux native X11 CLIPBOARD dependencies (R8)

When pkg-config finds `xcb`, Linux builds the noninstalled
`rdp-server-linux-x11-clipboard` target from the real
`src/x11/x11_clipboard_adapter.cpp`. Debian/Ubuntu provide the required
header/library through `libxcb1-dev`, already installed by hosted Linux CI.
The eight `clipboard.x11-*` CTests use a deterministic native-call seam and
need no `DISPLAY`, Xvfb, clipboard manager, RDP client or actual desktop
data. The INCR cases exercise large UTF-8, validated registered PNG,
PropertyDelete chunk progression, final zero-length completion, timeout,
generation/owner cancellation and requester destruction without a live X
server. Missing XCB development files mean this native target/test set is
**NOT RUN**, not PASS. The portable SDK and Windows/macOS builds do not gain
an XCB dependency. R5 still owns the sole XCB connection; the adapter borrows
it only while `X11DesktopResources` is valid. The owner's one-root command
is unchanged.

## Owner's required daily test from the latest GitHub main

Agents commit production code, its dedicated, registered behavior-named
CTest(s) and updated documentation **directly to `main`**. The owner does
not apply patches or merge branches. The following unchanged command must
configure, build and run the full applicable CTest suite in the **one**
persistent build root after fetching the latest `main`:

```sh
cd ~/rdp-server && git switch main && git pull --ff-only origin main && cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON && cmake --build build --config Debug --parallel 2 && ctest --test-dir build -C Debug --output-on-failure
```

Run in the appropriate shell/toolchain environment on Linux/X11, Windows
MSYS2 CLANG64 (Clang 23) and macOS 27. Check `git rev-parse HEAD`
when comparing results and inspect CMake's effective compiler, because
a reused build cache does not select a new compiler automatically. Tests
requiring live desktop/input/clipboard, credentials or service activation
must be separately opt-in: the normal full CTest cannot require them.
Agents own build/test repairs via new direct-to-main commits; the owner
only reports the output of the command.

## Linux/macOS (CMake 3.22+, C++23 compiler, OpenSSL)

```sh
# If already cloned, skip clone and reuse the checkout.
git clone https://github.com/k1moradi/RDP-server.git "$HOME/rdp-server"
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Debug --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Debug --output-on-failure
```

For Release, **reconfigure the same root** with
`-DCMAKE_BUILD_TYPE=Release` on single-config generators, understanding
it replaces prior configuration. Multi-config generators use
`--config Debug`/`--config Release` inside the same root.

## R6 Windows session-state linkage (2026-10-15; CI pending)

The noninstalled `rdp-server-windows-desktop` target now links
`wtsapi32` for read-only `WTSQuerySessionInformationW` session-state
observation, in addition to its existing `user32`, `d3d11` and
`dxgi` dependencies. The portable protocol SDK, Linux and macOS do
not gain WTS headers or libraries. This must compile under both hosted
Windows/MSVC and the owner's MSYS2 CLANG64/Clang 23; those toolchains
remain separate evidence gates.

## R6 native DXGI metadata linkage (2026-10-15; CI pending)

The noninstalled Windows-only `rdp-server-windows-desktop` adapter
explicitly links the Windows SDK `d3d11` and `dxgi` import libraries
alongside `user32`. This does not add native SDK dependencies to the
portable RDP protocol archive, Linux or macOS targets. Hosted
Windows/MSVC build and owner MSYS2 CLANG64 Clang23 are independent
verification gates; no ordinary CTest opens a live desktop.

## R6 Win32 cursor metadata linkage (2026-10-16; exact-SHA hosted PASS)

The same noninstalled `rdp-server-windows-desktop` target now compiles
`windows_cursor_snapshot.cpp` and links `gdi32` in addition to its
existing `user32`, D3D11, DXGI and WTS dependencies. `GetCursorInfo`
and `GetIconInfo` remain User32 calls; `GetObjectW`/`DeleteObject`
for the temporary cursor bitmaps require GDI32. No Windows cursor headers
or import libraries enter the installed portable protocol SDK. Hosted
Windows/MSVC and owner MSYS2 CLANG64/Clang23 remain independent compile
gates. Ordinary CTest uses synthetic callbacks and never reads a live cursor.
Implementation `0ee521f2802bb2f2fd3fd6fa1ebfb834f4d47287` compiled this
native target and passed **283/283** Windows/MSVC CTests in both Debug and
Release in Actions 38871393796. Owner MSYS2 CLANG64/Clang23 remains NOT RUN.

## Windows (PowerShell, MSVC and OpenSSL)

```powershell
$projectRoot = Join-Path $HOME "rdp-server"
$buildRoot = Join-Path $projectRoot "build"
cmake -S $projectRoot -B $buildRoot -DBUILD_TESTING=ON
cmake --build $buildRoot --config Debug --parallel 2
ctest --test-dir $buildRoot -C Debug --output-on-failure
```

Use C++23 standard mode without GNU extensions; GCC/Clang
`-Wall -Wextra -Wpedantic -Werror`, MSVC `/W4`.
Keep portable first-party code and OpenSSL separately from OS adapters.
Never compile/link xrdp, patched chansrv, VNC or another RDP daemon as
part of the active server. The current output is a protocol **library**,
not an independently usable RDP listener. Investigate build failures;
do not hide warnings, skip assertions or create a second build root.
Every implementation commit updates existing documentation/TODO and
runs [testing](testing_standards.md) gates.

## Verified build convention (2026-10-14)

At `3196a764ffbe24482ad131ad6949f1c2c23d44d9`, the checkout-local
single-build-root CMake configuration, build and CTest succeeded on all
three CI systems in [run 38535115706](https://github.com/k1moradi/RDP-server/actions/runs/38535115706).
This verifies CI checkout-local layout; it does **not** attest to the
existence of a persistent `~/rdp-server/build/` on the owner's machine
or to a production RDP daemon.

## Additional local-home-path enforcement (2026-10-14)

At `e1843b07c8772588f29e45a9b8e328e51c59e2ff`, the CMake
configure now **also refuses ordinary local checkouts outside
`~/rdp-server`**. The existing single `build/` root check applies
in both local and CI configurations. GitHub Actions
[run 38535723210](https://github.com/k1moradi/RDP-server/actions/runs/38535723210)
passed Linux, macOS and Windows with the explicit hosted-CI workspace
exception. No claim is made about directly executing a build on the
owner's local machine.

The owner's first reported macOS execution on
`bdcb68520c5339aa9866f2e7d5949cf6b5c9c056` reached the checkout through
`~/rdp-server` but CMake exposed the same case-preserving directory as
`/Users/keivanmoradi/RDP-server`. The old guard used only
`cmake_path(NORMAL_PATH)`, so it rejected that valid filesystem alias before
configuration. The corrected guard resolves the existing source and
`~/rdp-server` candidate with `file(REAL_PATH)` before comparison. It permits
case-only spelling differences on macOS/Windows only after that candidate is
known to exist; Linux remains case-sensitive. Windows also considers the MSYS2
shell `HOME` and, when present, converts it with `cygpath -m` instead of
assuming that `USERPROFILE` is the shell's `~`. The one-build-root check is
unchanged: only `<that checkout>/build` is accepted. Owner rerun of the exact
cross-platform command is still required before local macOS or MSYS2 PASS is
claimed.

## Automated compilation, tests and artifact delivery (2026-10-14)

The existing `.github/workflows/ci.yml` owns one unified pipeline for
`main` pushes, pull requests, manual dispatches and protocol release
tags. Each Linux/macOS/Windows runner uses only its checkout-local
`build/` root, compiles/tests Debug, reconfigures **the same root**
for Release, compiles/tests again, and stages an SDK install in
`build/stage`. The downstream consumer uses `build/consumer` and
loads the installed `RDPServer::protocol` CMake export. CPack generates
a ZIP in `build/`, SHA-256 checksums, and uploads both to the CI run.

For an ordinary local dry run, reuse **only** `~/rdp-server/build/`:

```sh
cmake -S "$HOME/rdp-server" -B "$HOME/rdp-server/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build "$HOME/rdp-server/build" --config Release --parallel 2
ctest --test-dir "$HOME/rdp-server/build" -C Release --output-on-failure
cmake --install "$HOME/rdp-server/build" --config Release --prefix "$HOME/rdp-server/build/stage"
cmake -S "$HOME/rdp-server/tests/consumer" -B "$HOME/rdp-server/build/consumer" -DCMAKE_PREFIX_PATH="$HOME/rdp-server/build/stage" -DCMAKE_BUILD_TYPE=Release
cmake --build "$HOME/rdp-server/build/consumer" --config Release --parallel 2
ctest --test-dir "$HOME/rdp-server/build/consumer" -C Release --output-on-failure
cmake --build "$HOME/rdp-server/build" --config Release --target package
```

Auto-publishing on `protocol-vX.Y.Z` tags is **prerelease delivery of
a development static library**, with no service activation or runtime
installation. The tag must match `PROJECT_VERSION` and point to a
commit reachable from `main`; tests on all 3 OSes and the documentation
gate must pass first. Do not describe this as RDP-server deployment
until a real authenticated server and OS adapters have been accepted.

## Verified SDK packaging on CI (2026-10-14)

The unified build/test/staged-install/downstream-consumer/CPack steps
passed in [Actions run 38543429777](https://github.com/k1moradi/RDP-server/actions/runs/38543429777)
for exact commit `1aa025960288d40f476e85c5a9c5f97b06bebf20`
on Linux, macOS and Windows. All runner output remained in the
runner's checkout-local `build/`; three distinct SDK ZIP artifacts
and SHA-256 manifests uploaded. The tag-triggered GitHub prerelease
job was SKIPPED (no tag). Direct local `~/rdp-server/build/` testing
and production server installation are NOT RUN.

## R10 runtime offline configuration syntax check (2026-10-15)

The R10 offline increment adds a native `rdp-server`
executable in the existing sole `build/` root. `rdp-server --help`
and `rdp-server --version` are informational. Attempting to start the
service fails with exit 2. `rdp-server --check-config FILE` performs
**offline syntax-only** validation (exit 0 for accepted syntax, exit
3 for invalid configuration). Accepted syntax does NOT verify real
certificate contents or OS authorization, and does not activate a
listener or server. The 25 `runtime.*` CTests execute without live
credentials, desktop access or socket binds. The SDK install/export
and CPack ZIP must remain protocol-only. Full project CI and local
same-main checkout validation remain NOT RUN at authoring.

## R10 offline POSIX configuration-file policy (2026-10-15)

The existing `rdp-server --check-config FILE` remains a syntax-only
diagnostic that never opens a listener. On POSIX platforms the config
file must be a regular file, not a final-component symlink, FIFO or
directory, and it cannot be group/world writable. A privately owned
file can be prepared with `chmod 600 /path/to/config`. Normal CTests
use generated synthetic files under the existing `build/runtime-fixtures`
directory. Windows currently validates syntax without native ACL/
reparse-point acceptance; do not use these checks as a substitute for
TLS certificate/private-key provisioning or OS authorization.
Five extra `runtime.*` CTests run only on POSIX and exercise the
actual runtime executable. The owner's established one-line
configure/build/CTest command is unchanged.

## R10 Windows native offline configuration handle (2026-10-15)

Windows `rdp-server --check-config FILE` accepts only drive-absolute
paths to disk-backed regular files without a final reparse point.
Four additional Windows-only `runtime.*` CTests use existing
`build/runtime-fixtures` data without accessing real credentials.
The owner's existing one-line CMake/CTest workflow is unchanged.
DACL and TLS private-key file permissions are NOT yet verified;
`--check-config` does not activate a service.

## R10 Windows offline config file DACL fixture gate (2026-10-15)

On Windows, `rdp-server --check-config` additionally inspects the
opened HANDLE's DACL for broad write/delete/permission-changing
grants. All Windows synthetic config fixtures in normal CTest are
given a private DACL using standard `whoami.exe` and `icacls.exe`,
then dedicated negative cases grant Everyone, Authenticated Users
or BUILTIN Users modify access and require exit 3. These commands
run only against files generated under `build/runtime-fixtures/`,
never a real credential or system file. The owner's normal CMake/
CTest one-liner is unchanged. No complete effective-access, TLS
private-key permissions or OS-admission claim is implied.

## R10 offline TLS-file metadata preflight (2026-10-15)

Use `rdp-server --check-config FILE` to validate syntax without
looking up TLS files. Use `rdp-server --check-tls-files FILE` to
add an offline metadata-only check of the configured actual cert/key
file paths. Accepted certificate files must be regular, nonempty,
at most 1 MiB, and not group/world writable on POSIX. Private keys
must be regular, nonempty, at most 256 KiB and owner-private
(`chmod 600`) on POSIX; the key owner must match the running eUID.
Windows checks non-reparse HANDLE identity and restricts key read
grants to owner/SYSTEM/Administrators. The cert and key may not
refer to the same underlying file (including via hard links).
A successful preflight does **not** validate X.509, PEM key
contents, private-key matching, expiry or service authorization,
and cannot start the server. Dedicated `runtime.*tls-files*`
CTests use synthetic content in `build/runtime-fixtures`.

## R10 POSIX TLS parent-path symlink gate (2026-10-15)

The separate `rdp-server --check-tls-files FILE` command checks
credential **metadata only**; syntax-only `--check-config` is
unchanged. On Linux/macOS, TLS files can reside in real nested
directories but none of their parent components may be symlinks.
The regular-file, size, owner, private-key mode and hardlink-alias
checks still apply. Three POSIX-only CTests generate safe synthetic
files under `build/runtime-fixtures`, including two parent-symlink
denials. The unchanged owner configure/build/CTest one-liner runs
these without genuine PEM data or a listener. Windows CLANG64
and real TLS contents remain separately unverified.

## R10 offline PEM credential consistency check (2026-10-15)

`rdp-server --check-tls-credentials FILE` runs the existing config
syntax and TLS-file metadata checks, then parses the already-open
certificate and private key as PEM and requires the key to match the
certificate. It never prompts for a password; encrypted private keys
are rejected. A passing result does not establish certificate trust,
hostname, chain, revocation, user authentication or permission to start the
RDP service. The certificate must be currently valid, match the private key,
and be acceptable to OpenSSL for TLS server use. Ordinary CTests use fixed
test-only EC material under `build/runtime-fixtures`; no real
credential is installed or read.

## Opt-in R9 Linux/Clang libFuzzer build

Normal builds leave `RDP_SERVER_BUILD_FUZZERS=OFF`. The Linux
sanitizer CI may set it ON while reusing that job's sole `build/`.
It requires Linux/Clang/CTest; the fuzzer target links
`-fsanitize=fuzzer,address,undefined`. Corpus and crash outputs
remain in `build/fuzz-corpus-mcs-cliprdr` and
`build/fuzz-artifacts-mcs-cliprdr`. Do not create `build-fuzz`
or alter the owner's unchanged configure/build/CTest command.


## R7 ScreenCaptureKit stream lifecycle and CoreVideo handoff (2026-10-16)

On Apple, the existing `rdp-server-macos-capture` target now enables Objective-C++ only inside the `APPLE` block and compiles `screen_capture_stream.mm` with ARC. The target links `ScreenCaptureKit`, `Foundation`, `CoreMedia`, `CoreVideo`, `CoreGraphics`, and `CoreFoundation`; none of these dependencies are added to `rdp-server-protocol`, Linux, or Windows. The existing CMake command remains valid and does not require Xcode project generation or a second build tree.

Ordinary CTests do not invoke the native ScreenCaptureKit backend. They use the production C++ lifecycle owner with an injected backend and synthetic CoreVideo buffers, so a normal test run neither starts live screen capture nor requests TCC permission. Compiling/linking the Objective-C++ source on macOS is evidence that the SDK bridge builds; it is not evidence that a live screen was captured.


## R4 static x264 encoder dependency (2026-10-16)

The normal owner configure/build/CTest command is unchanged. R4 builds the
pinned sources under `third_party/x264` as a static `rdp-server-x264`
library and links it only into noninstalled `rdp-server-graphics`. No
network fetch, system x264 installation, FFmpeg, NASM, OpenCL or second build
tree is required. The portable installed `RDPServer::protocol` SDK remains
x264-free.

The first integration deliberately uses x264's portable C implementation with
one encoder thread and no assembly optimizations. This is a correctness-first
cross-platform build contract; SIMD/thread tuning requires later R4/R9
measurement and must not silently change frame ordering or ownership.


## R7 generation-safe macOS cursor snapshot boundary (2026-10-16)

The Apple-only `rdp-server-macos-capture` target now also compiles `mac_cursor_snapshot.mm` with ARC and links AppKit in addition to the existing ScreenCaptureKit/CoreGraphics/CoreVideo stack. AppKit is not linked into the portable protocol SDK or non-Apple builds. Deprecated system-wide cursor introspection calls are locally warning-suppressed only in this translation unit; the target otherwise retains `-Wall -Wextra -Wpedantic -Werror`.

The existing `test_macos_capture_pixel_buffer` executable gains three synthetic cursor cases on every OS. Non-Apple builds compile only `mac_cursor_snapshot.cpp`; Apple additionally compile/links the real AppKit bridge through `rdp-server-macos-capture`, but ordinary CTest never invokes `queryNativeMacCursorSnapshot`. No TCC prompt, live cursor read or input event is part of the standard test command.


## R7 generation-pinned macOS input controller (2026-10-16)

The Apple-only `rdp-server-macos-capture` target also compiles `mac_input_controller.mm` and links ApplicationServices for the non-prompting Accessibility trust query; CoreGraphics already supplies Quartz event construction/posting. The native posting callback remains private to that translation unit and is not runtime-wired. No extra framework dependency reaches the installed portable protocol SDK or non-Apple builds.

`test_macos_input_controller` is registered on every OS with three ordinary cases: `macos.input-controller-lifecycle`, `macos.input-controller-validation-denials`, and `macos.input-controller-revocation-cleanup`. Non-Apple builds compile the portable controller plus synthetic geometry sources directly. Apple links the production macOS target, which compile/links the real Quartz/ApplicationServices bridge, but the tests inject their own callback and never query Accessibility or post native events.


## R7 synchronous macOS desktop session/permission guard (2026-10-16)

The Apple-only `rdp-server-macos-capture` target now also compiles `mac_desktop_session_guard.cpp`. Its native path uses CoreGraphics/CoreFoundation already linked by the R7 target and the existing non-prompting Screen Recording/Accessibility probes; no new framework reaches the portable protocol SDK.

`test_macos_desktop_session_guard` is registered on every OS with `macos.desktop-session-lifecycle`, `macos.desktop-session-validation-denials`, and `macos.desktop-session-revocation-reentry`. Non-Apple builds compile the portable guard plus synthetic geometry directly. Apple links the production R7 target, but ordinary CTest injects synthetic session/permission callbacks and never calls `CGSessionCopyCurrentDictionary`, queries real TCC/Accessibility state, starts capture, or posts input.


## R7 NSWorkspace session-change observer linkage (2026-10-16)

The Apple-only `rdp-server-macos-capture` target compiles
`native_session_change_watch.cpp` plus ARC Objective-C++
`native_session_change_watch.mm`. It reuses the target's existing AppKit and
Foundation linkage; no new native framework enters the installed portable
protocol SDK, Linux or Windows builds. Non-Apple
`test_macos_desktop_session_guard` compiles the portable watch source directly.

Ordinary CTest uses an injected registration backend and the production atomic
revision recorder; it never creates `NSWorkspace` observers. Native
`startNative()` is explicit and fails closed unless called from an
already-running AppKit main event-loop context. Hosted Apple compilation proves
SDK/API linkage only; it does not prove real fast-user-switch notifications
were delivered. Owner macOS 27 remains the separate delivery/desktop acceptance
gate.


## R7 portable framebuffer bridge build wiring (2026-10-16)

`capture_framebuffer_view.cpp` is compiled into the Apple-only
`rdp-server-macos-capture` target. On non-Apple hosts the standard synthetic
macOS fixture compiles that portable source directly beside
`capture_pixel_layout.cpp`, so stride/storage contract regressions are caught
without CoreVideo or ScreenCaptureKit headers.

The bridge is header-only with respect to R4 ownership: it consumes
`core/framebuffer_view.h` but does not link `rdp-server-graphics`, x264 or
any protocol transport target. Apple `test_macos_capture_stream` continues to
link the private macOS capture target only for SDK/lifecycle compile coverage;
the public native ScreenCaptureKit factory remains absent.


## R4 sanitizer compiler coverage for vendored x264 (2026-10-16)

Ordinary builds remain unchanged. In the existing Linux sanitizer CI job only,
CMake selects `clang` for C as well as `clang++` for C++, applying the same
ASan/UBSan compile flags to both languages. The repository's C translation
units are exclusively the pinned `third_party/x264` sources, so this directly
instruments the real codec while the existing R4 C++ converter/producer and
test executables are instrumented through the C++ flags. Link sanitizer flags
remain on the test executables. No system x264, alternate build directory or
new dependency is introduced.

## R2 Windows/macOS native admission evidence build boundaries (2026-10-17)

Windows builds a noninstalled `rdp-server-windows-native-session-evidence`
static target from the real Win32 token, LSA and WTS APIs and links only
`advapi32`, `secur32` and `wtsapi32`. The dedicated CTest is
`security.windows-native-session-evidence-provider-denials`. It does not
enumerate/capture a desktop or authenticate a client.

Apple builds a noninstalled `rdp-server-macos-native-session-evidence` static
target and links CoreFoundation, Security and SystemConfiguration. Its
`security.macos-native-session-evidence-provider-denials` CTest performs only
read-only console/audit/Security-session observations. It does not request TCC,
start ScreenCaptureKit, post input or start an AppKit observer. Linux and the
portable installed SDK gain neither dependency. Use the existing canonical
`build/` root and ordinary full CTest; no second build root or opt-in credential
cache is introduced.

## R7 Qt desktop GUI shell (2026-10-18)

Build optionally with `-DRDP_SERVER_BUILD_DESKTOP_GUI=ON` and Qt 6.4+ Widgets; run `ctest --test-dir build -R '^gui[.]offscreen-' --output-on-failure`. The default headless build remains Qt-free. Shipping `rdp-server-desktop` has a deny-only R10 adapter: opening the window creates no listener, capture or TCC request. R9 still must package redistributable Qt libraries/plugins and a macOS double-clickable `.app` in ZIP, verify LGPL/GPL compliance and measure archive size. R10 must provide the real typed admitted host-control API before Start can function; fake UI tests are not host acceptance.

## R5 extracted Linux GUI ZIP (2026-10-18)

The R7 Qt Widgets desktop target is explicitly opt-in. On a Linux builder with
Qt6 development packages and the `qt6-qpa-plugins` XCB platform plugin:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
  -DRDP_SERVER_BUILD_TESTING=OFF -DRDP_SERVER_BUILD_DESKTOP_GUI=ON
cmake --build build --config Release --target rdp-server-desktop --parallel 2
python3 packaging/linux/gui_bundle.py bundle \
  --gui build/rdp-server-desktop \
  --xcb-plugin /usr/lib/x86_64-linux-gnu/qt6/plugins/platforms/libqxcb.so \
  --source-sha "$(git rev-parse HEAD)" --version 0.1.0 \
  --output build/rdp-server-gui-linux.zip
python3 packaging/linux/gui_bundle.py verify \
  --bundle build/rdp-server-gui-linux.zip
```

Adjust the XCB plugin path for the builder architecture; the CI job locates
it using the package inventory. The builder uses `ldd` only on trusted local
build/Qt inputs and copies non-glibc dependency closure and the platform
plugin into the archive. Extract with a ZIP tool preserving Unix modes,
then double-click `RDP Server.desktop` (a file manager may separately ask to
trust an extracted desktop launcher), or run `run-gui.sh` via the file
manager. Both invoke only the Qt GUI, using relative library/plugin paths.
The archive does not contain `rdp-server serve` and does not use FUSE.
glibc/loader and native X server/device drivers remain host requirements;
do not claim compatibility on a distribution until the extracted ELF ABI,
`ldd`, Qt XCB plugin and GUI are tested there. Review Qt LGPL/GPL and bundled
library notices before distributing beyond development preview.

The GUI is deny-only until R2/R10 host control and native authority exist.
Launch does not bind a listener, request system privileges, capture pixels,
start input injection, install/enable systemd or create credentials. Newly
created user files obey umask 0077; no config is written by the launcher.
Live access requires the current owner to log into a physical X11 seat0.

## R7 Qt-to-R10 control adapter (2026-10-18)

The common Qt target now compiles `src/gui/host_control.cpp` and includes
the private source root only so it can consume
`server/runtime/runtime_host_control.h`. The adapter owns no listener,
lease, policy generation or native desktop. The production GUI constructs
R10's deny-only `UnavailableRuntimeHostControl`; extraction or double-click
therefore still cannot start networking. Windows R6's shared launcher uses
the same adapter. A future live backend may replace the unavailable R10
object without changing the UI authority boundary.

## R7 macOS PORTABLE-GUI .app ZIP (2026-10-18)

On an arm64 macOS builder with Qt 6.4+ installed locally:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
  -DRDP_SERVER_BUILD_TESTING=OFF -DRDP_SERVER_BUILD_DESKTOP_GUI=ON
cmake --build build --config Release --target rdp-server-desktop --parallel 2
sha="$(git rev-parse HEAD)"
short_sha="$(printf '%s' "$sha" | cut -c1-12)"
qt_bins="$(qmake6 -query QT_INSTALL_BINS)"
python3 packaging/macos/gui_bundle.py \
  --app build/rdp-server-desktop.app \
  --macdeployqt "$qt_bins/macdeployqt" \
  --source-sha "$sha" --version 0.1.0 --minimum-macos 13.0 \
  --output "build/rdp-server-portable-gui-0.1.0-macos-arm64-$short_sha.zip"
```

The ZIP root contains the actual `rdp-server-desktop.app`, its executable,
Info.plist, Qt frameworks and Cocoa platform plugin. The packager runs only
the caller-supplied local macdeployqt; it never launches the GUI, requests
TCC, installs a LaunchAgent, changes firewall/network state, downloads
dependencies or enables serving. Signing/notarization are recorded as
unverified development-preview state until R9/native release checks run.

## R9 Windows PORTABLE-GUI native assurance (2026-10-18)

The hosted Windows CLANG64 lane installs the matching MSYS2 Qt6 base package and builds `rdp-server-windows-gui` in the canonical checkout-local `build/` root. It then runs `packaging/windows/gui_bundle.py` with the local windeployqt, verifies the independently recomputed archive SHA with `scripts/verify_portable_gui.py`, extracts under `build/Extracted PORTABLE GUI`, and runs `scripts/verify_windows_pe_closure.py` with llvm-objdump. The PE verifier requires every non-system imported DLL, including compiler runtimes, to exist in the extracted tree.

`scripts/smoke_windows_portable_gui.ps1` executes the extracted `--offline-self-test` and `--offline-start-denial-test`, then starts the normal GUI twice, waits for a top-level window handle, requires no TCP/UDP endpoints owned by that process, closes through the ordinary window close path, and compares firewall profile state before/after. This is hosted packaging/offline evidence only; it neither starts RDP serving nor substitutes for the required owner-native unprivileged receipt. The lane intentionally does not upload the ZIP before aggregate exact-SHA success.

## Hosted arm64 macOS GUI closure lane (2026-10-18)

CI job `r7-macos-portable-gui` uses the standard arm64
`macos-latest` image, installs Homebrew `qt` and `openssl@3`, configures
the canonical checkout-local `build/` root with
`RDP_SERVER_BUILD_DESKTOP_GUI=ON`, builds
`rdp-server-desktop.app`, runs the dedicated package CTest and invokes
`packaging/macos/gui_bundle.py` with local `macdeployqt`. The extracted
archive is checked with `otool -L`; absolute Homebrew and hosted-runner home
paths are forbidden. This lane intentionally stops short of an Aqua
first-screen smoke and release signing/notarization acceptance.

## macOS macdeployqt Homebrew path resolution (2026-10-18)

The macOS GUI packager accepts a caller-supplied Homebrew
`$qt_prefix/bin/macdeployqt` even when the tool or an ancestor path is a
symlink. It resolves that path strictly and executes only the resulting
regular executable target. Broken links, directories and non-executable
targets fail closed. This does not permit symlink members in the source app or
portable archive.

## macOS minimal Qt plugin deployment (2026-10-18)

The desktop GUI links Qt Widgets and requires Cocoa QPA, not QML. The packager
queries the Qt plugin root using the `qmake` sibling of the supplied
`macdeployqt`, copies only `platforms/libqcocoa.dylib`, then invokes
`macdeployqt` with `-no-plugins -no-codesign` and
`-executable=<staged libqcocoa.dylib>`. This keeps the development-preview
archive unsigned as declared in its metadata and avoids dragging unrelated
Homebrew Qt QML/VirtualKeyboard/PDF plugin trees into the package. Native CI
still rejects any extracted Mach-O dependency that resolves to Homebrew or a
runner-home path.

## macOS staged install-ID normalization and ad-hoc preview signing (2026-10-18)

Homebrew Qt may retain absolute install IDs even after `macdeployqt` has
copied and patched the app. The R7 packager therefore normalizes staged
framework/plugin Mach-O IDs to bundle-relative `@rpath` IDs after deployment,
then runs `codesign --force --deep --sign -` on the finished app. This is
only an ad-hoc arm64 execution signature; `SIGNING-TRUST.json` continues to
report `signed=false` and `notarized=false` for release trust, with
`ad_hoc_signed=true`. Native CI continues to reject any remaining
Homebrew/runner dependency or install-name references.
