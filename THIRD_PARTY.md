# Third-party dependencies and attribution

The first-party C++23 code in this repository uses GPL-3.0-or-later.
Cryptographic primitives in the supported core build use the platform's
reviewed OpenSSL 3 development libraries and are not a bundled xrdp runtime.

Historical provenance: selected source was migrated from
[`k1moradi/xrdp-console`](https://github.com/k1moradi/xrdp-console)
at commit `1a8b83f07165783d62ce5f6657d4e1670ce62ff4`, preserving
its GPL license and explicit attribution. That project contained
upstream-derived Apache-2.0 xrdp protocol/header/C support sources;
**those upstream-owned C files are not bundled or linked here**.
Any future import of upstream code must retain its exact copyright,
license and provenance rather than simply rewriting file headers.

OpenSSL: <https://www.openssl.org/source/license.html>.

Support for FreeRDP, Windows App, X11, Wayland or macOS means protocol and
platform interoperability targets, **not** bundled third-party runtimes.
