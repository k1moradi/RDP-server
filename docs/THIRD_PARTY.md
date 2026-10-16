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


## x264 (R4 H.264 encoder)

R4 vendors the library-only source subset of the VideoLAN x264 project from
the public `mirror/x264` Git mirror at immutable revision
`4613ac3c15fd75cebc4b9f65b7fb95e70a3acce1` (2024-05-13). The canonical
upstream project is <https://code.videolan.org/videolan/x264.git>. Upstream
source headers state GNU GPL version 2 or later; `third_party/x264/COPYING`
is retained. The repository's GPL-3.0-or-later distribution uses x264 under
the GPL's "or later" option.

The top-level CMake build compiles one static 8-bit x264 library from the
vendored C encoder sources. Assembly, OpenCL, threading, the x264 CLI,
FFmpeg/libav, GPAC and L-SMASH are disabled and are not bundled. No upstream
source file is modified; the only repository-supplied files in that directory
are `config.h`, `x264_config.h`, and `README.rdp-server.md`.
`rdp-server-x264` is linked privately by the noninstalled
`rdp-server-graphics` target. It is not linked by, installed with, or
exported through `rdp-server-protocol` / `RDPServer::protocol`.
