# Pinned x264 source

This directory contains the library-only source subset used by R4.

- Project: x264 / VideoLAN
- Canonical upstream: https://code.videolan.org/videolan/x264.git
- Vendored source mirror: https://github.com/mirror/x264
- Pinned immutable revision: `4613ac3c15fd75cebc4b9f65b7fb95e70a3acce1`
- Revision date: 2024-05-13
- License: GNU GPL version 2 or later, as stated in the source headers and COPYING
- Local modifications: no upstream source files are modified. The repository supplies only
  `config.h` and `x264_config.h` for a portable 8-bit static C build with assembly,
  OpenCL, threading, CLI, FFmpeg/libav, GPAC and L-SMASH disabled.

Only the encoder library sources required by upstream's Makefile are vendored. The x264
CLI, input/output filters, examples and checkasm utilities are intentionally absent.
