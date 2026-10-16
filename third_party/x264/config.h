#pragma once

/* rdp-server pinned x264 portable-C build configuration.
 * Keep architecture assembly and external codec/container dependencies off. */
#if defined(_WIN32)
# define SYS_WINDOWS 1
#else
# define SYS_WINDOWS 0
#endif
#if defined(__APPLE__)
# define SYS_MACOSX 1
#else
# define SYS_MACOSX 0
#endif
#if defined(__linux__)
# define SYS_LINUX 1
#else
# define SYS_LINUX 0
#endif
#define SYS_FREEBSD 0
#define SYS_OPENBSD 0
#define SYS_SunOS 0
#define SYS_BEOS 0
#define ARCH_X86 0
#define ARCH_X86_64 0
#define ARCH_ARM 0
#define ARCH_AARCH64 0
#define ARCH_PPC 0
#define ARCH_MIPS 0
#define ARCH_LOONGARCH 0
#define HAVE_MMX 0
#define HAVE_X86_INLINE_ASM 0
#define HAVE_AS_FUNC 0
#define HAVE_VECTOREXT 0
#define HAVE_ALTIVEC 0
#define HAVE_ALTIVEC_H 0
#define HAVE_ARMV6 0
#define HAVE_ARMV6T2 0
#define HAVE_NEON 0
#define HAVE_MSA 0
#define HAVE_LSX 0
#define HAVE_LASX 0
#define HAVE_SVE 0
#define HAVE_SVE2 0
#define HAVE_THREAD 0
#define HAVE_POSIXTHREAD 0
#define HAVE_WIN32THREAD 0
#define HAVE_BEOSTHREAD 0
#define HAVE_LOG2F 1
#define HAVE_STRTOK_R 1
#define HAVE_MALLOC_H 0
#define HAVE_GPL 1
#define HAVE_INTERLACED 1
#define HAVE_OPENCL 0
#define HAVE_AVS 0
#define USE_AVXSYNTH 0
#define HAVE_SWSCALE 0
#define HAVE_LAVF 0
#define HAVE_FFMS 0
#define HAVE_GPAC 0
#define HAVE_LSMASH 0
#define HAVE_CPU_COUNT 0
#define HAVE_THP 0
#define HAVE_WINRT 0
#define HAVE_BITDEPTH8 1
#define HAVE_BITDEPTH10 0
#define STACK_ALIGNMENT 16
