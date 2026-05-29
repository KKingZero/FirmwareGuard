#ifndef FG_ARCH_H
#define FG_ARCH_H

/* Caller must include "firmwareguard.h" first. This header relies on
 * FG_NOT_SUPPORTED, bool (via <stdbool.h>), and snprintf-family headers
 * already being in scope. */

typedef enum {
    FG_ARCH_UNKNOWN = 0,
    FG_ARCH_X86,
    FG_ARCH_X86_64,
    FG_ARCH_ARM,
    FG_ARCH_AARCH64
} fg_arch_t;

static inline fg_arch_t fg_detect_arch(void) {
#if defined(__aarch64__)
    return FG_ARCH_AARCH64;
#elif defined(__arm__)
    return FG_ARCH_ARM;
#elif defined(__x86_64__)
    return FG_ARCH_X86_64;
#elif defined(__i386__)
    return FG_ARCH_X86;
#else
    return FG_ARCH_UNKNOWN;
#endif
}

static inline const char *fg_arch_name(fg_arch_t a) {
    switch (a) {
        case FG_ARCH_X86:     return "x86";
        case FG_ARCH_X86_64:  return "x86_64";
        case FG_ARCH_ARM:     return "arm";
        case FG_ARCH_AARCH64: return "aarch64";
        default:              return "unknown";
    }
}

static inline bool fg_arch_is_x86_family(fg_arch_t a) {
    return a == FG_ARCH_X86 || a == FG_ARCH_X86_64;
}

/* Capability gate: x86-only modules call this first.
 * Returns FG_NOT_SUPPORTED on ARM so caller reports cleanly instead of failing.
 * Only usable in int-returning functions; the early `return FG_NOT_SUPPORTED`
 * is intentionally incompatible with void / non-int returns (compile error
 * surfaces misuse at build time). */
#define FG_REQUIRE_X86()                                                    \
    do {                                                                    \
        if (!fg_arch_is_x86_family(fg_detect_arch())) {                     \
            return FG_NOT_SUPPORTED;                                        \
        }                                                                   \
    } while (0)

/* Report annotation helper: check classifications per plan. */
typedef enum {
    FG_CHECK_SUPPORTED = 0,
    FG_CHECK_UNSUPPORTED,
    FG_CHECK_NOT_APPLICABLE,
    FG_CHECK_FAILED
} fg_check_status_t;

#endif /* FG_ARCH_H */
