#ifndef GWLB_XDP_BPF_HELPERS_MIN_H
#define GWLB_XDP_BPF_HELPERS_MIN_H

/*
 * Stand-in for libbpf's <bpf/bpf_helpers.h>, covering only what this codebase
 * uses: the SEC()/__uint()/__type() macros, LIBBPF_PIN_BY_NAME, and the 7 BPF
 * helpers the programs call.
 *
 * The real bpf_helpers.h unconditionally includes the ~4700-line generated
 * bpf_helper_defs.h (every ~200 kernel helpers, plus scalar types and
 * kernel-internal structs their prototypes reference) — the same "giant
 * generated header for a handful of things" problem net_hdrs.h solves for
 * vmlinux.h. The 7 helpers below are copied verbatim from the container's
 * /usr/include/bpf/bpf_helper_defs.h, so the numeric IDs are copied, not
 * guessed (stable UAPI, never renumbered).
 *
 * bpf_endian.h is self-contained and still included directly from libbpf.
 *
 * The constants below are the values this codebase references from
 * <linux/bpf.h>'s enums, reduced to #defines.
 */

#define BPF_MAP_TYPE_HASH		1
#define BPF_MAP_TYPE_ARRAY		2
#define BPF_MAP_TYPE_PERCPU_HASH	5
#define BPF_MAP_TYPE_PERCPU_ARRAY	6
#define BPF_MAP_TYPE_LRU_HASH		9
#define BPF_MAP_TYPE_DEVMAP		14
#define BPF_MAP_TYPE_DEVMAP_HASH	25

/* bpf_map_update_elem()'s flags argument (BPF_EXIST unused by this codebase,
 * omitted). */
#define BPF_ANY		0
#define BPF_NOEXIST	1

#define XDP_ABORTED	0
#define XDP_DROP	1
#define XDP_PASS	2
#define XDP_TX		3
#define XDP_REDIRECT	4

/* Freestanding BPF compilation has no <stddef.h> NULL either — same
 * omission real bpf_helpers.h itself papers over for CO-RE/vmlinux.h
 * users, for the same reason. */
#ifndef NULL
#define NULL ((void *)0)
#endif

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#if __GNUC__ && !__clang__
#define SEC(name) __attribute__((section(name), used))
#else
#define SEC(name) \
	_Pragma("GCC diagnostic push") \
	_Pragma("GCC diagnostic ignored \"-Wignored-attributes\"") \
	__attribute__((section(name), used)) \
	_Pragma("GCC diagnostic pop")
#endif

#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

enum libbpf_pin_type {
	LIBBPF_PIN_NONE,
	LIBBPF_PIN_BY_NAME,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *) 23;
static long (*bpf_xdp_adjust_head)(struct xdp_md *xdp_md, int delta) = (void *) 44;
static long (*bpf_redirect_map)(void *map, __u64 key, __u64 flags) = (void *) 51;
static long (*bpf_xdp_load_bytes)(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len) = (void *) 189;
static long (*bpf_xdp_store_bytes)(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len) = (void *) 190;

#endif /* GWLB_XDP_BPF_HELPERS_MIN_H */
