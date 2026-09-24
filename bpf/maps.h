#ifndef GWLB_XDP_MAPS_H
#define GWLB_XDP_MAPS_H

#include "net_hdrs.h"
#include "bpf_helpers_min.h"
#include "geneve_defs.h"

/*
 * One LRU hash for both address families (struct flow_key tags which —
 * see geneve_defs.h) rather than a flow_state_v4/v6 pair: less map-value
 * space wasted on a v4 entry's unused address bytes than two full-width
 * maps would need doubled up, at the cost of v4 and v6 flows now sharing
 * one eviction budget instead of each having its own guaranteed capacity —
 * a burst of one family's traffic can now evict the other's entries,
 * which two separate maps never allowed.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); /* Resized during setup */
	__type(key, struct flow_key);
	__type(value, struct outer_hdr_cache);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, 0); /* shared by encap and decap */
} flow_state SEC(".maps");

enum metric {
	DECAP_CNT_PASS_NOT_GENEVE_PACKETS = 0,
	DECAP_CNT_PASS_NOT_GENEVE_BYTES,
	DECAP_CNT_DROP_MALFORMED_PACKETS,
	DECAP_CNT_DROP_MALFORMED_BYTES,
	DECAP_CNT_DROP_UNKNOWN_ENI_PACKETS,
	DECAP_CNT_DROP_UNKNOWN_ENI_BYTES,
	DECAP_CNT_OK_PACKETS,
	DECAP_CNT_OK_BYTES,
	ENCAP_CNT_DROP_MALFORMED_PACKETS,
	ENCAP_CNT_DROP_MALFORMED_BYTES,
	ENCAP_CNT_DROP_FLOW_MISS_PACKETS,
	ENCAP_CNT_DROP_FLOW_MISS_BYTES,
	ENCAP_CNT_OK_PACKETS,
	ENCAP_CNT_OK_BYTES,
	DECAP_CNT_DROP_ORIGIN_NOT_ALLOWED_PACKETS,
	DECAP_CNT_DROP_ORIGIN_NOT_ALLOWED_BYTES,
	/* Inner packet larger than one GENEVE packet on the uplink can carry
	 * (max_inner_len in _decap.c) — most likely GRO-merged GENEVE
	 * packets. */
	DECAP_CNT_DROP_OVERSIZE_PACKETS,
	DECAP_CNT_DROP_OVERSIZE_BYTES,
	/* Reply too large to fit the uplink once encapsulated — see
	 * max_inner_len in _encap.c. */
	ENCAP_CNT_DROP_OVERSIZE_PACKETS,
	ENCAP_CNT_DROP_OVERSIZE_BYTES,
	__METRIC_MAX,
};

struct metric_key {
	__u32	ifindex;
	__u32	counter;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, __METRIC_MAX); /* Resized during setup */
	__type(key, struct metric_key);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, 0); /* shared by encap and decap */
} metrics SEC(".maps");

/* amount is 1 for every packet-outcome counter, or a packet's byte length
 * for a _BYTES counter. A plain (non-atomic) add is enough: the value is
 * this CPU's own copy, and both programs run in softirq context (NAPI, or
 * the backlog queue veth feeds), which never nests on one CPU. */
static __always_inline void increment_metric(__u32 ifindex, __u32 idx, __u64 amount)
{
	struct metric_key key = { .ifindex = ifindex, .counter = idx };
	__u64 *cnt = bpf_map_lookup_elem(&metrics, &key);

	if (!cnt) {
		/* First packet for this (ENI, counter): create the entry zeroed,
		 * then re-look-up. Two CPUs can race here; the loser's BPF_NOEXIST
		 * fails harmlessly and it increments the entry the winner made. */
		__u64 zero = 0;

		bpf_map_update_elem(&metrics, &key, &zero, BPF_NOEXIST);
		cnt = bpf_map_lookup_elem(&metrics, &key);
	}
	if (cnt)
		*cnt += amount;
}

#endif /* GWLB_XDP_MAPS_H */
