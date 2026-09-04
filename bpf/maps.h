#ifndef GWLB_XDP_MAPS_H
#define GWLB_XDP_MAPS_H

#include "net_hdrs.h"
#include "bpf_helpers_min.h"
#include "geneve_defs.h"

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); /* Resized during setup */
	__type(key, struct flow_key_v4);
	__type(value, struct outer_hdr_cache);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, 0); /* shared by encap and decap */
} flow_state_v4 SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); /* resized during setup cmd */
	__type(key, struct flow_key_v6);
	__type(value, struct outer_hdr_cache);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, 0); /* shared by encap and decap */
} flow_state_v6 SEC(".maps");

enum metric {
	DECAP_CNT_PASS_NOT_GENEVE = 0,
	DECAP_CNT_DROP_MALFORMED,
	DECAP_CNT_DROP_UNKNOWN_ENI,
	DECAP_CNT_DROP_HDR_TOO_LONG,
	DECAP_CNT_DROP_FAMILY_DISABLED,
	DECAP_CNT_OK,
	ENCAP_CNT_DROP_MALFORMED,
	ENCAP_CNT_DROP_FLOW_MISS,
	ENCAP_CNT_DROP_FAMILY_DISABLED,
	ENCAP_CNT_OK,
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

static __always_inline void increment_metric(__u32 ifindex, __u32 idx)
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
		__sync_fetch_and_add(cnt, 1);
}

#endif /* GWLB_XDP_MAPS_H */
