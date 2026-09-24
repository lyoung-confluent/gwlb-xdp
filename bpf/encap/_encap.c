#include "net_hdrs.h"
#include "bpf_helpers_min.h"
#include <bpf/bpf_endian.h>
#include "geneve_defs.h"
#include "maps.h"

/* The reply's redirect target, fixed for the life of the program, so it lives
 * in .rodata rather than a devmap: plain bpf_redirect(ifindex, 0) gets the
 * same bulk-queue batching as bpf_redirect_map() since Linux 5.13.
 *
 * A redirect (not XDP_PASS) is required: the reply's source must be uplink's
 * own address for GWLB to route it back, and the kernel refuses to forward a
 * locally-sourced packet out a non-loopback interface via XDP_PASS.
 */
const volatile __u32 uplink_ifindex = 0;

/*
 * Reply orientation, set once by `setup` for the life of the program (see
 * setEniMode in cmd/setup.go): 0 (default) means every ENI on this box is
 * NAT/terminating, so replies come back with src/dst swapped and encap
 * looks up the swapped tuple; 1 means every ENI is a transparent appliance
 * that returns each packet with the same 5-tuple it received, so encap
 * looks up the literal tuple. Box-wide rather than per-ENI: this lets it live
 * in .rodata (a single scalar, fixed at load time) instead of a per-ifindex
 * map lookup on every packet.
 */
const volatile __u8 eni_mode = 0;

/*
 * The largest reply (IP header onward) encap will encapsulate, set once by
 * `setup` to the uplink's MTU - GENEVE_OVERHEAD (see encap.Load). Anything
 * larger couldn't leave the uplink once encapsulated — the redirect would
 * fail silently past this program, so it's dropped and counted here
 * instead. Sizing replies to what GWLB itself will pass back (its
 * documented 8500) is the netns's job, via its route MTU: GWLB fragments a
 * larger reply itself if it can, so encap has no business being stricter
 * than the uplink.
 */
const volatile __u32 max_inner_len = DEFAULT_MAX_INNER_LEN;

/*
 * Fragment tracking for replies: only a datagram's first fragment carries
 * the L4 header its flow_key needs, so when encap matches a first fragment
 * to its flow it records that flow's cached outer header here, keyed by the
 * fragment's own (as-observed) addresses, protocol and identification — see
 * frag_key. The later fragments look that up instead of flow_state. LRU and
 * fixed-size: an entry only needs to outlive one datagram's fragments.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct flow_key);
	__type(value, struct outer_hdr_cache);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, 0);
} frag_state SEC(".maps");

/* frag_state's key for the datagram t is a fragment of: struct flow_key's
 * shape, with the fragment identification split across sport/dport. */
static __always_inline void frag_key(struct flow_key *key, __u32 ifindex, bool is_v6,
				     const struct inner_tuple *t)
{
	build_flow_key(key, ifindex, is_v6, t->saddr, t->daddr,
		       (__u16)(t->frag_id >> 16), (__u16)t->frag_id, t->proto);
}

static __always_inline __u16 csum_fold(__u32 csum)
{
#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return (__u16)~csum;
}

/* ihl is always 5 for cached outer headers — decap rejects outer IP
 * options before caching. */
static __always_inline __u16 ipv4_checksum(struct iphdr *ip)
{
	ip->check = 0;
	__u32 csum = 0;
	__u16 *words = (__u16 *)ip;

#pragma unroll
	for (int i = 0; i < (int)(sizeof(*ip) / 2); i++)
		csum += words[i];

	return csum_fold(csum);
}

SEC("xdp")
int encap(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	/* Captured once, from the frame as it arrived on this veth: every
	 * _BYTES counter below is based on this rather than re-deriving
	 * data_end - data at its own site, so no outcome's count depends on
	 * whatever size the buffer happens to be after the outer header's
	 * restored. */
	__u32 frame_len = (__u32)((__u8 *)data_end - (__u8 *)data);

	__u32 ifindex = ctx->ingress_ifindex;

	bool transparent = eni_mode != 0;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}
	/* Non-IP chatter on this veth (ARP, ...) is netns-internal, not a GWLB
	 * response — let the kernel handle it. IPv6's own equivalents (ND,
	 * MLD) are recognized and passed below, once parsed. */
	bool is_v6;

	if (eth->h_proto == bpf_htons(ETH_P_IP))
		is_v6 = false;
	else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
		is_v6 = true;
	else
		return XDP_PASS;

	struct inner_tuple t;
	void *l4;
	int err = is_v6 ? parse_ipv6((void *)(eth + 1), data_end, &t, &l4)
			: parse_ipv4((void *)(eth + 1), data_end, &t, &l4);
	if (err) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	/* Neighbor Discovery and MLD between the netns and this veth (the
	 * netns resolving its next hop, DAD, multicast listener reports) —
	 * never a reply to a decapsulated flow, so there's nothing to look up. */
	if (is_v6 && icmpv6_is_link_local_control(&t))
		return XDP_PASS;

	/* Too large to leave the uplink once encapsulated (see max_inner_len).
	 * The veth's own MTU (the same value, see `add`) normally keeps replies
	 * within this; anything larger means an unsegmented GSO packet got
	 * through, or the uplink's MTU has shrunk since `setup`. */
	if (frame_len - sizeof(struct ethhdr) > max_inner_len) {
		increment_metric(ifindex, ENCAP_CNT_DROP_OVERSIZE_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_OVERSIZE_BYTES, frame_len);
		return XDP_DROP;
	}

	struct flow_key key;
	struct outer_hdr_cache *cache_p;

	if (icmp_is_quoting_error(is_v6, &t)) {
		/* An ICMP/ICMPv6 error the netns generated about one of its
		 * flows (port unreachable, time exceeded, packet too big, ...)
		 * can't be matched by its own tuple: that's the netns talking to
		 * whichever end sent the offending packet, with no port-like id
		 * to key on. But it quotes the offending packet right after its
		 * own 8-byte header — a packet decap delivered, so its tuple, as
		 * quoted, is exactly the forward key decap cached the flow under
		 * (in either eni_mode). Matching that entry sends the error back
		 * with its flow's own GENEVE options, flow cookie included. */
		struct inner_tuple q;
		void *ql4;
		void *quoted = (__u8 *)l4 + sizeof(struct icmphdr);

		err = is_v6 ? parse_ipv6(quoted, data_end, &q, &ql4)
			    : parse_ipv4(quoted, data_end, &q, &ql4);
		if (err) {
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
			return XDP_DROP;
		}
		build_flow_key(&key, ifindex, is_v6, q.saddr, q.daddr, q.sport, q.dport, q.proto);
		cache_p = bpf_map_lookup_elem(&flow_state, &key);
	} else if (t.frag == FRAG_LATER) {
		/* No L4 header to key on: match the datagram's first fragment,
		 * which recorded its flow in frag_state (below). */
		frag_key(&key, ifindex, is_v6, &t);
		cache_p = bpf_map_lookup_elem(&frag_state, &key);
	} else {
		/* transparent: reply matches the cached tuple literally.
		 * Otherwise (NAT/SNAT) it comes back with src/dst (and port)
		 * swapped from what decap cached. */
		if (transparent)
			build_flow_key(&key, ifindex, is_v6, t.saddr, t.daddr, t.sport, t.dport, t.proto);
		else
			build_flow_key(&key, ifindex, is_v6, t.daddr, t.saddr, t.dport, t.sport, t.proto);
		cache_p = bpf_map_lookup_elem(&flow_state, &key);
	}

	if (!cache_p) {
		/* Response for a flow this box never decapped (or, for a later
		 * fragment, one whose first fragment never matched). */
		increment_metric(ifindex, ENCAP_CNT_DROP_FLOW_MISS_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_FLOW_MISS_BYTES, frame_len);
		return XDP_DROP;
	}

	/* A first fragment just matched its flow: record it for the rest of
	 * the datagram's fragments to find (see frag_state). */
	if (t.frag == FRAG_FIRST) {
		struct flow_key fkey;

		frag_key(&fkey, ifindex, is_v6, &t);
		bpf_map_update_elem(&frag_state, &fkey, cache_p, BPF_ANY);
	}

	struct outer_hdr_cache cache = *cache_p; /* copy out before adjust_head */

	/* Drop the veth's 14-byte L2 framing, reopen room for the cached
	 * eth+ip+udp+geneve+opts header (OUTER_HDR_LEN, now an exact size —
	 * see geneve_defs.h — not something to re-check per use the way a
	 * variable cached length would need). */
	int delta = (int)sizeof(struct ethhdr) - (int)OUTER_HDR_LEN;
	if (bpf_xdp_adjust_head(ctx, delta)) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	if (bpf_xdp_store_bytes(ctx, 0, cache.hdr, OUTER_HDR_LEN)) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	struct ethhdr *new_eth = data;
	if ((void *)(new_eth + 1) > data_end) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}
	struct iphdr *new_ip = (void *)(new_eth + 1);
	if ((void *)(new_ip + 1) > data_end) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}
	struct udphdr *new_udp = (void *)(new_ip + 1);
	if ((void *)(new_udp + 1) > data_end) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	/* Nothing to fix up in new_eth/new_ip's addressing: decap already
	 * swapped both the Ethernet dst/src and the IP saddr/daddr, and set
	 * the reply's own TTL, ECN, DF and ID, before ever caching this header
	 * (see _decap.c), so the store above already left them correct for
	 * the reply. Only the fields that depend on
	 * this specific reply's own size — computed below — still need
	 * touching after the replay. */
	__u16 total_len = (__u16)((__u8 *)data_end - (__u8 *)data - sizeof(struct ethhdr));
	new_ip->tot_len = bpf_htons(total_len);
	new_ip->check = 0;
	new_ip->check = ipv4_checksum(new_ip);

	new_udp->len = bpf_htons(total_len - sizeof(struct iphdr));
	/* Outer UDP checksum zeroed: RFC 8926 makes it optional for IPv4, and
	 * AWS's gwlbtun reference never computes one when building replies. */
	new_udp->check = 0;

	/*
	 * The inner L4 checksum is already in the packet bytes, so it's replayed
	 * verbatim: TX checksum offload is disabled on the netns veth (see `add`),
	 * so the netns egress path writes the real checksum before it reaches
	 * encap — this redirect transmit never hits transmit-time offload.
	 *
	 * _BYTES counts what leaves the uplink — the reply plus the
	 * GENEVE_OVERHEAD just added — matching decap_ok_bytes, which counts the
	 * full encapsulated frame too.
	 */
	increment_metric(ifindex, ENCAP_CNT_OK_PACKETS, 1);
	increment_metric(ifindex, ENCAP_CNT_OK_BYTES, frame_len + GENEVE_OVERHEAD);
	return bpf_redirect(uplink_ifindex, 0);
}
