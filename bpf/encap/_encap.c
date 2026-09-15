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

/* Per-address-family enable flags, mirroring _decap.c's. See maps.h. */
const volatile __u8 ipv4_enabled = 1;
const volatile __u8 ipv6_enabled = 1;

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
	 * _BYTES counter below uses this rather than re-deriving
	 * data_end - data at its own site, so every outcome — drop or ok —
	 * counts the same thing (bytes received on the veth), not whatever
	 * size the buffer happens to be after the outer header's restored. */
	__u32 frame_len = (__u32)((__u8 *)data_end - (__u8 *)data);

	__u32 ifindex = ctx->ingress_ifindex;

	bool transparent = eni_mode != 0;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}
	/* Non-IP chatter on this veth (ARP, IPv6 ND, ...) is netns-internal,
	 * not a GWLB response — let the kernel handle it. */
	bool is_v6;

	if (eth->h_proto == bpf_htons(ETH_P_IP))
		is_v6 = false;
	else if (eth->h_proto == bpf_htons(ETH_P_IPV6))
		is_v6 = true;
	else
		return XDP_PASS;

	/* Family disabled at load time — drop before touching flow_state. */
	if ((is_v6 && !ipv6_enabled) || (!is_v6 && !ipv4_enabled)) {
		increment_metric(ifindex, ENCAP_CNT_DROP_FAMILY_DISABLED_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_FAMILY_DISABLED_BYTES, frame_len);
		return XDP_DROP;
	}

	__u16 sport = 0, dport = 0;
	__u8 proto = 0;
	union flow_addr saddr, daddr;

	__builtin_memset(&saddr, 0, sizeof(saddr));
	__builtin_memset(&daddr, 0, sizeof(daddr));

	if (!is_v6) {
		struct iphdr *ip = (void *)(eth + 1);

		if ((void *)(ip + 1) > data_end) {
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
			return XDP_DROP;
		}
		if (ip->ihl < 5) {
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
			return XDP_DROP;
		}

		if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
			__u8 *l4 = (__u8 *)ip + (ip->ihl * 4);
			struct udphdr *l4hdr = (void *)l4;

			if ((void *)(l4hdr + 1) > data_end) {
				increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
				increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
				return XDP_DROP;
			}
			sport = l4hdr->source;
			dport = l4hdr->dest;
		}
		proto = ip->protocol;
		saddr.v4 = ip->saddr;
		daddr.v4 = ip->daddr;
	} else {
		struct ipv6hdr *ip6 = (void *)(eth + 1);

		if ((void *)(ip6 + 1) > data_end) {
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
			return XDP_DROP;
		}
		/* Extension headers aren't walked — see _decap.c. */
		if (ip6->nexthdr == IPPROTO_TCP || ip6->nexthdr == IPPROTO_UDP) {
			struct udphdr *l4hdr = (void *)(ip6 + 1);

			if ((void *)(l4hdr + 1) > data_end) {
				increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_PACKETS, 1);
				increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED_BYTES, frame_len);
				return XDP_DROP;
			}
			sport = l4hdr->source;
			dport = l4hdr->dest;
		}
		proto = ip6->nexthdr;
		__builtin_memcpy(saddr.v6, &ip6->saddr, 16);
		__builtin_memcpy(daddr.v6, &ip6->daddr, 16);
	}

	/* transparent: reply matches the cached tuple literally. Otherwise
	 * (NAT/SNAT) it comes back with src/dst (and port) swapped from what
	 * decap cached. saddr/daddr being family-agnostic by this point (see
	 * union flow_addr) means this swap, unlike the parsing above, doesn't
	 * need its own v4/v6 copy — one shared builder call either way. */
	struct flow_key key;
	if (transparent)
		build_flow_key(&key, ifindex, is_v6, saddr, daddr, sport, dport, proto);
	else
		build_flow_key(&key, ifindex, is_v6, daddr, saddr, dport, sport, proto);

	struct outer_hdr_cache *cache_p = bpf_map_lookup_elem(&flow_state, &key);

	if (!cache_p) {
		/* Response for a flow this box never decapped. */
		increment_metric(ifindex, ENCAP_CNT_DROP_FLOW_MISS_PACKETS, 1);
		increment_metric(ifindex, ENCAP_CNT_DROP_FLOW_MISS_BYTES, frame_len);
		return XDP_DROP;
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
	 * swapped both the Ethernet dst/src and the IP saddr/daddr before
	 * ever caching this header (see _decap.c), so the store above already
	 * left them correct for the reply. Only the fields that depend on
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
	 */
	increment_metric(ifindex, ENCAP_CNT_OK_PACKETS, 1);
	increment_metric(ifindex, ENCAP_CNT_OK_BYTES, frame_len);
	return bpf_redirect(uplink_ifindex, 0);
}
