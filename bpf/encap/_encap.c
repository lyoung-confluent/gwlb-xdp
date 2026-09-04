#include "net_hdrs.h"
#include "bpf_helpers_min.h"
#include <bpf/bpf_endian.h>
#include "geneve_defs.h"
#include "maps.h"

/* Smallest valid cached outer header: eth + ip + udp. */
#define MIN_OUTER_HDR_BYTES \
	(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))

/* Reject a cached outer header too short to hold eth+ip+udp, or longer than the
 * cache buffer. The upper bound is also what lets the verifier accept cache.len
 * as a length argument to the bpf_xdp_*_bytes() helpers (a __u16 map field is
 * otherwise an unbounded 0..65535 scalar). This must be re-asserted at each
 * point of use: every intervening helper call reloads cache.len from its stack
 * spill, widening the range back out. Kept as one macro so all three sites stay
 * provably identical. Expands only inside encap, so it reads the enclosing
 * `ifindex` (ctx->ingress_ifindex) for the per-ENI counter. */
#define REJECT_BAD_CACHE_LEN(c) \
	do { \
		if ((c).len < (__u16)MIN_OUTER_HDR_BYTES || \
		    (c).len > MAX_OUTER_HDR_BYTES) { \
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED); \
			return XDP_DROP; \
		} \
	} while (0)

/* This box's own hwaddr for the synthesized outer Ethernet header, set by the
 * loader before load.
 *
 * Six scalars rather than one __u8[6]: an array-typed .rodata global read back
 * as all-zero at runtime with this clang/BPF toolchain, while scalar .rodata
 * works. */
const volatile __u8 uplink_mac_0 = 0;
const volatile __u8 uplink_mac_1 = 0;
const volatile __u8 uplink_mac_2 = 0;
const volatile __u8 uplink_mac_3 = 0;
const volatile __u8 uplink_mac_4 = 0;
const volatile __u8 uplink_mac_5 = 0;

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

	__u32 ifindex = ctx->ingress_ifindex;

	bool transparent = eni_mode != 0;

	__u8 uplink_mac[6] = {
		uplink_mac_0, uplink_mac_1, uplink_mac_2, uplink_mac_3, uplink_mac_4, uplink_mac_5,
	};

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
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

	/* Family disabled at load time — drop before the shrunk flow_state
	 * lookup. */
	if ((is_v6 && !ipv6_enabled) || (!is_v6 && !ipv4_enabled)) {
		increment_metric(ifindex, ENCAP_CNT_DROP_FAMILY_DISABLED);
		return XDP_DROP;
	}

	__u16 sport = 0, dport = 0;
	__u8 proto = 0;
	struct outer_hdr_cache *cache_p = NULL;

	if (!is_v6) {
		struct iphdr *ip = (void *)(eth + 1);

		if ((void *)(ip + 1) > data_end) {
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
			return XDP_DROP;
		}
		if (ip->ihl < 5) {
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
			return XDP_DROP;
		}

		if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
			__u8 *l4 = (__u8 *)ip + (ip->ihl * 4);
			struct udphdr *l4hdr = (void *)l4;

			if ((void *)(l4hdr + 1) > data_end) {
				increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
				return XDP_DROP;
			}
			sport = l4hdr->source;
			dport = l4hdr->dest;
		}
		proto = ip->protocol;

		/* transparent: reply matches the cached tuple literally.
		 * Otherwise (NAT/SNAT) it comes back with src/dst swapped. The
		 * shared builder guarantees the key (padding included) is formed
		 * exactly as decap formed it. */
		struct flow_key_v4 key;
		if (transparent)
			build_flow_key_v4(&key, ifindex, ip->saddr, ip->daddr,
					  sport, dport, proto);
		else
			build_flow_key_v4(&key, ifindex, ip->daddr, ip->saddr,
					  dport, sport, proto);

		cache_p = bpf_map_lookup_elem(&flow_state_v4, &key);
	} else {
		struct ipv6hdr *ip6 = (void *)(eth + 1);

		if ((void *)(ip6 + 1) > data_end) {
			increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
			return XDP_DROP;
		}
		/* Extension headers aren't walked — see _decap.c. */
		if (ip6->nexthdr == IPPROTO_TCP || ip6->nexthdr == IPPROTO_UDP) {
			struct udphdr *l4hdr = (void *)(ip6 + 1);

			if ((void *)(l4hdr + 1) > data_end) {
				increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
				return XDP_DROP;
			}
			sport = l4hdr->source;
			dport = l4hdr->dest;
		}
		proto = ip6->nexthdr;

		/* transparent picks literal vs. swapped — see the v4 path. */
		struct flow_key_v6 key6;
		if (transparent)
			build_flow_key_v6(&key6, ifindex, &ip6->saddr, &ip6->daddr,
					  sport, dport, proto);
		else
			build_flow_key_v6(&key6, ifindex, &ip6->daddr, &ip6->saddr,
					  dport, sport, proto);

		cache_p = bpf_map_lookup_elem(&flow_state_v6, &key6);
	}

	if (!cache_p) {
		/* Response for a flow this box never decapped. */
		increment_metric(ifindex, ENCAP_CNT_DROP_FLOW_MISS);
		return XDP_DROP;
	}
	struct outer_hdr_cache cache = *cache_p; /* copy out before adjust_head */

	REJECT_BAD_CACHE_LEN(cache);

	/* Drop the veth's L2 framing, reopen room for the cached outer header. */
	int delta = (int)sizeof(struct ethhdr) - (int)cache.len;
	if (bpf_xdp_adjust_head(ctx, delta)) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
		return XDP_DROP;
	}

	/* Re-check: adjust_head reloaded cache.len from a spill, losing the
	 * narrowed range (see the macro). */
	REJECT_BAD_CACHE_LEN(cache);

	if (bpf_xdp_store_bytes(ctx, 0, cache.hdr, cache.len)) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
		return XDP_DROP;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	struct ethhdr *new_eth = data;
	if ((void *)(new_eth + 1) > data_end) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
		return XDP_DROP;
	}
	struct iphdr *new_ip = (void *)(new_eth + 1);
	if ((void *)(new_ip + 1) > data_end) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
		return XDP_DROP;
	}
	struct udphdr *new_udp = (void *)(new_ip + 1);
	if ((void *)(new_udp + 1) > data_end) {
		increment_metric(ifindex, ENCAP_CNT_DROP_MALFORMED);
		return XDP_DROP;
	}

	/* Reply's dst MAC is the cached frame's src MAC (the delivering peer):
	 * set dst from src first, then overwrite src with this box's address. */
	__builtin_memcpy(new_eth->h_dest, new_eth->h_source, 6);
	__builtin_memcpy(new_eth->h_source, uplink_mac, 6);
	new_eth->h_proto = bpf_htons(ETH_P_IP);

	/* decap saw src=GWLBE dst=appliance; the reply needs the reverse. */
	__be32 old_src = new_ip->saddr, old_dst = new_ip->daddr;
	new_ip->saddr = old_dst;
	new_ip->daddr = old_src;

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
	increment_metric(ifindex, ENCAP_CNT_OK);
	return bpf_redirect(uplink_ifindex, 0);
}
