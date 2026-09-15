#include "net_hdrs.h"
#include "bpf_helpers_min.h"
#include <bpf/bpf_endian.h>
#include "geneve_defs.h"
#include "maps.h"

/*
 * Value type for eni_to_ifindex: the veth-outer ifindex plus the L2 addressing
 * decap synthesizes into the Ethernet header (GWLB encapsulates at L3, so
 * there's no inner L2 header to preserve). All three are decap-only and looked
 * up together, so they're folded into one value for one hash lookup.
 *
 * ifindex also scopes flow_state entries to this ENI (see struct flow_key).
 */
struct eni_info {
	__u32	ifindex;	/* veth-outer ifindex */
	__u8	dst[6];		/* veth-outer's peer (inner) hwaddr; must match so
				   the tenant netns accepts the frame (PACKET_HOST) */
	__u8	src[6];		/* veth-outer's own hwaddr */
};

/*
 * ENI ID -> veth-outer ifindex + inner mac pair, looked up by decap on every
 * packet. Plain bpf_redirect(ifindex, 0) gets the same bulk-queue batching as
 * bpf_redirect_map() since Linux 5.13, so no devmap is needed. max_entries is
 * a placeholder — the loader overrides it with --max-enis before loading.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);	/* ENI ID */
	__type(value, struct eni_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, 0);
} eni_to_ifindex SEC(".maps");

/*
 * Validates one GWLB GENEVE option at *pos — class/type/length must match
 * exactly, not just fit a bound — and advances *pos past it (header +
 * data) on success. Returns a pointer to its data, or NULL if it doesn't
 * match (including running past data_end), in which case *pos is left
 * unmodified and the caller drops the packet as malformed.
 *
 * decap calls this exactly three times, once per option, in the fixed
 * order GWLB always sends (see geneve_defs.h) — this isn't a generic
 * options walk, just shared bounds/field-matching logic for three
 * straight-line call sites.
 */
static __always_inline void *parse_gwlb_opt(__u8 **pos, void *data_end,
					     __u8 type, __u32 want_len)
{
	struct geneve_opt_hdr *opt = (void *)*pos;

	if ((void *)(opt + 1) > data_end)
		return NULL;
	if (opt->opt_class != bpf_htons(GENEVE_OPT_CLASS_AWS) ||
	    opt->type != type || opt->length * 4 != want_len)
		return NULL;

	__u8 *data = (__u8 *)(opt + 1);
	if ((void *)(data + want_len) > data_end)
		return NULL;

	*pos = data + want_len;
	return data;
}

/* Per-address-family enable flags, set by the loader before load (default:
 * both enabled). A disabled family's inner packets are dropped before ever
 * touching flow_state (shared by both families — see maps.h — so there's
 * no per-family map to shrink the way there once was).
 * const volatile so the verifier treats them as constant once .rodata is
 * frozen, without constant-folding the pre-load default. */
const volatile __u8 ipv4_enabled = 1;
const volatile __u8 ipv6_enabled = 1;

/* build_flow_key lives in geneve_defs.h, shared with encap. */

SEC("xdp")
int decap(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	/* Captured once, from the frame as it arrived: every _BYTES counter
	 * below uses this rather than re-deriving data_end - data at its own
	 * site, so every outcome — drop, pass, or ok — counts the same thing
	 * (bytes received on the uplink), not whatever size the buffer
	 * happens to be after bpf_xdp_adjust_head has run. */
	__u32 frame_len = (__u32)((__u8 *)data_end - (__u8 *)data);

	/* The uplink decap is attached to. Counts pre-ENI events (not-GENEVE,
	 * malformed, unknown-ENI) against the interface they arrived on, rather
	 * than a synthetic 0; post-ENI events use the tenant's veth ifindex. */
	__u32 ingress_ifindex = ctx->ingress_ifindex;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	/* GWLB never sends outer IP options. */
	if (ip->ihl != 5 || ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	struct udphdr *udp = (void *)((__u8 *)ip + (ip->ihl * 4));
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (udp->dest != bpf_htons(GENEVE_PORT)) {
		increment_metric(ingress_ifindex, DECAP_CNT_PASS_NOT_GENEVE_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_PASS_NOT_GENEVE_BYTES, frame_len);
		return XDP_PASS;
	}

	struct gwlb_genevehdr *gnv = (void *)(udp + 1);
	if ((void *)(gnv + 1) > data_end) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}
	if (gnv->ver != 0) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}
	/* GWLB's own tunnel VNI, distinct from the AWS ENI ID carried as a
	 * GENEVE option below. GWLB never sets it, so anything else means
	 * this box is being sent traffic it shouldn't be. */
	if (gnv->vni[0] != 0 || gnv->vni[1] != 0 || gnv->vni[2] != 0) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	/* GWLB always sends exactly GWLB_OPTS_LEN bytes of options — the three
	 * parsed below, fixed order and fixed length, no more and no less. */
	__u32 opt_len = gnv->opt_len * 4;
	if (opt_len != GWLB_OPTS_LEN) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	__u8 *opt_start = (__u8 *)(gnv + 1);
	__u8 *opt_end = opt_start + opt_len;
	if ((void *)opt_end > data_end) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	/* Option 1: ENI ID — which VPC endpoint this packet belongs to. */
	__u8 *pos = opt_start;
	void *opt_data = parse_gwlb_opt(&pos, data_end, GWLB_OPT_TYPE_ENI, GWLB_OPT_ENI_LEN);
	if (!opt_data) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}
	__u64 eni_id = bpf_be64_to_cpu(*(__be64 *)opt_data);

	/* Option 2: Attachment ID. GWLB only ever attaches this box as a
	 * single appliance, so anything but 0 means either a multi-appliance
	 * deployment this box doesn't support, or a packet not meant for it. */
	opt_data = parse_gwlb_opt(&pos, data_end, GWLB_OPT_TYPE_ATTACHMENT, GWLB_OPT_ATTACHMENT_LEN);
	if (!opt_data) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}
	if (bpf_be64_to_cpu(*(__be64 *)opt_data) != 0) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	/* Option 3: flow cookie. Parsed but not consumed yet — will matter
	 * once cookie validation is added. */
	opt_data = parse_gwlb_opt(&pos, data_end, GWLB_OPT_TYPE_COOKIE, GWLB_OPT_COOKIE_LEN);
	if (!opt_data) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}
	__u32 flow_cookie = bpf_ntohl(*(__be32 *)opt_data);
	(void)flow_cookie;

	struct eni_info *info = bpf_map_lookup_elem(&eni_to_ifindex, &eni_id);
	if (!info) {
		/* ENI not provisioned by the loader, or GWLB misdirected. */
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_UNKNOWN_ENI_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_UNKNOWN_ENI_BYTES, frame_len);
		return XDP_DROP;
	}
	__u32 ifindex = info->ifindex;

	/* GWLB encapsulates at L3: proto_type is the inner packet's ethertype
	 * and there is no inner Ethernet header. Only IPv4/IPv6 inner packets
	 * are supported. */
	__be16 inner_proto_be = gnv->proto_type;
	__u16 inner_ethertype = bpf_ntohs(inner_proto_be);
	bool inner_is_v6;

	if (inner_ethertype == ETH_P_IP)
		inner_is_v6 = false;
	else if (inner_ethertype == ETH_P_IPV6)
		inner_is_v6 = true;
	else {
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	/* Family disabled at load time — drop before touching flow_state. */
	if ((inner_is_v6 && !ipv6_enabled) || (!inner_is_v6 && !ipv4_enabled)) {
		increment_metric(ifindex, DECAP_CNT_DROP_FAMILY_DISABLED_PACKETS, 1);
		increment_metric(ifindex, DECAP_CNT_DROP_FAMILY_DISABLED_BYTES, frame_len);
		return XDP_DROP;
	}

	__u16 inner_sport = 0, inner_dport = 0;
	union flow_addr saddr, daddr;
	__u8 inner_proto = 0;

	__builtin_memset(&saddr, 0, sizeof(saddr));
	__builtin_memset(&daddr, 0, sizeof(daddr));

	if (!inner_is_v6) {
		struct iphdr *inner_ip = (void *)opt_end;

		if ((void *)(inner_ip + 1) > data_end) {
			increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
			increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
			return XDP_DROP;
		}
		if (inner_ip->ihl < 5) {
			increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
			increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
			return XDP_DROP;
		}

		if (inner_ip->protocol == IPPROTO_TCP || inner_ip->protocol == IPPROTO_UDP) {
			/* sport/dport are the first two u16s of both TCP and
			 * UDP, so a udphdr-shaped read serves either. */
			__u8 *l4 = (__u8 *)inner_ip + (inner_ip->ihl * 4);
			struct udphdr *l4hdr = (void *)l4;

			if ((void *)(l4hdr + 1) > data_end) {
				increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
				increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
				return XDP_DROP;
			}
			inner_sport = l4hdr->source;
			inner_dport = l4hdr->dest;
		}
		/* ICMP and others: ports left 0, flow keyed on addrs+proto. */
		saddr.v4 = inner_ip->saddr;
		daddr.v4 = inner_ip->daddr;
		inner_proto = inner_ip->protocol;
	} else {
		struct ipv6hdr *inner_ip6 = (void *)opt_end;

		if ((void *)(inner_ip6 + 1) > data_end) {
			increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
			increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
			return XDP_DROP;
		}
		/* Extension headers aren't walked: for GWLB traffic L4 sits
		 * immediately after the 40-byte base header. */
		if (inner_ip6->nexthdr == IPPROTO_TCP || inner_ip6->nexthdr == IPPROTO_UDP) {
			struct udphdr *l4hdr = (void *)(inner_ip6 + 1);

			if ((void *)(l4hdr + 1) > data_end) {
				increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
				increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
				return XDP_DROP;
			}
			inner_sport = l4hdr->source;
			inner_dport = l4hdr->dest;
		}
		__builtin_memcpy(saddr.v6, &inner_ip6->saddr, 16);
		__builtin_memcpy(daddr.v6, &inner_ip6->daddr, 16);
		inner_proto = inner_ip6->nexthdr;
	}

	/* Cache under a single key: the tuple exactly as forwarded to the
	 * appliance. The reply can come back in either orientation, but
	 * encap doesn't guess — its eni_mode .rodata flag (bpf/encap/_encap.c)
	 * fixes this box's orientation at load time, so it looks up exactly
	 * one. */
	struct flow_key fwd_key;
	build_flow_key(&fwd_key, ifindex, inner_is_v6, saddr, daddr,
		       inner_sport, inner_dport, inner_proto);

	/* eth+ip+udp+geneve+opts is now OUTER_HDR_LEN exactly — opt_len was
	 * just verified to be GWLB_OPTS_LEN, not merely bounded by it — so the
	 * whole outer header is cached verbatim in one load, Ethernet header
	 * included (see the comment on struct outer_hdr_cache). */
	struct outer_hdr_cache cache;
	__builtin_memset(&cache, 0, sizeof(cache));
	if (bpf_xdp_load_bytes(ctx, 0, cache.hdr, OUTER_HDR_LEN)) {
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	/* Pre-swap the addressing that the eventual reply will need reversed,
	 * so encap can replay this cache onto the wire completely unmodified.
	 * Doing it here rather than in encap means it runs once per request
	 * instead of once per reply — a real saving whenever a flow's traffic
	 * is asymmetric (e.g. a bulk download's data packets outnumber its
	 * acks), and never a loss otherwise. */
	struct ethhdr *cache_eth = (struct ethhdr *)cache.hdr;

	__u8 dst_mac[6], src_mac[6];
	__builtin_memcpy(dst_mac, cache_eth->h_dest, 6);
	__builtin_memcpy(src_mac, cache_eth->h_source, 6);
	__builtin_memcpy(cache_eth->h_dest, src_mac, 6);
	__builtin_memcpy(cache_eth->h_source, dst_mac, 6);

	/* saddr/daddr sit at a 2-byte-shy-of-4-aligned offset within cache.hdr
	 * (14-byte Ethernet header, then a 20-byte IP header) — kept in plain
	 * __u8* + memcpy terms, like the MAC swap above, rather than a typed
	 * struct iphdr* scalar access: the verifier accepts unaligned access
	 * through a packet pointer (as _encap.c's new_ip used to rely on) but
	 * rejects it for a stack buffer like this one. */
	__u8 *ip_saddr = cache.hdr + sizeof(struct ethhdr) + __builtin_offsetof(struct iphdr, saddr);
	__u8 *ip_daddr = cache.hdr + sizeof(struct ethhdr) + __builtin_offsetof(struct iphdr, daddr);

	__u8 saddr_bytes[4], daddr_bytes[4];
	__builtin_memcpy(saddr_bytes, ip_saddr, 4);
	__builtin_memcpy(daddr_bytes, ip_daddr, 4);
	__builtin_memcpy(ip_saddr, daddr_bytes, 4);
	__builtin_memcpy(ip_daddr, saddr_bytes, 4);

	bpf_map_update_elem(&flow_state, &fwd_key, &cache, BPF_ANY);

	/* Strip everything through the GENEVE options, then reopen room for a
	 * synthesized L2 header, leaving [new eth hdr][inner IP packet]. */
	if (bpf_xdp_adjust_head(ctx, (int)(OUTER_HDR_LEN - sizeof(struct ethhdr)))) {
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	struct ethhdr *new_eth = data;
	if ((void *)(new_eth + 1) > data_end) {
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}
	__builtin_memcpy(new_eth->h_dest, info->dst, 6);
	__builtin_memcpy(new_eth->h_source, info->src, 6);
	new_eth->h_proto = inner_proto_be;

	increment_metric(ifindex, DECAP_CNT_OK_PACKETS, 1);
	increment_metric(ifindex, DECAP_CNT_OK_BYTES, frame_len);
	return bpf_redirect(ifindex, 0);
}
