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
 * ifindex also scopes flow_state entries to this ENI (see struct flow_key_v4).
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

/* Trip count for the option-parsing loop: MAX_GENEVE_OPT_BYTES worth of
 * options, 4 bytes (smallest opt header) at a time. Must be a compile-time
 * constant so the loop can be fully unrolled. */
#define GENEVE_OPT_MAX_ITER	(MAX_GENEVE_OPT_BYTES / 4)

/* Per-address-family enable flags, set by the loader before load (default:
 * both enabled). A disabled family's flow_state map is shrunk to one entry;
 * inner packets of that family are dropped before any flow_state access.
 * const volatile so the verifier treats them as constant once .rodata is
 * frozen, without constant-folding the pre-load default. */
const volatile __u8 ipv4_enabled = 1;
const volatile __u8 ipv6_enabled = 1;

/* build_flow_key_v4/v6 live in geneve_defs.h, shared with encap. */

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

	__u32 opt_len = gnv->opt_len * 4;
	if (opt_len > MAX_GENEVE_OPT_BYTES) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_HDR_TOO_LONG_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_HDR_TOO_LONG_BYTES, frame_len);
		return XDP_DROP;
	}

	__u8 *opt_start = (__u8 *)(gnv + 1);
	__u8 *opt_end = opt_start + opt_len;
	if ((void *)opt_end > data_end) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	__u64 eni_id = 0, attachment_id = 0;
	__u32 flow_cookie = 0;
	bool have_eni = false;
	bool malformed = false;

	/* The body has no break/continue/return: clang's unroller won't unroll
	 * a bpf-target loop containing an early exit, and left un-unrolled the
	 * verifier blows its instruction budget on the back-edge. Every
	 * iteration runs unconditionally, guarded by `pos < opt_end`. */
	__u8 *pos = opt_start;
#pragma clang loop unroll(full)
	for (int i = 0; i < GENEVE_OPT_MAX_ITER; i++) {
		if (pos < opt_end && !malformed) {
			struct geneve_opt_hdr *opt = (void *)pos;
			if ((void *)(opt + 1) > data_end) {
				malformed = true;
			} else {
				__u32 this_opt_len = opt->length * 4;
				__u8 *opt_data = pos + sizeof(*opt);

				if (opt->opt_class == bpf_htons(GENEVE_OPT_CLASS_AWS)) {
					if (opt->type == GWLB_OPT_TYPE_ENI &&
					    this_opt_len == GWLB_OPT_ENI_LEN) {
						if ((void *)(opt_data + GWLB_OPT_ENI_LEN) > data_end) {
							malformed = true;
						} else {
							eni_id = bpf_be64_to_cpu(*(__be64 *)opt_data);
							have_eni = true;
						}
					} else if (opt->type == GWLB_OPT_TYPE_ATTACHMENT &&
						   this_opt_len == GWLB_OPT_ATTACHMENT_LEN) {
						if ((void *)(opt_data + GWLB_OPT_ATTACHMENT_LEN) > data_end) {
							malformed = true;
						} else {
							attachment_id = bpf_be64_to_cpu(*(__be64 *)opt_data);
						}
					} else if (opt->type == GWLB_OPT_TYPE_COOKIE &&
						   this_opt_len == GWLB_OPT_COOKIE_LEN) {
						if ((void *)(opt_data + GWLB_OPT_COOKIE_LEN) > data_end) {
							malformed = true;
						} else {
							flow_cookie = bpf_ntohl(*(__be32 *)opt_data);
						}
					}
				}

				if (!malformed)
					pos += sizeof(*opt) + this_opt_len;
			}
		}
	}
	/* Parsed but not consumed yet — will matter once dispatch keys on more
	 * than the ENI ID, or once cookie validation is added. */
	(void)attachment_id;
	(void)flow_cookie;

	if (malformed || !have_eni) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

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

	/* Family disabled at load time — drop before touching its shrunk
	 * flow_state map. */
	if ((inner_is_v6 && !ipv6_enabled) || (!inner_is_v6 && !ipv4_enabled)) {
		increment_metric(ifindex, DECAP_CNT_DROP_FAMILY_DISABLED_PACKETS, 1);
		increment_metric(ifindex, DECAP_CNT_DROP_FAMILY_DISABLED_BYTES, frame_len);
		return XDP_DROP;
	}

	__u16 inner_sport = 0, inner_dport = 0;
	__u32 v4_saddr = 0, v4_daddr = 0;
	struct in6_addr v6_saddr, v6_daddr;
	__u8 inner_proto = 0;

	__builtin_memset(&v6_saddr, 0, sizeof(v6_saddr));
	__builtin_memset(&v6_daddr, 0, sizeof(v6_daddr));

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
		v4_saddr = inner_ip->saddr;
		v4_daddr = inner_ip->daddr;
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
		v6_saddr = inner_ip6->saddr;
		v6_daddr = inner_ip6->daddr;
		inner_proto = inner_ip6->nexthdr;
	}

	/* Cache under a single key: the tuple exactly as forwarded to the
	 * appliance. The reply can come back in either orientation, but
	 * encap doesn't guess — its eni_mode .rodata flag (bpf/encap/_encap.c)
	 * fixes this box's orientation at load time, so it looks up exactly
	 * one. */
	struct flow_key_v4 fwd_key4;
	struct flow_key_v6 fwd_key6;

	if (!inner_is_v6)
		build_flow_key_v4(&fwd_key4, ifindex, v4_saddr, v4_daddr,
				inner_sport, inner_dport, inner_proto);
	else
		build_flow_key_v6(&fwd_key6, ifindex, &v6_saddr, &v6_daddr,
				   inner_sport, inner_dport, inner_proto);

	/* Computed from fixed sizes plus opt_len rather than (opt_end - eth):
	 * the pointer subtraction leaves the verifier unable to prove the
	 * result non-negative after stack spills, whereas opt_len is already a
	 * tightly-bounded scalar. */
	__u32 outer_len = (__u32)sizeof(struct ethhdr) + sizeof(struct iphdr) +
			  sizeof(struct udphdr) + sizeof(struct gwlb_genevehdr) +
			  opt_len;
	if (outer_len > MAX_OUTER_HDR_BYTES) {
		/* Unreachable given the opt_len cap, but the verifier needs it. */
		increment_metric(ifindex, DECAP_CNT_DROP_HDR_TOO_LONG_PACKETS, 1);
		increment_metric(ifindex, DECAP_CNT_DROP_HDR_TOO_LONG_BYTES, frame_len);
		return XDP_DROP;
	}

	struct outer_hdr_cache cache;
	__builtin_memset(&cache, 0, sizeof(cache));
	cache.len = (__u16)outer_len;
	if (bpf_xdp_load_bytes(ctx, 0, cache.hdr, outer_len)) {
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	if (!inner_is_v6)
		bpf_map_update_elem(&flow_state_v4, &fwd_key4, &cache, BPF_ANY);
	else
		bpf_map_update_elem(&flow_state_v6, &fwd_key6, &cache, BPF_ANY);

	/* Strip everything through the GENEVE options, then reopen room for a
	 * synthesized L2 header, leaving [new eth hdr][inner IP packet]. */
	if (bpf_xdp_adjust_head(ctx, (int)(outer_len - sizeof(struct ethhdr)))) {
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
