#include "net_hdrs.h"
#include "bpf_helpers_min.h"
#include <bpf/bpf_endian.h>
#include "geneve_defs.h"
#include "maps.h"

/*
 * Restricts accepted GENEVE traffic to one outer-source IPv4 CIDR, set once
 * by `setup` from --allowed-origin-cidr (see decap.Load in decap.go). Both
 * default to all-zero bytes, under which (ip->saddr & mask) == addr holds
 * for every packet (0 == 0 always) — filtering is off unless the flag is
 * passed, with no separate enable/disable knob needed.
 *
 * Stored as raw address bytes (network order, the same order ip->saddr
 * holds in memory) rather than a __u32, so setup.go never has to reason
 * about host-vs-network byte order when populating them — see
 * AllowedOriginCIDR in decap.go.
 */
const volatile __u8 allowed_origin_addr[4] = {0, 0, 0, 0};
const volatile __u8 allowed_origin_mask[4] = {0, 0, 0, 0};

/*
 * The largest inner packet (IP header onward) decap will deliver, set once
 * by `setup` to the uplink's MTU - GENEVE_OVERHEAD (see decap.Load) — the
 * most a single GENEVE packet on the uplink can carry, and each ENI veth's
 * MTU (see `add`). Deliberately not GWLB's documented 8500: GWLB doesn't
 * hold the packets it sends to that, including the fragments it creates
 * itself when splitting a larger packet, so anything the uplink can carry
 * has to be deliverable.
 */
const volatile __u32 max_inner_len = DEFAULT_MAX_INNER_LEN;

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

/* parse_ipv4/parse_ipv6 and build_flow_key live in geneve_defs.h, shared
 * with encap. */

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

	/* A non-first outer fragment carries no UDP header of its own — what
	 * sits where one would be is payload — so there's no telling here
	 * whether it's GENEVE at all. Leave it to the kernel. */
	__u16 outer_frag_off = bpf_ntohs(ip->frag_off);
	if (outer_frag_off & IP_OFFSET)
		return XDP_PASS;

	struct udphdr *udp = (void *)((__u8 *)ip + (ip->ihl * 4));
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (udp->dest != bpf_htons(GENEVE_PORT)) {
		increment_metric(ingress_ifindex, DECAP_CNT_PASS_NOT_GENEVE_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_PASS_NOT_GENEVE_BYTES, frame_len);
		return XDP_PASS;
	}

	{
		/* Read element-by-element rather than memcpy'ing straight off
		 * allowed_origin_addr/_mask: memcpy's source argument is a plain
		 * (non-volatile) pointer, so passing the volatile array itself
		 * would strip its volatile qualifier and let the compiler serve
		 * the *compiled-in* initializer instead of a genuine load of
		 * whatever `setup` actually wrote there — silently ignoring
		 * --allowed-origin-cidr. Indexing each element is a properly
		 * volatile-qualified access, forcing the real read. */
		__u8 addr_bytes[4] = {
			allowed_origin_addr[0], allowed_origin_addr[1],
			allowed_origin_addr[2], allowed_origin_addr[3],
		};
		__u8 mask_bytes[4] = {
			allowed_origin_mask[0], allowed_origin_mask[1],
			allowed_origin_mask[2], allowed_origin_mask[3],
		};
		__u32 addr, mask;

		__builtin_memcpy(&addr, addr_bytes, sizeof(addr));
		__builtin_memcpy(&mask, mask_bytes, sizeof(mask));
		if ((ip->saddr & mask) != addr) {
			increment_metric(ingress_ifindex, DECAP_CNT_DROP_ORIGIN_NOT_ALLOWED_PACKETS, 1);
			increment_metric(ingress_ifindex, DECAP_CNT_DROP_ORIGIN_NOT_ALLOWED_BYTES, frame_len);
			return XDP_DROP;
		}
	}

	/* The first fragment of a fragmented GENEVE packet: GWLB never
	 * fragments its outer packets, and decap only ever sees this one
	 * piece, so the inner packet here is truncated — and caching its
	 * outer header would replay MF onto every reply of the flow. */
	if (outer_frag_off & IP_MF) {
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ingress_ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
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

	/* Larger than any single GENEVE packet the uplink can carry: most
	 * likely several GRO merged into one before this program ran (generic
	 * XDP runs after GRO). Redirecting it would fail silently against the
	 * veth's MTU anyway, so drop it here where it can be counted. */
	if (frame_len - OUTER_HDR_LEN > max_inner_len) {
		increment_metric(ifindex, DECAP_CNT_DROP_OVERSIZE_PACKETS, 1);
		increment_metric(ifindex, DECAP_CNT_DROP_OVERSIZE_BYTES, frame_len);
		return XDP_DROP;
	}

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

	struct inner_tuple t;
	void *l4;
	int err = inner_is_v6 ? parse_ipv6((void *)opt_end, data_end, &t, &l4)
			      : parse_ipv4((void *)opt_end, data_end, &t, &l4);
	if (err) {
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
		increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
		return XDP_DROP;
	}

	/* Every well-formed inner packet is delivered, but not every one
	 * gets a flow_state entry:
	 *  - a non-first fragment carries no L4 header, so its ports (and so
	 *    its flow_key) are unknowable — the first fragment caches the
	 *    flow for all of them;
	 *  - an ICMP error never elicits a reply, and has no port-like id of
	 *    its own to key on — caching it would only collapse every such
	 *    error between two hosts onto one entry for nothing. */
	bool cache_flow = t.frag != FRAG_LATER && !icmp_is_quoting_error(inner_is_v6, &t);

	/* Cache under a single key: the tuple exactly as forwarded to the
	 * appliance. The reply can come back in either orientation, but
	 * encap doesn't guess — its eni_mode .rodata flag (bpf/encap/_encap.c)
	 * fixes this box's orientation at load time, so it looks up exactly
	 * one. */
	struct flow_key fwd_key;
	build_flow_key(&fwd_key, ifindex, inner_is_v6, t.saddr, t.daddr,
		       t.sport, t.dport, t.proto);

	/* eth+ip+udp+geneve+opts is now OUTER_HDR_LEN exactly — opt_len was
	 * just verified to be GWLB_OPTS_LEN, not merely bounded by it — so the
	 * whole outer header is cached verbatim in one load, Ethernet header
	 * included (see the comment on struct outer_hdr_cache). */
	struct outer_hdr_cache cache;
	__builtin_memset(&cache, 0, sizeof(cache));
	if (cache_flow) {
		if (bpf_xdp_load_bytes(ctx, 0, cache.hdr, OUTER_HDR_LEN)) {
			increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_PACKETS, 1);
			increment_metric(ifindex, DECAP_CNT_DROP_MALFORMED_BYTES, frame_len);
			return XDP_DROP;
		}

		/* Pre-swap the addressing that the eventual reply will need
		 * reversed, so encap can replay this cache onto the wire
		 * completely unmodified. Doing it here rather than in encap
		 * means it runs once per request instead of once per reply — a
		 * real saving whenever a flow's traffic is asymmetric (e.g. a
		 * bulk download's data packets outnumber its acks), and never a
		 * loss otherwise. */
		struct ethhdr *cache_eth = (struct ethhdr *)cache.hdr;

		__u8 dst_mac[6], src_mac[6];
		__builtin_memcpy(dst_mac, cache_eth->h_dest, 6);
		__builtin_memcpy(src_mac, cache_eth->h_source, 6);
		__builtin_memcpy(cache_eth->h_dest, src_mac, 6);
		__builtin_memcpy(cache_eth->h_source, dst_mac, 6);

		/* saddr/daddr sit at a 2-byte-shy-of-4-aligned offset within
		 * cache.hdr (14-byte Ethernet header, then a 20-byte IP header)
		 * — kept in plain __u8* + memcpy terms, like the MAC swap above,
		 * rather than a typed struct iphdr* scalar access: the verifier
		 * accepts unaligned access through a packet pointer but rejects
		 * it for a stack buffer like this one. */
		__u8 *ip_saddr = cache.hdr + sizeof(struct ethhdr) + __builtin_offsetof(struct iphdr, saddr);
		__u8 *ip_daddr = cache.hdr + sizeof(struct ethhdr) + __builtin_offsetof(struct iphdr, daddr);

		__u8 saddr_bytes[4], daddr_bytes[4];
		__builtin_memcpy(saddr_bytes, ip_saddr, 4);
		__builtin_memcpy(daddr_bytes, ip_daddr, 4);
		__builtin_memcpy(ip_saddr, daddr_bytes, 4);
		__builtin_memcpy(ip_daddr, saddr_bytes, 4);

		/* The reply is a new datagram from this box, so it doesn't
		 * inherit the request's per-hop and per-packet IP fields: the
		 * request's TTL was already decremented on the way in, its ECN
		 * bits (CE included) describe congestion on that path rather
		 * than the reply's, and its DF/ID belong to that one packet. Use
		 * a fixed TTL, keep DSCP but clear ECN to Not-ECT, set DF and
		 * zero the ID (RFC 6864: an atomic datagram's ID means nothing).
		 * Normalizing here, before outer_hdr_stable_eq, also stops TTL or
		 * ECN changes from forcing a flow_state rewrite. */
		__u8 *ip_hdr = cache.hdr + sizeof(struct ethhdr);

		ip_hdr[__builtin_offsetof(struct iphdr, tos)] &= ~IPTOS_ECN_MASK;
		ip_hdr[__builtin_offsetof(struct iphdr, ttl)] = OUTER_REPLY_TTL;
		ip_hdr[__builtin_offsetof(struct iphdr, id)] = 0;
		ip_hdr[__builtin_offsetof(struct iphdr, id) + 1] = 0;
		ip_hdr[__builtin_offsetof(struct iphdr, frag_off)] = IP_DF >> 8;
		ip_hdr[__builtin_offsetof(struct iphdr, frag_off) + 1] = 0;
	}

	/* Strip everything through the GENEVE options, then reopen room for a
	 * synthesized L2 header, leaving [new eth hdr][inner IP packet]. Done
	 * before publishing to flow_state: if this fails, the packet is dropped
	 * undelivered, so there must be no cache entry for it. */
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

	/* Only (re)write the entry when its encapsulation actually changed
	 * (see outer_hdr_stable_eq). The lookup also refreshes the entry's LRU
	 * recency, so a flow that keeps arriving is never aged out. */
	if (cache_flow) {
		struct outer_hdr_cache *cur = bpf_map_lookup_elem(&flow_state, &fwd_key);

		if (!cur || !outer_hdr_stable_eq(cur, &cache))
			bpf_map_update_elem(&flow_state, &fwd_key, &cache, BPF_ANY);
	}

	increment_metric(ifindex, DECAP_CNT_OK_PACKETS, 1);
	increment_metric(ifindex, DECAP_CNT_OK_BYTES, frame_len);
	return bpf_redirect(ifindex, 0);
}
