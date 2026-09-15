#ifndef GWLB_XDP_GENEVE_DEFS_H
#define GWLB_XDP_GENEVE_DEFS_H

/*
 * Scalar types (__u8/__be16/...) are provided by the includer: the BPF programs
 * get them from net_hdrs.h (included first), since clang's -target bpf can't
 * pull in <linux/types.h>.
 */

/* RFC 8926 GENEVE base header, network byte order. */
struct gwlb_genevehdr {
	__u8	opt_len:6;	/* length of options, in 4-byte words */
	__u8	ver:2;
	__u8	rsvd1:6;
	__u8	critical:1;
	__u8	oam:1;
	__be16	proto_type;	/* ethertype of inner payload, e.g. 0x0800 */
	__u8	vni[3];
	__u8	rsvd2;
} __attribute__((packed));

/* RFC 8926 section 3.5 variable option header. */
struct geneve_opt_hdr {
	__be16	opt_class;
	__u8	type;
	__u8	length:5;	/* in 4-byte words, excludes this 4-byte header */
	__u8	rsvd:3;
} __attribute__((packed));

/*
 * AWS Gateway Load Balancer GENEVE options (class 0x0108), confirmed against
 * the aws-gateway-load-balancer-tunnel-handler reference (GenevePacket.cpp):
 * all three are mandatory on every GWLB packet and fixed-length.
 *
 *   type 0x01  ENI ID        8 bytes (__be64)
 *   type 0x02  Attachment ID 8 bytes (__be64)
 *   type 0x03  Flow cookie   4 bytes (__be32)
 */
#define GENEVE_OPT_CLASS_AWS		0x0108

#define GWLB_OPT_TYPE_ENI		0x01
#define GWLB_OPT_TYPE_ATTACHMENT	0x02
#define GWLB_OPT_TYPE_COOKIE		0x03

#define GWLB_OPT_ENI_LEN		8
#define GWLB_OPT_ATTACHMENT_LEN		8
#define GWLB_OPT_COOKIE_LEN		4

/*
 * decap assumes every GWLB packet carries exactly these three options, each
 * a 4-byte geneve_opt_hdr plus its fixed-length data, in exactly this order
 * — not a generic options walk. GWLB_OPTS_LEN is the resulting fixed total
 * (12 + 12 + 8 = 32 bytes), and is itself part of OUTER_HDR_LEN below.
 */
#define GWLB_OPTS_LEN ( \
	3 * sizeof(struct geneve_opt_hdr) + \
	GWLB_OPT_ENI_LEN + GWLB_OPT_ATTACHMENT_LEN + GWLB_OPT_COOKIE_LEN)

#define GENEVE_PORT			6081

/* Constants from <linux/if_ether.h>/<linux/in.h>, which can't be included
 * under -target bpf. */
#define ETH_P_IP			0x0800
#define ETH_P_IPV6			0x86DD

#define IPPROTO_ICMP			1
#define IPPROTO_TCP			6
#define IPPROTO_UDP			17
#define IPPROTO_ICMPV6			58

/* linux/icmp.h / linux/icmpv6.h echo request/reply types — the only ICMP
 * messages parse_l4_ports (below) gives per-flow identity via their id
 * field. Everything else (unreachable, time-exceeded, ...) leaves a flow's
 * ports at 0, same as any other protocol parse_l4_ports doesn't recognize. */
#define ICMP_ECHO_REQUEST		8
#define ICMP_ECHO_REPLY			0
#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129

/*
 * eth(14) + ip(20) + udp(8) + geneve(8) + opts(32): with decap assuming
 * exactly the three fixed-length GWLB options above, every piece of the
 * outer header is now a compile-time constant rather than a bound, so this
 * is an exact size, not a cap.
 */
#define OUTER_HDR_LEN			82

/* An inner packet's address, either family — a plain __u32 for v4, or the
 * full 16 bytes for v6. Which one's live is struct flow_key's own is_v6,
 * not a tag here: build_flow_key always zeroes the key first and then
 * copies only the bytes that family actually uses, so a v4 address's
 * unused upper 12 bytes are deterministically zero rather than whatever
 * was sitting in the caller's union, and can never alias a real v6 one. */
union flow_addr {
	__u32	v4;
	__u8	v6[16];
};

/*
 * Inner 5-tuple, either address family — one struct/map for both rather
 * than a separate v4/v6 pair, so a single flow_state map (see maps.h)
 * serves both; is_v6 disambiguates the union above. ifindex folds tenant
 * identity into the key (see maps.h). This is the inner packet's own
 * tuple; the outer GENEVE tunnel is IPv4 either way.
 */
struct flow_key {
	__u32		ifindex;
	union flow_addr	saddr;
	union flow_addr	daddr;
	__u16		sport;
	__u16		dport;
	__u8		proto;
	__u8		is_v6;
	__u8		pad[2];
};

/*
 * Cached outer eth+ip+udp+geneve+opts header, stored by decap with its
 * Ethernet dst/src and IP saddr/daddr already swapped into reply orientation
 * (see _decap.c) so encap can replay it onto the wire completely unmodified
 * — only fields that depend on that specific reply's own size (IP/UDP
 * length, IP checksum) still get touched, in _encap.c, after the replay.
 * Shared by v4 and v6 inner flows — the outer header doesn't vary with the
 * inner address family.
 *
 * This box's own hwaddr for the reply needs no separately configured
 * uplink MAC: it's simply whichever address the original request was
 * itself addressed to, which the swap above already turns into the
 * reply's source.
 */
struct outer_hdr_cache {
	__u8	hdr[OUTER_HDR_LEN];
};

/*
 * Fills in *sport / *dport from l4 per proto, for flow_key purposes — shared
 * by decap and encap so both derive a flow's ports identically. l4 must
 * already be validated for at least sizeof(struct udphdr) (8) bytes before
 * data_end; struct icmphdr is the same size, so callers' existing TCP/UDP
 * bounds check already covers ICMP/ICMPv6 too (see _decap.c/_encap.c).
 *
 * TCP/UDP: the real source/dest ports. ICMP/ICMPv6 echo request or reply:
 * both *sport and *dport get the same value, the echo's own id — ICMP has
 * no source/dest port pair, just one identifier, and duplicating it into
 * both makes build_flow_key's NAT-mode port swap a no-op for it rather than
 * needing ICMP-specific handling there. Anything else (ICMP errors like
 * unreachable/time-exceeded included) leaves *sport / *dport untouched at the
 * 0 callers already default them to: those protocols carry no per-flow
 * identity of their own, so every flow of that protocol between the same
 * two addresses collapses onto one flow_key.
 */
static __always_inline void parse_l4_ports(__u8 proto, void *l4, __u16 *sport, __u16 *dport)
{
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		struct udphdr *hdr = l4;

		*sport = hdr->source;
		*dport = hdr->dest;
	} else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
		struct icmphdr *hdr = l4;

		if (hdr->type == ICMP_ECHO_REQUEST || hdr->type == ICMP_ECHO_REPLY ||
		    hdr->type == ICMPV6_ECHO_REQUEST || hdr->type == ICMPV6_ECHO_REPLY) {
			*sport = hdr->id;
			*dport = hdr->id;
		}
	}
}

/*
 * Flow-key constructor, shared by decap (key from the inner packet as
 * forwarded) and encap (pre-swapped tuple for the NAT reply orientation). Kept
 * in one place so both populate the key — padding included — identically; a
 * silent divergence would break every lookup with no error.
 *
 * saddr/daddr are taken by value: each is exactly one union flow_addr's
 * worth of registers/stack, cheap for an __always_inline call, and it
 * keeps the union (rather than its address) the thing every caller
 * actually builds — see build_flow_key's callers in _decap.c/_encap.c.
 */
static __always_inline void build_flow_key(struct flow_key *key, __u32 ifindex,
					    bool is_v6, union flow_addr saddr,
					    union flow_addr daddr,
					    __u16 sport, __u16 dport, __u8 proto)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->ifindex = ifindex;
	key->is_v6 = is_v6;
	if (is_v6) {
		__builtin_memcpy(key->saddr.v6, saddr.v6, 16);
		__builtin_memcpy(key->daddr.v6, daddr.v6, 16);
	} else {
		key->saddr.v4 = saddr.v4;
		key->daddr.v4 = daddr.v4;
	}
	key->sport = sport;
	key->dport = dport;
	key->proto = proto;
}

#endif /* GWLB_XDP_GENEVE_DEFS_H */
