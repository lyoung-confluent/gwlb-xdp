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

#define IPPROTO_HOPOPTS			0
#define IPPROTO_ICMP			1
#define IPPROTO_TCP			6
#define IPPROTO_UDP			17
#define IPPROTO_FRAGMENT		44
#define IPPROTO_ICMPV6			58

/* linux/ip.h: IPv4 frag_off bits (host order). */
#define IP_DF				0x4000
#define IP_MF				0x2000
#define IP_OFFSET			0x1FFF

/* linux/ip.h: the ECN field's bits within the IPv4 TOS byte. */
#define IPTOS_ECN_MASK			0x03

/* The outer IPv4 TTL every reply goes out with, Linux's default
 * (net.ipv4.ip_default_ttl) — the same as a reply sent from a normal UDP
 * socket, the way AWS's gwlbtun reference sends them. See the TTL/ECN/DF/ID
 * rewrite in _decap.c. */
#define OUTER_REPLY_TTL			64

/* linux/ipv6.h: IPv6 fragment header frag_off bits (host order). */
#define IP6_MF				0x0001
#define IP6_OFFSET			0xFFF8

/* linux/icmp.h / linux/icmpv6.h echo request/reply types — the only ICMP
 * messages parse_l4 (below) gives per-flow identity via their id field.
 * Everything else leaves a flow's ports at 0, same as any other protocol
 * parse_l4 doesn't recognize. */
#define ICMP_ECHO_REQUEST		8
#define ICMP_ECHO_REPLY			0
#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129

/* The ICMP/ICMPv6 error types that quote the offending packet right after
 * their own 8-byte header (RFC 792, RFC 4443) — see icmp_is_quoting_error. */
#define ICMP_DEST_UNREACH		3
#define ICMP_TIME_EXCEEDED		11
#define ICMP_PARAMETERPROB		12
#define ICMPV6_DEST_UNREACH		1
#define ICMPV6_PKT_TOOBIG		2
#define ICMPV6_TIME_EXCEED		3
#define ICMPV6_PARAMPROB		4

/* ICMPv6 types 130-143: MLD (130-132, 143), Neighbor Discovery (133-137)
 * and the other link-local control messages in between. Never a reply to a
 * decapsulated flow — see icmpv6_is_link_local_control. */
#define ICMPV6_MLD_QUERY		130
#define ICMPV6_MLD2_REPORT		143

/*
 * eth(14) + ip(20) + udp(8) + geneve(8) + opts(32): with decap assuming
 * exactly the three fixed-length GWLB options above, every piece of the
 * outer header is now a compile-time constant rather than a bound, so this
 * is an exact size, not a cap.
 */
#define OUTER_HDR_LEN			82

/* What encapsulation adds to an inner packet on the wire: OUTER_HDR_LEN
 * minus the Ethernet header the inner frame already had (68 bytes). */
#define GENEVE_OVERHEAD			(OUTER_HDR_LEN - 14)

/*
 * Compiled-in default for decap's and encap's max_inner_len: the largest
 * inner packet (IP header onward) that fits a 9001-byte uplink (the EC2
 * default) once encapsulated. `setup` always overrides it with the real
 * uplink's MTU - GENEVE_OVERHEAD (see bpf.MaxInnerLen).
 */
#define DEFAULT_MAX_INNER_LEN		(9001 - GENEVE_OVERHEAD)

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
 *
 * encap's frag_state map reuses this same key shape for fragment tracking,
 * with the fragment identification (split high/low 16 bits) standing in
 * for sport/dport — see frag_key in _encap.c.
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
 * Ethernet dst/src and IP saddr/daddr already swapped into reply orientation,
 * and its TTL, ECN, DF and ID already set to what a reply carries (see
 * _decap.c), so encap can replay it onto the wire completely unmodified
 * — only fields that depend on that specific reply's own size (IP/UDP
 * length, IP checksum) still get touched, in _encap.c, after the replay.
 * Shared by v4 and v6 inner flows — the outer header doesn't vary with the
 * inner address family.
 *
 * This box's own hwaddr for the reply needs no separately configured
 * uplink MAC: it's simply whichever address the original request was
 * itself addressed to, which the swap above already turns into the
 * reply's source.
 *
 * 4-byte aligned (sizeof rounds up to 84) so outer_hdr_stable_eq can compare
 * it in 16-bit words: the verifier rejects misaligned stack accesses.
 */
struct outer_hdr_cache {
	__u8	hdr[OUTER_HDR_LEN];
} __attribute__((aligned(4)));

/*
 * Reports whether two cached outer headers agree on every byte that
 * identifies the flow's encapsulation — everything except the fields that
 * legitimately change packet to packet within one flow: outer IP tot_len,
 * id and check, and UDP len and check. decap uses this to skip rewriting a
 * flow_state entry that already holds the same encapsulation (the common
 * case: the same flow arriving over the same GWLB path, packet after
 * packet), instead of an LRU replace — node alloc, bucket lock, free-list
 * push — on every packet. encap recomputes every skipped field itself, so
 * whichever packet's values the entry happens to hold doesn't matter.
 */
static __always_inline bool outer_hdr_stable_eq(const struct outer_hdr_cache *a,
						const struct outer_hdr_cache *b)
{
	const __u16 *x = (const __u16 *)a->hdr;
	const __u16 *y = (const __u16 *)b->hdr;

#pragma unroll
	for (int i = 0; i < OUTER_HDR_LEN / 2; i++) {
		if (i == (14 + __builtin_offsetof(struct iphdr, tot_len)) / 2 ||
		    i == (14 + __builtin_offsetof(struct iphdr, id)) / 2 ||
		    i == (14 + __builtin_offsetof(struct iphdr, check)) / 2 ||
		    i == (14 + 20 + __builtin_offsetof(struct udphdr, len)) / 2 ||
		    i == (14 + 20 + __builtin_offsetof(struct udphdr, check)) / 2)
			continue;
		if (x[i] != y[i])
			return false;
	}
	return true;
}

/* How much of a fragmented datagram a packet carries — see struct
 * inner_tuple. FRAG_LATER packets carry no L4 header at all. */
#define FRAG_NONE			0
#define FRAG_FIRST			1
#define FRAG_LATER			2

/*
 * One inner packet's parsed identity, filled in by parse_ipv4/parse_ipv6
 * and shared by decap and encap so both derive a flow identically.
 *
 * proto is the upper-layer protocol, past any IPv6 hop-by-hop options and
 * fragment header. sport/dport are the real ports for TCP/UDP, the echo id
 * (in both) for ICMP/ICMPv6 echo request/reply, and 0 otherwise — ICMP has
 * no source/dest port pair, just one identifier, and duplicating it into
 * both makes the NAT-mode port swap a no-op for it. Protocols with no
 * per-flow identity of their own collapse every flow between the same two
 * addresses onto one flow_key.
 *
 * has_l4 means the packet carries at least 8 bytes of a TCP/UDP/ICMP/ICMPv6
 * header (enough for ports, or an ICMP type and id), and icmp_type is only
 * meaningful with it. A FRAG_LATER fragment never has one: its ports live
 * in the first fragment, so it's matched by frag_id instead (see
 * frag_state in _encap.c).
 */
struct inner_tuple {
	union flow_addr	saddr;
	union flow_addr	daddr;
	__u32		frag_id;	/* IPv4 id or IPv6 fragment header id */
	__u16		sport;
	__u16		dport;
	__u8		proto;
	__u8		frag;		/* FRAG_NONE / FRAG_FIRST / FRAG_LATER */
	__u8		has_l4;
	__u8		icmp_type;
};

/* linux/ipv6.h struct frag_hdr. */
struct ipv6_frag_hdr {
	__u8	nexthdr;
	__u8	reserved;
	__be16	frag_off;
	__be32	identification;
};

/*
 * Fills in t's L4 fields from l4 per t->proto (see struct inner_tuple).
 * Returns -1 if a protocol it reads ports/type from is truncated below its
 * first 8 bytes, 0 otherwise — including for any protocol it doesn't read
 * at all, which is left with has_l4 unset and ports 0.
 */
static __always_inline int parse_l4(struct inner_tuple *t, void *l4, void *data_end)
{
	if (t->proto != IPPROTO_TCP && t->proto != IPPROTO_UDP &&
	    t->proto != IPPROTO_ICMP && t->proto != IPPROTO_ICMPV6)
		return 0;

	/* sport/dport (TCP/UDP) and type/id (ICMP) all sit within the first 8
	 * bytes, so one udphdr-sized bounds check covers every case. */
	if ((void *)((__u8 *)l4 + sizeof(struct udphdr)) > data_end)
		return -1;
	t->has_l4 = 1;

	if (t->proto == IPPROTO_TCP || t->proto == IPPROTO_UDP) {
		struct udphdr *hdr = l4;

		t->sport = hdr->source;
		t->dport = hdr->dest;
		return 0;
	}

	struct icmphdr *hdr = l4;

	t->icmp_type = hdr->type;
	if ((t->proto == IPPROTO_ICMP &&
	     (hdr->type == ICMP_ECHO_REQUEST || hdr->type == ICMP_ECHO_REPLY)) ||
	    (t->proto == IPPROTO_ICMPV6 &&
	     (hdr->type == ICMPV6_ECHO_REQUEST || hdr->type == ICMPV6_ECHO_REPLY))) {
		t->sport = hdr->id;
		t->dport = hdr->id;
	}
	return 0;
}

/*
 * Parses the IPv4 packet at ip into t, and points *l4 at its L4 header (or
 * where one would be, for a FRAG_LATER fragment or a protocol parse_l4
 * doesn't read). IP options are skipped via ihl. Returns -1 if the packet is
 * malformed (truncated, or ihl < 5), 0 otherwise.
 */
static __always_inline int parse_ipv4(struct iphdr *ip, void *data_end,
				      struct inner_tuple *t, void **l4)
{
	__builtin_memset(t, 0, sizeof(*t));
	if ((void *)(ip + 1) > data_end || ip->ihl < 5)
		return -1;

	t->saddr.v4 = ip->saddr;
	t->daddr.v4 = ip->daddr;
	t->proto = ip->protocol;
	*l4 = (__u8 *)ip + ip->ihl * 4;

	__u16 frag_off = bpf_ntohs(ip->frag_off);
	if (frag_off & (IP_MF | IP_OFFSET)) {
		t->frag = (frag_off & IP_OFFSET) ? FRAG_LATER : FRAG_FIRST;
		t->frag_id = bpf_ntohs(ip->id);
	}
	if (t->frag == FRAG_LATER)
		return 0;
	return parse_l4(t, *l4, data_end);
}

/*
 * parse_ipv4's IPv6 counterpart. Walks at most one hop-by-hop options header
 * (MLD reports always carry one, for their router alert) and then at most
 * one fragment header; any other extension header is left as t->proto
 * itself, with no ports. Returns -1 if the packet (or one of those two
 * headers) is truncated, 0 otherwise.
 */
static __always_inline int parse_ipv6(struct ipv6hdr *ip6, void *data_end,
				      struct inner_tuple *t, void **l4)
{
	__builtin_memset(t, 0, sizeof(*t));
	if ((void *)(ip6 + 1) > data_end)
		return -1;

	__builtin_memcpy(t->saddr.v6, &ip6->saddr, 16);
	__builtin_memcpy(t->daddr.v6, &ip6->daddr, 16);
	t->proto = ip6->nexthdr;

	__u8 *next = (__u8 *)(ip6 + 1);
	if (t->proto == IPPROTO_HOPOPTS) {
		if ((void *)(next + 2) > data_end)
			return -1;
		t->proto = next[0];
		next += (next[1] + 1) * 8;
	}
	if (t->proto == IPPROTO_FRAGMENT) {
		struct ipv6_frag_hdr *fh = (void *)next;

		if ((void *)(fh + 1) > data_end)
			return -1;
		t->proto = fh->nexthdr;
		next = (__u8 *)(fh + 1);

		/* An atomic fragment (offset 0, no M flag) is a whole packet
		 * that just happens to carry a fragment header: FRAG_NONE. */
		__u16 frag_off = bpf_ntohs(fh->frag_off);
		if (frag_off & (IP6_MF | IP6_OFFSET)) {
			t->frag = (frag_off & IP6_OFFSET) ? FRAG_LATER : FRAG_FIRST;
			t->frag_id = bpf_ntohl(fh->identification);
		}
	}
	*l4 = next;
	if (t->frag == FRAG_LATER)
		return 0;
	return parse_l4(t, next, data_end);
}

/* Whether t is an ICMP (IPv4) or ICMPv6 error that quotes the offending
 * packet right after its own 8-byte header. */
static __always_inline bool icmp_is_quoting_error(bool is_v6, const struct inner_tuple *t)
{
	if (!t->has_l4)
		return false;
	if (!is_v6)
		return t->proto == IPPROTO_ICMP &&
		       (t->icmp_type == ICMP_DEST_UNREACH ||
			t->icmp_type == ICMP_TIME_EXCEEDED ||
			t->icmp_type == ICMP_PARAMETERPROB);
	return t->proto == IPPROTO_ICMPV6 &&
	       t->icmp_type >= ICMPV6_DEST_UNREACH && t->icmp_type <= ICMPV6_PARAMPROB;
}

/* Whether t is an MLD or Neighbor Discovery message (or one of the other
 * link-local ICMPv6 control types between them): traffic between the ENI's
 * netns and its veth, never a reply to anything decap delivered. */
static __always_inline bool icmpv6_is_link_local_control(const struct inner_tuple *t)
{
	return t->has_l4 && t->proto == IPPROTO_ICMPV6 &&
	       t->icmp_type >= ICMPV6_MLD_QUERY && t->icmp_type <= ICMPV6_MLD2_REPORT;
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
