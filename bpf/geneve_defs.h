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

#define GENEVE_PORT			6081

/* Constants from <linux/if_ether.h>/<linux/in.h>, which can't be included
 * under -target bpf. */
#define ETH_P_IP			0x0800
#define ETH_P_IPV6			0x86DD

#define IPPROTO_ICMP			1
#define IPPROTO_TCP			6
#define IPPROTO_UDP			17

/*
 * Upper bound on GENEVE option bytes decap walks (its unrolled loop runs
 * MAX_GENEVE_OPT_BYTES/4 times). Real GWLB traffic carries 3 options = 32
 * bytes; 40 leaves one extra option's headroom.
 *
 * This is a verifier limit, not a traffic estimate: each step up adds another
 * unrolled copy of the parsing logic, and 48 (12 iterations) already exceeds
 * the verifier's 1M-instruction budget while 40 (10 iterations) loads (checked
 * via `make verify` in the dev container). Raising this requires re-checking
 * against the verifier.
 */
#define MAX_GENEVE_OPT_BYTES		40

/* eth(14) + ip(20) + udp(8) + geneve(8) + opts(40), rounded up to 16. */
#define MAX_OUTER_HDR_BYTES		96

/*
 * Inner 5-tuple, IPv4. Separate struct+map from the IPv6 version rather than
 * one struct with a 16-byte address: no wasted map-value space, no version tag.
 */
struct flow_key_v4 {
	__u32	ifindex;	/* folds tenant identity into the key; see maps.h */
	__u32	saddr;
	__u32	daddr;
	__u16	sport;
	__u16	dport;
	__u8	proto;
	__u8	pad[3];
};

/* Inner 5-tuple, IPv6 — same shape, addresses widened to 16 bytes. This is the
 * inner packet only; the outer GENEVE tunnel is IPv4 either way. */
struct flow_key_v6 {
	__u32	ifindex;
	__u8	saddr[16];
	__u8	daddr[16];
	__u16	sport;
	__u16	dport;
	__u8	proto;
	__u8	pad[3];
};

/* Cached outer eth+ip+udp+geneve(+opts) header, replayed verbatim on encap
 * except for recomputed fields (see _encap.c). Shared by v4 and v6 inner
 * flows — the outer header doesn't vary with the inner address family. */
struct outer_hdr_cache {
	__u16	len;
	__u8	hdr[MAX_OUTER_HDR_BYTES];
};

/*
 * Flow-key constructors, shared by decap (key from the inner packet as
 * forwarded) and encap (pre-swapped tuple for the NAT reply orientation). Kept
 * in one place so both populate the key — padding included — identically; a
 * silent divergence would break every lookup with no error.
 */
static __always_inline void build_flow_key_v4(struct flow_key_v4 *key, __u32 ifindex,
					    __u32 saddr, __u32 daddr,
					    __u16 sport, __u16 dport,
					    __u8 proto)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->ifindex = ifindex;
	key->saddr = saddr;
	key->daddr = daddr;
	key->sport = sport;
	key->dport = dport;
	key->proto = proto;
}

static __always_inline void build_flow_key_v6(struct flow_key_v6 *key, __u32 ifindex,
					       const struct in6_addr *saddr,
					       const struct in6_addr *daddr,
					       __u16 sport, __u16 dport,
					       __u8 proto)
{
	__builtin_memset(key, 0, sizeof(*key));
	key->ifindex = ifindex;
	__builtin_memcpy(key->saddr, saddr, 16);
	__builtin_memcpy(key->daddr, daddr, 16);
	key->sport = sport;
	key->dport = dport;
	key->proto = proto;
}

#endif /* GWLB_XDP_GENEVE_DEFS_H */
