#ifndef GWLB_XDP_NET_HDRS_H
#define GWLB_XDP_NET_HDRS_H

/*
 * Hand-written stand-ins for the handful of kernel types the BPF programs
 * touch (struct ethhdr/iphdr/ipv6hdr/udphdr/tcphdr/in6_addr, struct xdp_md,
 * and the __u8/__be16/... scalar typedefs), replacing a full generated
 * vmlinux.h.
 *
 * vmlinux.h exists to support CO-RE, which relocates field accesses against
 * the running kernel's BTF. Nothing here uses CO-RE — these are RFC-defined
 * wire headers and stable UAPI (struct xdp_md) at fixed offsets — so the
 * ~160k-line generated header was pure overhead (and once caused a struct
 * name collision). If CO-RE is ever needed, replace this with a real
 * vmlinux.h. See bpf_helpers_min.h for the same treatment of bpf_helpers.h.
 */

#include <stdbool.h> /* compiler-provided freestanding header; safe under -target bpf */

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

/* Big-endian-tagged aliases (sparse annotates these in the kernel; nothing
 * here checks sparse, so plain aliases are enough to document intent). */
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __sum16;

/* linux/if_ether.h */
struct ethhdr {
	__u8	h_dest[6];
	__u8	h_source[6];
	__be16	h_proto;
};

/* linux/ip.h. Bitfields hardcoded little-endian — bpf2go only builds
 * amd64/arm64 (LE) targets. */
struct iphdr {
	__u8	ihl:4,
		version:4;
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
};

/* linux/in6.h */
struct in6_addr {
	__u8	s6_addr[16];
};

/* linux/ipv6.h. Same LE-only bitfield note as iphdr. */
struct ipv6hdr {
	__u8			priority:4,
				version:4;
	__u8			flow_lbl[3];
	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;
	struct in6_addr		saddr;
	struct in6_addr		daddr;
};

/* linux/udp.h */
struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};

/* linux/tcp.h, fixed 20-byte part only. This codebase only locates the
 * checksum field, so the data-offset/flags bytes aren't broken into
 * sub-fields. */
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
	__u8	doff_reserved;
	__u8	flags;
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

/* linux/bpf.h — stable UAPI, part of the ABI. */
struct xdp_md {
	__u32	data;
	__u32	data_end;
	__u32	data_meta;
	__u32	ingress_ifindex;
	__u32	rx_queue_index;
	__u32	egress_ifindex;
};

#endif /* GWLB_XDP_NET_HDRS_H */
