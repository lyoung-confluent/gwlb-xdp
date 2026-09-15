//go:build e2e

// Package e2e sends a synthetic AWS GWLB GENEVE packet across real veth
// interfaces (decap's uplink, the ENI's veth pair) and a real UDP echo
// server in the ENI's netns, then checks the GENEVE reply that comes back —
// exercising decap and encap together without a real GWLB. See e2e_test.go.
//
// Everything here — Ethernet/IPv4/UDP framing and the GENEVE header/options
// — is built and parsed with github.com/gopacket/gopacket/layers: real
// checksums, no hand-rolled header-layout bugs. Note the import path: this
// is the actively maintained fork (github.com/google/gopacket was archived
// by Google), which matters for more than freshness here — google/gopacket
// v1.1.19's Geneve layer has no SerializeTo (decode-only) and decodes each
// option's length field as an incompatible 4-bit/4-bit split rather than
// RFC 8926's actual 5-bit-length/3-bit-reserved layout bpf/geneve_defs.h
// implements. The fork fixes both.
package e2e

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const (
	genevePort = 6081

	geneveOptClassAWS       = 0x0108
	geneveOptTypeENI        = 0x01
	geneveOptTypeAttachment = 0x02
	geneveOptTypeCookie     = 0x03
)

var serializeOpts = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// buildGeneveOptions returns the three mandatory AWS GWLB GENEVE options
// (ENI ID, attachment ID, flow cookie), in the exact fixed order decap
// assumes them to be in (see bpf/decap/_decap.c and bpf/geneve_defs.h).
func buildGeneveOptions(eniID, attachmentID uint64, flowCookie uint32) []*layers.GeneveOption {
	eniData := make([]byte, 8)
	binary.BigEndian.PutUint64(eniData, eniID)

	attData := make([]byte, 8)
	binary.BigEndian.PutUint64(attData, attachmentID)

	cookieData := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieData, flowCookie)

	return []*layers.GeneveOption{
		{Class: geneveOptClassAWS, Type: geneveOptTypeENI, Data: eniData},
		{Class: geneveOptClassAWS, Type: geneveOptTypeAttachment, Data: attData},
		{Class: geneveOptClassAWS, Type: geneveOptTypeCookie, Data: cookieData},
	}
}

// verifyIPChecksum reports whether hdr — a raw IPv4 header, checksum field
// included as transmitted — is internally consistent: per RFC 1071, summing
// every 16-bit word of a header over its own correct checksum folds to all
// ones. Used to check encap's own recomputed checksum (see ipv4_checksum in
// _encap.c) rather than trusting gopacket's decode, which parses the
// checksum field as data without verifying it.
func verifyIPChecksum(hdr []byte) bool {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return sum == 0xFFFF
}

// requestParams describes the synthetic GWLB->box GENEVE packet
// buildRequestFrame assembles.
type requestParams struct {
	outerSrcMAC, outerDstMAC net.HardwareAddr
	outerSrcIP, outerDstIP   net.IP
	outerSrcPort             uint16
	geneveVer                uint8 // 0 for a well-formed packet — decap drops anything else, see _decap.c
	vni                      [3]byte
	opts                     []*layers.GeneveOption // from buildGeneveOptions

	innerSrcIP, innerDstIP     net.IP
	innerSrcPort, innerDstPort uint16
	payload                    []byte
}

// buildRequestFrame assembles a full Ethernet frame carrying an outer
// IPv4/UDP/GENEVE tunnel around an inner IPv4/UDP packet, matching exactly
// what decap (bpf/decap/_decap.c) expects to parse.
func buildRequestFrame(p requestParams) ([]byte, error) {
	// Inner packet: no Ethernet layer — GWLB encapsulates at L3, and decap
	// synthesizes the inner Ethernet header itself (see _decap.c).
	innerIP := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    p.innerSrcIP,
		DstIP:    p.innerDstIP,
	}
	innerUDP := &layers.UDP{
		SrcPort: layers.UDPPort(p.innerSrcPort),
		DstPort: layers.UDPPort(p.innerDstPort),
	}
	if err := innerUDP.SetNetworkLayerForChecksum(innerIP); err != nil {
		return nil, fmt.Errorf("SetNetworkLayerForChecksum for inner UDP failed: %w", err)
	}

	innerBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(innerBuf, serializeOpts, innerIP, innerUDP, gopacket.Payload(p.payload)); err != nil {
		return nil, fmt.Errorf("serializing inner packet failed: %w", err)
	}

	geneve := &layers.Geneve{
		Version:  p.geneveVer,
		Protocol: layers.EthernetTypeIPv4,
		VNI:      uint32(p.vni[0])<<16 | uint32(p.vni[1])<<8 | uint32(p.vni[2]),
		Options:  p.opts,
	}

	eth := &layers.Ethernet{
		SrcMAC:       p.outerSrcMAC,
		DstMAC:       p.outerDstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	outerIP := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    p.outerSrcIP,
		DstIP:    p.outerDstIP,
	}
	outerUDP := &layers.UDP{
		SrcPort: layers.UDPPort(p.outerSrcPort),
		DstPort: layers.UDPPort(genevePort),
	}
	if err := outerUDP.SetNetworkLayerForChecksum(outerIP); err != nil {
		return nil, fmt.Errorf("SetNetworkLayerForChecksum for outer UDP failed: %w", err)
	}

	outerBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(outerBuf, serializeOpts, eth, outerIP, outerUDP, geneve, gopacket.Payload(innerBuf.Bytes())); err != nil {
		return nil, fmt.Errorf("serializing outer packet failed: %w", err)
	}
	return append([]byte(nil), outerBuf.Bytes()...), nil
}

// replyPacket is what parseReply extracts from a captured frame. Despite
// the name, sendGENEVE also uses it to read back a just-built *request*
// frame — the wire shape is identical either way (outer eth/ip/udp/geneve
// wrapping an inner ip/udp/payload), and doing so gets the "verbatim
// replay" check in assertValidReply comparing against what actually left
// the wire rather than against buildRequestFrame's own inputs.
type replyPacket struct {
	outerSrcMAC, outerDstMAC net.HardwareAddr
	outerSrcIP, outerDstIP   net.IP
	outerDstPort             uint16
	outerUDPChecksum         uint16 // encap zeroes this on a reply — see _encap.c
	outerIPChecksumValid     bool   // encap recomputes this on a reply — see ipv4_checksum in _encap.c

	opts []byte // raw GENEVE option bytes — see the type comment and parseReply

	innerSrcIP, innerDstIP     net.IP
	innerSrcPort, innerDstPort uint16
	innerIPChecksumValid       bool // untouched by encap, but still worth a sanity check
	payload                    []byte
}

// parseReply parses frame as an outer eth/IPv4/UDP/GENEVE packet wrapping an
// inner IPv4/UDP packet — the shape both a request and a reply have (see
// the type comment on replyPacket).
func parseReply(frame []byte) (*replyPacket, error) {
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		return nil, fmt.Errorf("decoding outer frame failed: %w", errLayer.Error())
	}

	eth, ok := packet.LinkLayer().(*layers.Ethernet)
	if !ok || eth.EthernetType != layers.EthernetTypeIPv4 {
		return nil, fmt.Errorf("not an IPv4 ethernet frame")
	}
	outerIP, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("no outer IPv4 layer")
	}
	outerUDP, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok {
		return nil, fmt.Errorf("no outer UDP layer")
	}
	gn, ok := packet.Layer(layers.LayerTypeGeneve).(*layers.Geneve)
	if !ok {
		return nil, fmt.Errorf("no GENEVE layer (not a GWLB packet?)")
	}

	// gn.Contents is the base header plus options, delimited by the base
	// header's own Ver/OptLen field. Compared as raw bytes (not gn.Options)
	// because "verbatim replay" is fundamentally a byte-level claim about
	// what encap does (see _encap.c) — this isn't working around a decoder
	// bug the way it would have been against google/gopacket (see the
	// package comment).
	if len(gn.Contents) < 8 {
		return nil, fmt.Errorf("truncated GENEVE header")
	}
	opts := append([]byte(nil), gn.Contents[8:]...)

	// The inner packet (an IPv4/UDP packet, no Ethernet header — see
	// buildRequestFrame) is GENEVE's payload; decode it as its own packet
	// rather than relying on gopacket's first-layer-wins Layer()/
	// NetworkLayer() accessors, which can't distinguish it from the outer
	// IPv4/UDP layers already decoded above.
	innerPacket := gopacket.NewPacket(gn.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default)
	if errLayer := innerPacket.ErrorLayer(); errLayer != nil {
		return nil, fmt.Errorf("decoding inner packet failed: %w", errLayer.Error())
	}
	innerIP, ok := innerPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("no inner IPv4 layer")
	}
	innerUDP, ok := innerPacket.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok {
		return nil, fmt.Errorf("no inner UDP layer")
	}

	return &replyPacket{
		outerDstMAC: eth.DstMAC,
		outerSrcMAC: eth.SrcMAC,

		outerSrcIP: outerIP.SrcIP,
		outerDstIP: outerIP.DstIP,

		outerDstPort:         uint16(outerUDP.DstPort),
		outerUDPChecksum:     outerUDP.Checksum,
		outerIPChecksumValid: verifyIPChecksum(outerIP.Contents),

		opts: opts,

		innerSrcIP:           innerIP.SrcIP,
		innerDstIP:           innerIP.DstIP,
		innerSrcPort:         uint16(innerUDP.SrcPort),
		innerDstPort:         uint16(innerUDP.DstPort),
		innerIPChecksumValid: verifyIPChecksum(innerIP.Contents),
		payload:              innerUDP.Payload,
	}, nil
}
