//go:build e2e

package e2e

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
	"github.com/lyoung-confluent/gwlb-xdp/cmd"
)

// maxFrameLen sizes every frame read buffer: comfortably above the largest
// frame any test sends or expects back (a 9001-byte uplink MTU plus its
// Ethernet header).
const maxFrameLen = 16384

// closedPort has no listener on any endpoint's backend, so a datagram to it draws
// an ICMP port unreachable from the netns kernel.
const closedPort = echoServerPort + 1

// sendFrame sends one pre-built frame out gwlbIface, as the GWLB would.
func sendFrame(t *testing.T, fd int, gwlbIface *net.Interface, frame []byte) {
	t.Helper()
	if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: gwlbIface.Index}); err != nil {
		t.Fatalf("unix.Sendto failed: %v", err)
	}
}

// innerRequestFrame wraps inner (an inner IPv4 or IPv6 packet, per
// ethertype) in a GENEVE request for gwlbID carrying flowCookie, addressed
// exactly as sendGENEVE's are.
func innerRequestFrame(t *testing.T, uplinkIface, gwlbIface *net.Interface, gwlbID uint64, flowCookie uint32, inner []byte, ethertype layers.EthernetType) []byte {
	t.Helper()
	frame, err := buildRequestFrame(requestParams{
		outerSrcMAC:    gwlbIface.HardwareAddr,
		outerDstMAC:    uplinkIface.HardwareAddr,
		outerSrcIP:     net.ParseIP(fakeGWLBOuterSrcIP),
		outerDstIP:     net.ParseIP(fakeGWLBOuterDstIP),
		outerSrcPort:   fakeOuterSrcPort,
		opts:           buildGeneveOptions(gwlbID, fakeAttachmentID, flowCookie),
		innerPacket:    inner,
		innerEthertype: ethertype,
	})
	if err != nil {
		t.Fatalf("buildRequestFrame failed: %v", err)
	}
	return frame
}

// collectReplies reads frames on fd, handing each one whose outer source MAC
// is uplinkMAC (i.e. an encapsulated reply, not our own looped-back request
// — see waitForReply) to fn until fn reports done or timeout elapses. It
// reports whether fn finished.
func collectReplies(t *testing.T, fd int, uplinkMAC net.HardwareAddr, timeout time.Duration, fn func(frame []byte) (done bool)) bool {
	t.Helper()
	tv := unix.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatalf("unix.SetsockoptTimeval failed: %v", err)
	}

	buf := make([]byte, maxFrameLen)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			t.Fatalf("reading frames failed: %v", err)
		}
		if n < 14 || !bytes.Equal(buf[6:12], uplinkMAC) {
			continue
		}
		if fn(append([]byte(nil), buf[:n]...)) {
			return true
		}
	}
	return false
}

// inEndpointNetns runs fn inside gwlbID's netns (provisionEndpoint's isolated mode).
func inEndpointNetns(t *testing.T, gwlbID uint64, fn func() error) {
	t.Helper()
	ns, err := netns.GetFromName(cmd.FormatVPCEID(gwlbID))
	if err != nil {
		t.Fatalf("netns.GetFromName failed: %v", err)
	}
	defer ns.Close()
	if err := cmd.WithNetns(ns, fn); err != nil {
		t.Fatalf("running in endpoint %#x's netns failed: %v", gwlbID, err)
	}
}

// TestICMPErrorReply checks that an ICMP error the backend generates about
// one of its flows — here a port unreachable, for a datagram to a port
// nothing listens on — goes back to the GWLB encapsulated with that flow's
// own GENEVE options. The error's own tuple matches no flow (and has no
// port-like id), so encap has to find the flow through the packet the error
// quotes (see icmp_is_quoting_error in bpf/geneve_defs.h).
func TestICMPErrorReply(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	one := provisionEndpoint(t, gwlbID, true, echoServerPort, bytes.Clone)
	fd := openGWLBSocket(t, gwlbIface)

	cases := []struct {
		name      string
		v6        bool
		cookie    uint32
		ethertype layers.EthernetType
		clientIP  string
		serverIP  string
		// wantType/wantCode: port unreachable, per family.
		wantType, wantCode uint8
	}{
		{"ipv4", false, 0x0A0B0C0D, layers.EthernetTypeIPv4, fakeClientIP, echoServerIP, 3, 3},
		{"ipv6", true, 0x0E0F1011, layers.EthernetTypeIPv6, fakeClientIP6, echoServerIP6, 1, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("to a port nothing listens on")
			var inner []byte
			var err error
			if tc.v6 {
				inner, err = buildInnerUDPv6(net.ParseIP(tc.clientIP), net.ParseIP(tc.serverIP), fakeClientPort, closedPort, payload)
			} else {
				inner, err = buildInnerUDPv4(net.ParseIP(tc.clientIP), net.ParseIP(tc.serverIP), fakeClientPort, closedPort, payload)
			}
			if err != nil {
				t.Fatalf("building the inner request failed: %v", err)
			}
			frame := innerRequestFrame(t, uplinkIface, gwlbIface, gwlbID, tc.cookie, inner, tc.ethertype)
			reqOpts, _, _, err := geneveInner(frame)
			if err != nil {
				t.Fatalf("parsing our own request frame failed: %v", err)
			}

			okBefore := metricSum(t, "encap_ok_packets", one.outerIfindex)
			missBefore := metricSum(t, "encap_drop_flow_miss_packets", one.outerIfindex)
			sendFrame(t, fd, gwlbIface, frame)

			var opts, errPkt []byte
			var checksumOK bool
			if !collectReplies(t, fd, uplinkIface.HardwareAddr, 5*time.Second, func(f []byte) bool {
				o, in, ok, err := geneveInner(f)
				if err != nil {
					return false
				}
				opts, errPkt, checksumOK = o, in, ok
				return true
			}) {
				t.Fatalf("no encapsulated ICMP error observed within 5s (encap_drop_flow_miss_packets %d -> %d)",
					missBefore, metricSum(t, "encap_drop_flow_miss_packets", one.outerIfindex))
			}

			if !bytes.Equal(opts, reqOpts) {
				t.Errorf("ICMP error GENEVE options = %x, want %x (the erroring flow's own, flow cookie included)", opts, reqOpts)
			}
			if !checksumOK {
				t.Error("ICMP error outer IP header checksum is invalid")
			}

			// The error itself: backend -> client, ICMP(v6) port unreachable,
			// quoting the request that caused it.
			var src, dst net.IP
			var icmpType, icmpCode uint8
			var quoted []byte
			if tc.v6 {
				if len(errPkt) < 48 || errPkt[6] != 58 {
					t.Fatalf("reply isn't an ICMPv6 packet: %x", errPkt)
				}
				src, dst = net.IP(errPkt[8:24]), net.IP(errPkt[24:40])
				icmpType, icmpCode = errPkt[40], errPkt[41]
				quoted = errPkt[48:]
			} else {
				ihl := int(errPkt[0]&0xF) * 4
				if len(errPkt) < ihl+8 || errPkt[9] != 1 {
					t.Fatalf("reply isn't an ICMP packet: %x", errPkt)
				}
				src, dst = net.IP(errPkt[12:16]), net.IP(errPkt[16:20])
				icmpType, icmpCode = errPkt[ihl], errPkt[ihl+1]
				quoted = errPkt[ihl+8:]
			}
			if !src.Equal(net.ParseIP(tc.serverIP)) || !dst.Equal(net.ParseIP(tc.clientIP)) {
				t.Errorf("ICMP error addresses = %s -> %s, want %s -> %s", src, dst, tc.serverIP, tc.clientIP)
			}
			if icmpType != tc.wantType || icmpCode != tc.wantCode {
				t.Errorf("ICMP error type/code = %d/%d, want %d/%d (port unreachable)", icmpType, icmpCode, tc.wantType, tc.wantCode)
			}
			if !bytes.HasPrefix(quoted, inner[:min(len(inner), len(quoted))]) || len(quoted) < 28 {
				t.Errorf("ICMP error quotes %x, want a prefix of the request %x", quoted, inner)
			}

			if got := metricSum(t, "encap_ok_packets", one.outerIfindex); got != okBefore+1 {
				t.Errorf("encap_ok_packets = %d, want %d", got, okBefore+1)
			}
			if got := metricSum(t, "encap_drop_flow_miss_packets", one.outerIfindex); got != missBefore {
				t.Errorf("encap_drop_flow_miss_packets = %d, want %d (unchanged)", got, missBefore)
			}
		})
	}
}

// watchVethOuter returns a packet socket on veth-outer in the root netns,
// which only sees what encap passed to the stack.
func watchVethOuter(t *testing.T, outerIfindex uint32) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatalf("unix.Socket failed: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: int(outerIfindex)}); err != nil {
		t.Fatalf("unix.Bind failed: %v", err)
	}
	return fd
}

// sendFromEndpointNetns sends one UDP datagram to dst from inside gwlbID's netns.
func sendFromEndpointNetns(t *testing.T, gwlbID uint64, dst string) {
	t.Helper()
	inEndpointNetns(t, gwlbID, func() error {
		conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.ParseIP(dst), Port: 9})
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Write([]byte("resolve me"))
		return err
	})
}

// sawNeighborSolicit reports whether a Neighbor Solicitation for target
// turns up on fd within timeout.
func sawNeighborSolicit(t *testing.T, fd int, target string, timeout time.Duration) bool {
	t.Helper()
	tv := unix.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatalf("unix.SetsockoptTimeval failed: %v", err)
	}
	const ndNeighborSolicit = 135
	ip := net.ParseIP(target)
	buf := make([]byte, maxFrameLen)
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		n, err := unix.Read(fd, buf)
		if err != nil {
			continue
		}
		f := buf[:n]
		// eth(14) + ipv6(40) + NS: type(1) code(1) csum(2) reserved(4) target(16)
		if n >= 14+40+24 && binary.BigEndian.Uint16(f[12:14]) == unix.ETH_P_IPV6 &&
			f[14+6] == 58 && f[14+40] == ndNeighborSolicit && net.IP(f[14+48:14+64]).Equal(ip) {
			return true
		}
	}
	return false
}

// TestNoNeighborResolution checks that the endpoint's netns sends a packet
// straight out its veth without first resolving the next hop: `add` turns
// ARP/ND off on veth-inner (see cmd/add.go), since nothing would ever answer
// for an address the root netns doesn't own. The datagram here, to an
// on-link address nothing answers for, must reach encap (a flow miss, since
// decap never delivered its flow) rather than wait on a Neighbor
// Solicitation.
func TestNoNeighborResolution(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)

	setupUplink(t)
	runSetup(t, 8)
	one := provisionEndpoint(t, gwlbID, true, echoServerPort, bytes.Clone)
	fd := watchVethOuter(t, one.outerIfindex)

	const unresolved = "2001:db8::99"
	missBefore := metricSum(t, "encap_drop_flow_miss_packets", one.outerIfindex)
	sendFromEndpointNetns(t, gwlbID, unresolved)

	if sawNeighborSolicit(t, fd, unresolved, time.Second) {
		t.Errorf("Neighbor Solicitation for %s observed on veth-outer, want none (ARP off on veth-inner)", unresolved)
	}
	if got := metricSum(t, "encap_drop_flow_miss_packets", one.outerIfindex); got != missBefore+1 {
		t.Errorf("encap_drop_flow_miss_packets = %d, want %d (the datagram itself, sent unresolved)", got, missBefore+1)
	}
}

// TestNeighborDiscoveryPassed checks that IPv6 Neighbor Discovery (and MLD)
// the endpoint's netns sends out its veth reaches the root netns rather than
// being dropped by encap as a flow miss: they're IPv6 packets, but never a
// reply to anything decap delivered (see icmpv6_is_link_local_control in
// bpf/geneve_defs.h). `add` turns ARP/ND off on veth-inner, so this turns it
// back on first — as a --script could — to get a Neighbor Solicitation sent.
func TestNeighborDiscoveryPassed(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)

	setupUplink(t)
	runSetup(t, 8)
	one := provisionEndpoint(t, gwlbID, true, echoServerPort, bytes.Clone)
	fd := watchVethOuter(t, one.outerIfindex)

	inEndpointNetns(t, gwlbID, func() error {
		link, err := netlink.LinkByName(cmd.FormatInterfaceName(gwlbID, true))
		if err != nil {
			return err
		}
		return netlink.LinkSetARPOn(link)
	})

	// A datagram to an on-link address with no neighbor entry makes the
	// netns kernel send a Neighbor Solicitation for it.
	const unresolved = "2001:db8::99"
	sendFromEndpointNetns(t, gwlbID, unresolved)
	if !sawNeighborSolicit(t, fd, unresolved, 5*time.Second) {
		t.Fatalf("no Neighbor Solicitation for %s observed on veth-outer within 5s — encap dropped it?", unresolved)
	}

	// Everything the netns has sent so far — this NS, MLD reports — was
	// link-local control traffic, none of it a flow miss.
	if got := metricSum(t, "encap_drop_flow_miss_packets", one.outerIfindex); got != 0 {
		t.Errorf("encap_drop_flow_miss_packets = %d, want 0 (ND/MLD should be passed, not looked up)", got)
	}
}

// fragment is one IP fragment's slice of its datagram's payload.
type fragment struct {
	offset int
	more   bool
	data   []byte
}

// parseFragment reads an inner IPv4 or IPv6 packet as a fragment, returning
// ok=false for anything unfragmented.
func parseFragment(inner []byte, v6 bool) (fragment, bool) {
	if v6 {
		if len(inner) < 48 || inner[6] != 44 {
			return fragment{}, false
		}
		end := 40 + int(binary.BigEndian.Uint16(inner[4:6]))
		fo := binary.BigEndian.Uint16(inner[42:44])
		return fragment{offset: int(fo & 0xFFF8), more: fo&1 != 0, data: inner[48:min(end, len(inner))]}, true
	}
	if len(inner) < 20 {
		return fragment{}, false
	}
	ihl := int(inner[0]&0xF) * 4
	end := int(binary.BigEndian.Uint16(inner[2:4]))
	fo := binary.BigEndian.Uint16(inner[6:8])
	if fo&0x3FFF == 0 {
		return fragment{}, false
	}
	return fragment{offset: int(fo&0x1FFF) * 8, more: fo&0x2000 != 0, data: inner[ihl:min(end, len(inner))]}, true
}

// TestFragmentedReply checks that a reply too large for the veth MTU —
// fragmented by the backend's own stack — makes it back in full: only the
// first fragment carries the UDP header a flow_state key needs, so every
// later fragment has to be matched through frag_state (see _encap.c).
func TestFragmentedReply(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	// Each reply is three copies of its request: 4000 bytes in, 12000 out —
	// over the veth's 8500-byte MTU, so the backend fragments it.
	one := provisionEndpoint(t, gwlbID, true, echoServerPort, func(b []byte) []byte { return bytes.Repeat(b, 3) })
	fd := openGWLBSocket(t, gwlbIface)

	payload := bytes.Repeat([]byte("0123456789abcdef"), 250) // 4000 bytes
	want := bytes.Repeat(payload, 3)

	for _, v6 := range []bool{false, true} {
		name := map[bool]string{false: "ipv4", true: "ipv6"}[v6]
		t.Run(name, func(t *testing.T) {
			var inner []byte
			var err error
			ethertype := layers.EthernetTypeIPv4
			if v6 {
				ethertype = layers.EthernetTypeIPv6
				inner, err = buildInnerUDPv6(net.ParseIP(fakeClientIP6), net.ParseIP(echoServerIP6), fakeClientPort, echoServerPort, payload)
			} else {
				inner, err = buildInnerUDPv4(net.ParseIP(fakeClientIP), net.ParseIP(echoServerIP), fakeClientPort, echoServerPort, payload)
			}
			if err != nil {
				t.Fatalf("building the inner request failed: %v", err)
			}
			frame := innerRequestFrame(t, uplinkIface, gwlbIface, gwlbID, fakeFlowCookie, inner, ethertype)
			reqOpts, _, _, err := geneveInner(frame)
			if err != nil {
				t.Fatalf("parsing our own request frame failed: %v", err)
			}

			okBefore := metricSum(t, "encap_ok_packets", one.outerIfindex)
			missBefore := metricSum(t, "encap_drop_flow_miss_packets", one.outerIfindex)
			sendFrame(t, fd, gwlbIface, frame)

			// Reassemble by offset until the last fragment and every byte
			// before it have arrived.
			datagram := make([]byte, 8+len(want))
			have := make([]bool, len(datagram))
			frags, total := 0, -1
			complete := func() bool {
				if total < 0 {
					return false
				}
				for _, h := range have[:total] {
					if !h {
						return false
					}
				}
				return true
			}
			done := collectReplies(t, fd, uplinkIface.HardwareAddr, 5*time.Second, func(f []byte) bool {
				opts, in, checksumOK, err := geneveInner(f)
				if err != nil {
					return false
				}
				fr, ok := parseFragment(in, v6)
				if !ok {
					t.Errorf("got an unfragmented reply (%d bytes), want fragments", len(in))
					return true
				}
				frags++
				if !bytes.Equal(opts, reqOpts) {
					t.Errorf("fragment at offset %d: GENEVE options = %x, want %x", fr.offset, opts, reqOpts)
				}
				if !checksumOK {
					t.Errorf("fragment at offset %d: outer IP header checksum is invalid", fr.offset)
				}
				if fr.offset+len(fr.data) > len(datagram) {
					t.Errorf("fragment at offset %d overruns the %d-byte datagram", fr.offset, len(datagram))
					return true
				}
				copy(datagram[fr.offset:], fr.data)
				for i := range fr.data {
					have[fr.offset+i] = true
				}
				if !fr.more {
					total = fr.offset + len(fr.data)
				}
				return complete()
			})
			if !done {
				t.Fatalf("reply not fully reassembled within 5s: %d fragments seen, last fragment seen=%v (encap_drop_flow_miss_packets %d -> %d)",
					frags, total >= 0, missBefore, metricSum(t, "encap_drop_flow_miss_packets", one.outerIfindex))
			}
			if frags < 2 {
				t.Errorf("reply arrived in %d fragment(s), want at least 2 — test isn't exercising fragmentation", frags)
			}
			if total != len(datagram) {
				t.Fatalf("reassembled datagram is %d bytes, want %d", total, len(datagram))
			}
			if sp, dp := binary.BigEndian.Uint16(datagram[0:2]), binary.BigEndian.Uint16(datagram[2:4]); sp != echoServerPort || dp != fakeClientPort {
				t.Errorf("reassembled UDP ports = %d -> %d, want %d -> %d", sp, dp, echoServerPort, fakeClientPort)
			}
			if !bytes.Equal(datagram[8:], want) {
				t.Error("reassembled UDP payload doesn't match the backend's reply")
			}

			if got := metricSum(t, "encap_ok_packets", one.outerIfindex); got != okBefore+uint64(frags) {
				t.Errorf("encap_ok_packets = %d, want %d", got, okBefore+uint64(frags))
			}
			if got := metricSum(t, "encap_drop_flow_miss_packets", one.outerIfindex); got != missBefore {
				t.Errorf("encap_drop_flow_miss_packets = %d, want %d (unchanged)", got, missBefore)
			}
		})
	}
}

// TestDecapOversizeDropped checks that an inner packet larger than one
// GENEVE packet on the uplink can carry (9001 - 68 = 8933 bytes) — what
// several GRO-merged GENEVE packets would look like to decap — is dropped
// and counted, rather than redirected onto a veth that would drop it
// silently. The GWLB side of the simulated uplink gets a larger MTU so it
// can send such a frame at all; the uplink end still accepts it, since veth
// allows a VLAN tag's worth of slack.
func TestDecapOversizeDropped(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)

	uplinkIface, gwlbIface := setupUplink(t)
	gwlbLink, err := netlink.LinkByName(gwlbIfName)
	if err != nil {
		t.Fatalf("netlink.LinkByName failed: %v", err)
	}
	if err := netlink.LinkSetMTU(gwlbLink, 9100); err != nil {
		t.Fatalf("netlink.LinkSetMTU failed: %v", err)
	}
	runSetup(t, 8)
	one := provisionEndpoint(t, gwlbID, true, echoServerPort, bytes.Clone)
	fd := openGWLBSocket(t, gwlbIface)

	// 20 + 8 + 8907 = an 8935-byte inner packet, 2 over the limit.
	payload := make([]byte, 8907)
	frame, _ := sendGENEVE(t, fd, uplinkIface, gwlbIface, gwlbID, payload)
	if reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 2*time.Second); reply != nil {
		t.Fatalf("got a GENEVE reply for an oversize inner packet, want none")
	}
	if got := metricSum(t, "decap_drop_oversize_packets", one.outerIfindex); got != 1 {
		t.Errorf("decap_drop_oversize_packets[outer ifindex] = %d, want 1", got)
	}
	if got := metricSum(t, "decap_drop_oversize_bytes", one.outerIfindex); got != uint64(len(frame)) {
		t.Errorf("decap_drop_oversize_bytes[outer ifindex] = %d, want %d", got, len(frame))
	}
	if got := metricSum(t, "decap_ok_packets", one.outerIfindex); got != 0 {
		t.Errorf("decap_ok_packets[outer ifindex] = %d, want 0", got)
	}
}

// fragmentInner splits inner — a whole IPv4 or IPv6 packet with no options
// or extension headers — into fragments whose packets are at most firstLen
// bytes, the way GWLB fragments a packet too large for it: fragment payloads
// 8-byte aligned, and for IPv4 the original DF bit kept on every fragment,
// DF and MF together on all but the last.
func fragmentInner(t *testing.T, inner []byte, v6 bool, firstLen int, id uint32) [][]byte {
	t.Helper()
	hdrLen := 20
	if v6 {
		hdrLen = 40 + 8 // plus the fragment header each fragment gains
	}
	payload := inner[20:]
	if v6 {
		payload = inner[40:]
	}
	chunk := (firstLen - hdrLen) &^ 7

	var frags [][]byte
	for off := 0; off < len(payload); off += chunk {
		end := min(off+chunk, len(payload))
		more := end < len(payload)
		var f []byte
		if v6 {
			f = make([]byte, 48+end-off)
			copy(f, inner[:40])
			binary.BigEndian.PutUint16(f[4:6], uint16(8+end-off))
			f[6] = 44 // next header: fragment
			f[40] = inner[6]
			fo := uint16(off)
			if more {
				fo |= 1
			}
			binary.BigEndian.PutUint16(f[42:44], fo)
			binary.BigEndian.PutUint32(f[44:48], id)
			copy(f[48:], payload[off:end])
		} else {
			f = make([]byte, 20+end-off)
			copy(f, inner[:20])
			binary.BigEndian.PutUint16(f[2:4], uint16(len(f)))
			binary.BigEndian.PutUint16(f[4:6], uint16(id))
			fo := uint16(off/8) | 0x4000 // DF, kept on every fragment
			if more {
				fo |= 0x2000
			}
			binary.BigEndian.PutUint16(f[6:8], fo)
			f[10], f[11] = 0, 0
			var sum uint32
			for i := 0; i < 20; i += 2 {
				sum += uint32(binary.BigEndian.Uint16(f[i : i+2]))
			}
			for sum>>16 != 0 {
				sum = (sum & 0xFFFF) + (sum >> 16)
			}
			binary.BigEndian.PutUint16(f[10:12], ^uint16(sum))
			copy(f[20:], payload[off:end])
		}
		frags = append(frags, f)
	}
	return frags
}

// TestLargeRequests checks that decap delivers everything the uplink can
// carry, not just GWLB's documented 8500 bytes, to an endpoint added with --mtu
// at the uplink's limit (the default 8500 would drop these at the veth): a
// whole inner packet at that limit, and a datagram arriving as fragments
// sized the way GWLB fragments a packet too large for it (an 8812-byte first
// fragment, DF kept on both). For the fragmented requests, the backend's short reply can only
// be matched if decap cached the flow from the first fragment's real
// transport header — for IPv6, the one behind its fragment header.
func TestLargeRequests(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)
	const replyLen = 16

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	one := provisionEndpointWith(t, gwlbID, true, "", 9001-bpf.GeneveOverhead, echoServerPort, func(b []byte) []byte { return bytes.Clone(b[:min(len(b), replyLen)]) })
	fd := openGWLBSocket(t, gwlbIface)

	cases := []struct {
		name        string
		v6          bool
		payloadLen  int
		fragmentLen int // 0: send whole
	}{
		// 20 + 8 + 8905 = 8933 bytes: exactly 9001 - 68.
		{"whole packet at the uplink limit", false, 8905, 0},
		{"GWLB-style fragments ipv4", false, 12000, 8812},
		{"GWLB-style fragments ipv6", true, 12000, 8812},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.payloadLen)
			for j := range payload {
				payload[j] = byte(j*13 + i)
			}
			var inner []byte
			var err error
			ethertype := layers.EthernetTypeIPv4
			if tc.v6 {
				ethertype = layers.EthernetTypeIPv6
				inner, err = buildInnerUDPv6(net.ParseIP(fakeClientIP6), net.ParseIP(echoServerIP6), fakeClientPort, echoServerPort, payload)
			} else {
				inner, err = buildInnerUDPv4(net.ParseIP(fakeClientIP), net.ParseIP(echoServerIP), fakeClientPort, echoServerPort, payload)
			}
			if err != nil {
				t.Fatalf("building the inner request failed: %v", err)
			}
			pkts := [][]byte{inner}
			if tc.fragmentLen != 0 {
				pkts = fragmentInner(t, inner, tc.v6, tc.fragmentLen, uint32(0x4242+i))
				if len(pkts) < 2 || len(pkts[0]) > tc.fragmentLen {
					t.Fatalf("fragmentInner made %d fragments, first %d bytes; want 2+, first at most %d", len(pkts), len(pkts[0]), tc.fragmentLen)
				}
			}

			var reqOpts []byte
			okBefore := metricSum(t, "decap_ok_packets", one.outerIfindex)
			for _, p := range pkts {
				frame := innerRequestFrame(t, uplinkIface, gwlbIface, gwlbID, fakeFlowCookie, p, ethertype)
				if reqOpts, _, _, err = geneveInner(frame); err != nil {
					t.Fatalf("parsing our own request frame failed: %v", err)
				}
				sendFrame(t, fd, gwlbIface, frame)
			}

			var reply []byte
			var opts []byte
			if !collectReplies(t, fd, uplinkIface.HardwareAddr, 5*time.Second, func(f []byte) bool {
				o, in, _, err := geneveInner(f)
				if err != nil {
					return false
				}
				opts, reply = o, in
				return true
			}) {
				t.Fatalf("no reply observed within 5s (decap_ok_packets %d -> %d, decap_drop_oversize_packets %d, encap_drop_flow_miss_packets %d)",
					okBefore, metricSum(t, "decap_ok_packets", one.outerIfindex),
					metricSum(t, "decap_drop_oversize_packets", one.outerIfindex),
					metricSum(t, "encap_drop_flow_miss_packets", one.outerIfindex))
			}
			if got := metricSum(t, "decap_ok_packets", one.outerIfindex); got != okBefore+uint64(len(pkts)) {
				t.Errorf("decap_ok_packets = %d, want %d", got, okBefore+uint64(len(pkts)))
			}
			if !bytes.Equal(opts, reqOpts) {
				t.Errorf("reply GENEVE options = %x, want %x", opts, reqOpts)
			}
			udpOff := 20
			if tc.v6 {
				udpOff = 40
			}
			if len(reply) != udpOff+8+replyLen || !bytes.Equal(reply[udpOff+8:], payload[:replyLen]) {
				t.Errorf("reply = %x, want a UDP datagram carrying %x", reply, payload[:replyLen])
			}
		})
	}
	if got := metricSum(t, "decap_drop_oversize_packets", one.outerIfindex); got != 0 {
		t.Errorf("decap_drop_oversize_packets = %d, want 0", got)
	}
}

// TestEncapOversizeDropped checks that a reply too large to leave the uplink
// once encapsulated is dropped and counted by encap. That can only happen
// once the uplink's MTU has shrunk since `setup` (which fixed encap's limit)
// while the endpoint's veth was sized from a larger one: here setup sees a
// 1500-byte uplink (limit 1500 - 68 = 1432) and add a 9001-byte one (veth
// 8500), so the backend's 2028-byte reply crosses the veth whole.
func TestEncapOversizeDropped(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)

	uplinkIface, gwlbIface := setupUplink(t)
	uplink, err := netlink.LinkByName(uplinkIfName)
	if err != nil {
		t.Fatalf("netlink.LinkByName failed: %v", err)
	}
	if err := netlink.LinkSetMTU(uplink, 1500); err != nil {
		t.Fatalf("netlink.LinkSetMTU failed: %v", err)
	}
	runSetup(t, 8)
	if err := netlink.LinkSetMTU(uplink, 9001); err != nil {
		t.Fatalf("netlink.LinkSetMTU failed: %v", err)
	}
	one := provisionEndpoint(t, gwlbID, true, echoServerPort, func(b []byte) []byte { return bytes.Repeat(b, 2) })
	fd := openGWLBSocket(t, gwlbIface)

	payload := make([]byte, 1000) // reply: 20 + 8 + 2000 = 2028 bytes
	sendGENEVE(t, fd, uplinkIface, gwlbIface, gwlbID, payload)
	if reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 2*time.Second); reply != nil {
		t.Fatalf("got a GENEVE reply too large for the uplink, want none")
	}
	if got := metricSum(t, "decap_ok_packets", one.outerIfindex); got != 1 {
		t.Errorf("decap_ok_packets[outer ifindex] = %d, want 1 (the request itself fits)", got)
	}
	if got := metricSum(t, "encap_drop_oversize_packets", one.outerIfindex); got != 1 {
		t.Errorf("encap_drop_oversize_packets[outer ifindex] = %d, want 1", got)
	}
	if got, want := metricSum(t, "encap_drop_oversize_bytes", one.outerIfindex), uint64(14+20+8+2000); got != want {
		t.Errorf("encap_drop_oversize_bytes[outer ifindex] = %d, want %d", got, want)
	}
	if got := metricSum(t, "encap_ok_packets", one.outerIfindex); got != 0 {
		t.Errorf("encap_ok_packets[outer ifindex] = %d, want 0", got)
	}
}

// TestTCPBulkReply drives a real TCP connection to a server in the endpoint's
// netns and has it send a burst far larger than one segment, well within its
// initial congestion window. With TSO/GSO
// left on the veth, that burst would reach encap as GSO super-packets —
// encapsulated as one oversized frame each and then dropped on the way out
// the uplink. With them off (see disableVethOffloads in cmd/add.go), the
// netns stack segments it first, and every byte arrives in wire-sized,
// individually encapsulated segments.
func TestTCPBulkReply(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)
	const (
		tcpPort   = 18080
		bulkLen   = 60000
		clientISN = 1000
		mss       = bpf.GWLBMTU - 40 // what the veth's MTU gives it
	)

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	one := provisionEndpoint(t, gwlbID, true, echoServerPort, bytes.Clone)
	fd := openGWLBSocket(t, gwlbIface)

	bulk := make([]byte, bulkLen)
	for i := range bulk {
		bulk[i] = byte(i * 7)
	}

	var ln net.Listener
	inEndpointNetns(t, gwlbID, func() error {
		var err error
		ln, err = net.Listen("tcp4", net.JoinHostPort(echoServerIP, "18080"))
		return err
	})
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write(bulk)
		accepted <- conn
	}()
	t.Cleanup(func() {
		ln.Close()
		select {
		case conn := <-accepted:
			conn.Close()
		default:
		}
	})

	send := func(s tcpSegment) {
		t.Helper()
		s.srcIP, s.dstIP = net.ParseIP(fakeClientIP), net.ParseIP(echoServerIP)
		s.srcPort, s.dstPort = fakeClientPort, tcpPort
		s.window = 65535
		inner, err := buildInnerTCPv4(s)
		if err != nil {
			t.Fatalf("buildInnerTCPv4 failed: %v", err)
		}
		sendFrame(t, fd, gwlbIface, innerRequestFrame(t, uplinkIface, gwlbIface, gwlbID, fakeFlowCookie, inner, layers.EthernetTypeIPv4))
	}
	// replyTCP decodes an encapsulated reply's inner TCP segment.
	replyTCP := func(f []byte) (*layers.TCP, int, bool) {
		_, in, _, err := geneveInner(f)
		if err != nil {
			return nil, 0, false
		}
		p := gopacket.NewPacket(in, layers.LayerTypeIPv4, gopacket.Default)
		tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
		return tcp, len(in), ok
	}

	send(tcpSegment{seq: clientISN, syn: true, mss: mss})
	var serverISN uint32
	if !collectReplies(t, fd, uplinkIface.HardwareAddr, 5*time.Second, func(f []byte) bool {
		tcp, _, ok := replyTCP(f)
		if ok && tcp.SYN && tcp.ACK && tcp.Ack == clientISN+1 {
			serverISN = tcp.Seq
			return true
		}
		return false
	}) {
		t.Fatal("no SYN-ACK observed within 5s")
	}
	send(tcpSegment{seq: clientISN + 1, ack: serverISN + 1, ackFlag: true})

	got := make([]byte, bulkLen)
	have := make([]bool, bulkLen)
	segments, acked := 0, 0
	if !collectReplies(t, fd, uplinkIface.HardwareAddr, 10*time.Second, func(f []byte) bool {
		tcp, innerLen, ok := replyTCP(f)
		if !ok || len(tcp.Payload) == 0 {
			return false
		}
		segments++
		if len(f) > 9001+14 {
			t.Errorf("encapsulated segment is a %d-byte frame, over the uplink's 9001-byte MTU", len(f))
		}
		if innerLen > bpf.GWLBMTU {
			t.Errorf("inner segment is %d bytes, over the veth's %d-byte MTU", innerLen, bpf.GWLBMTU)
		}
		off := int(tcp.Seq - serverISN - 1)
		if off < 0 || off+len(tcp.Payload) > bulkLen {
			t.Errorf("segment at offset %d (%d bytes) is outside the %d-byte burst", off, len(tcp.Payload), bulkLen)
			return true
		}
		copy(got[off:], tcp.Payload)
		for i := range tcp.Payload {
			have[off+i] = true
		}
		// ACK everything received contiguously so far, like a real client:
		// without ACKs the server may hold back a short final segment
		// (TSO deferral) until its retransmit timer fires.
		prefix := 0
		for prefix < bulkLen && have[prefix] {
			prefix++
		}
		if prefix > acked {
			acked = prefix
			send(tcpSegment{seq: clientISN + 1, ack: serverISN + 1 + uint32(acked), ackFlag: true})
		}
		return acked == bulkLen
	}) {
		n := 0
		for _, h := range have {
			if h {
				n++
			}
		}
		stats, _ := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
		t.Fatalf("only %d of %d bytes arrived within 10s, over %d segments (encap_ok_packets=%d, encap_drop_oversize_packets=%d, packet socket stats=%+v)",
			n, bulkLen, segments, metricSum(t, "encap_ok_packets", one.outerIfindex),
			metricSum(t, "encap_drop_oversize_packets", one.outerIfindex), stats)
	}
	if !bytes.Equal(got, bulk) {
		t.Error("received bytes don't match what the server sent")
	}
	if segments < 2 {
		t.Errorf("burst arrived in %d segment(s), want several", segments)
	}
}
