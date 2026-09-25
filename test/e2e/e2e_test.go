//go:build e2e

package e2e

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gopacket/gopacket/layers"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
	"github.com/lyoung-confluent/gwlb-xdp/cmd"
)

// flowStateCount returns the number of live entries in the pinned flow_state
// map. Walking the whole map is fine at test scale.
func flowStateCount(t *testing.T) int {
	t.Helper()
	return len(flowStateIfindexes(t))
}

// flowStateCountFor returns how many live flow_state entries are keyed by
// ifindex — used to assert `remove` sweeps exactly one ENI's cached flows
// (see TestRemove).
func flowStateCountFor(t *testing.T, ifindex uint32) int {
	t.Helper()
	var n int
	for _, i := range flowStateIfindexes(t) {
		if i == ifindex {
			n++
		}
	}
	return n
}

// flowStateIfindexes returns the ifindex (struct flow_key's leading field)
// of every live flow_state entry.
func flowStateIfindexes(t *testing.T) []uint32 {
	t.Helper()
	m, err := ebpf.LoadPinnedMap(bpf.PinDir+"/flow_state", nil)
	if err != nil {
		t.Fatalf("loading pinned flow_state map failed: %v", err)
	}
	defer m.Close()

	var ifindexes []uint32
	var key interface{}
	for {
		next, err := m.NextKeyBytes(key)
		if err != nil {
			t.Fatalf("(*ebpf.Map).NextKeyBytes for flow_state failed: %v", err)
		}
		if next == nil {
			return ifindexes
		}
		key = next
		ifindexes = append(ifindexes, binary.NativeEndian.Uint32(next[:4]))
	}
}

// Two real veth pairs stand in for the two links gwlb-xdp actually drives:
//
//	uplinkIfName <-> gwlbIfName   simulates the physical uplink to a GWLB —
//	                              gwlbIfName plays the GWLB itself, sending
//	                              the synthetic GENEVE request and capturing
//	                              the reply over a raw socket.
//	(created by cmd.RunAdd)       simulates one ENI's veth pair; its netns
//	                              side runs a real UDP echo server standing
//	                              in for the appliance/backend.
const (
	uplinkIfName = "e2e-uplink"
	gwlbIfName   = "e2e-gwlb"

	echoServerIP   = "192.0.2.10"
	fakeClientIP   = "192.0.2.1"
	echoServerPort = 17777
	fakeClientPort = 54321

	// IPv6 counterparts, for the inner-IPv6 data path (TestEndToEndV6).
	// provisionENI configures these alongside the v4 addressing on every ENI,
	// so the same backend answers both families.
	echoServerIP6 = "2001:db8::10"
	fakeClientIP6 = "2001:db8::1"

	fakeGWLBOuterSrcIP = "198.51.100.1" // stands in for the real GWLB's own IP
	fakeGWLBOuterDstIP = "198.51.100.2" // stands in for this box's IP
	fakeOuterSrcPort   = 12345

	// decap now drops any packet whose attachment ID or GENEVE VNI isn't
	// exactly 0 (see _decap.c), so both must stay 0 for every frame these
	// tests expect to actually reach a backend.
	fakeAttachmentID = 0
	fakeFlowCookie   = 0x11223344

	unknownGWLBID = 0xBAD // never provisioned — see the "unknown ENI" subtest
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func requireRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("e2e test needs real netns/veth/XDP support, linux only")
	}
	if os.Geteuid() != 0 {
		t.Skip("e2e test needs CAP_NET_ADMIN/CAP_SYS_ADMIN/CAP_BPF — run as root (see `make e2e`)")
	}
}

// setupUplink creates the veth pair standing in for the physical uplink
// (uplinkIfName) and the GWLB's own side of that link (gwlbIfName), brings
// both up, and returns them. Deleting uplinkIfName also removes its peer.
func setupUplink(t *testing.T) (uplinkIface, gwlbIface *net.Interface) {
	t.Helper()

	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: uplinkIfName, MTU: 9001},
		PeerName:  gwlbIfName,
		PeerMTU:   9001,
	}); err != nil {
		t.Fatalf("netlink.LinkAdd for %s/%s failed: %v", uplinkIfName, gwlbIfName, err)
	}
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(uplinkIfName); err == nil {
			_ = netlink.LinkDel(link) // also removes the gwlbIfName peer
		}
	})
	for _, name := range [...]string{uplinkIfName, gwlbIfName} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("netlink.LinkByName(%q) failed: %v", name, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatalf("netlink.LinkSetUp(%q) failed: %v", name, err)
		}
	}

	uplinkIface, err := net.InterfaceByName(uplinkIfName)
	if err != nil {
		t.Fatalf("net.InterfaceByName(%q) failed: %v", uplinkIfName, err)
	}
	gwlbIface, err = net.InterfaceByName(gwlbIfName)
	if err != nil {
		t.Fatalf("net.InterfaceByName(%q) failed: %v", gwlbIfName, err)
	}
	return uplinkIface, gwlbIface
}

// runSetup runs `setup` against uplinkIfName, exactly as the CLI itself
// would, and registers `teardown` to reverse it.
func runSetup(t *testing.T, maxENIs uint32) {
	t.Helper()
	if err := cmd.RunSetup(uplinkIfName, maxENIs, 64, false, ""); err != nil {
		t.Fatalf("cmd.RunSetup failed: %v", err)
	}
	t.Cleanup(func() {
		if err := cmd.RunTeardown(); err != nil {
			t.Errorf("cmd.RunTeardown failed: %v", err)
		}
	})
}

// openGWLBSocket opens the raw AF_PACKET socket standing in for the real
// GWLB, bound to gwlbIface — used to send synthetic tunnel packets and
// capture whatever comes back.
func openGWLBSocket(t *testing.T, gwlbIface *net.Interface) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatalf("unix.Socket failed: %v", err)
	}
	t.Cleanup(func() { unix.Close(fd) })

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  gwlbIface.Index,
	}); err != nil {
		t.Fatalf("unix.Bind failed: %v", err)
	}
	// Room for a burst of jumbo replies (see TestTCPBulkReply): the default
	// receive buffer holds only a handful of ~9KB frames, and anything past
	// it is dropped before the test ever reads it.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 8<<20); err != nil {
		t.Fatalf("unix.SetsockoptInt(SO_RCVBUFFORCE) failed: %v", err)
	}
	return fd
}

// eni holds what tests need in order to address one provisioned ENI: its
// GWLB-visible ID and the ifindex decap_ok/encap_ok metrics are keyed by
// (its veth-outer, in the root netns — see the comment inside provisionENI).
type eni struct {
	gwlbID       uint64
	outerIfindex uint32
}

// backendAddr describes one address family's worth of an ENI's backend: the
// echo server's own address, the CIDR to assign it on veth-inner, and the
// net.ListenUDP network to serve on. provisionENI configures every ENI with
// both v4 and v6 so the same backend answers either family (see TestEndToEnd
// vs TestEndToEndV6).
type backendAddr struct {
	network string // "udp4" / "udp6", for net.ListenUDP
	family  int    // netlink.FAMILY_V4 / netlink.FAMILY_V6
	cidr    string // echo address + prefix, e.g. "192.0.2.10/24"
	echoIP  string
	nodad   bool // skip IPv6 DAD so the address is usable immediately
}

var backendAddrs = []backendAddr{
	{"udp4", netlink.FAMILY_V4, echoServerIP + "/24", echoServerIP, false},
	{"udp6", netlink.FAMILY_V6, echoServerIP6 + "/64", echoServerIP6, true},
}

// provisionENI runs `add` for gwlbID — into a dedicated netns when isolated
// is true (the normal case), or leaving its veth pair in the root netns
// (--no-netns) when false — and starts a real UDP echo server (one per address
// family, see backendAddrs) on its veth-inner at echoPort, standing in for the
// backend/appliance. Each received datagram's payload is passed through
// transform before being echoed back, so a test can tell which ENI's backend
// actually answered — pass bytes.Clone (or similar) for a plain echo.
//
// The veth pair gets add's default MTU (bpf.GWLBMTU), so the backend's own
// traffic is sized to GWLB's documented MTU with no route MTU needed.
//
// No neighbor entry is pinned for the client address, even though it's
// on-link and nothing will ever answer ARP/ND for it: `add` turns ARP off on
// veth-inner, so the echo server's reply needs none (see cmd/add.go).
func provisionENI(t *testing.T, gwlbID uint64, isolated bool, echoPort int, transform func([]byte) []byte) eni {
	t.Helper()
	return provisionENIWith(t, gwlbID, isolated, "", 0, echoPort, transform)
}

// provisionENIWith is provisionENI, passing scriptPath to `add` as its
// --script and mtu as its --mtu (0 for the default).
func provisionENIWith(t *testing.T, gwlbID uint64, isolated bool, scriptPath string, mtu int, echoPort int, transform func([]byte) []byte) eni {
	t.Helper()

	vpceID := cmd.FormatVPCEID(gwlbID)
	if err := cmd.RunAdd(vpceID, scriptPath, isolated, mtu); err != nil {
		t.Fatalf("cmd.RunAdd(%q, isolated=%v) failed: %v", vpceID, isolated, err)
	}

	// The veth-outer end never leaves the root netns, isolated or not (see
	// cmd/add.go) — this lookup always runs there. Its ifindex is what
	// decap_ok/encap_ok are keyed by (both are post-ENI-resolution
	// counters — see _decap.c/_encap.c), as opposed to the uplink's own
	// ifindex the pre-ENI drop counters use.
	outerName := cmd.FormatInterfaceName(gwlbID, false)
	innerName := cmd.FormatInterfaceName(gwlbID, true)
	outerIface, err := net.InterfaceByName(outerName)
	if err != nil {
		t.Fatalf("net.InterfaceByName(%q) failed: %v", outerName, err)
	}

	// nlh is the netlink handle addressing the inner veth's netns (a dedicated
	// one when isolated, the root netns otherwise), and inNetns runs fn with
	// the calling thread switched into that same netns so a socket opened
	// there lands on the inner veth. For --no-netns both are just "here".
	var nlh *netlink.Handle
	inNetns := func(fn func() error) error { return fn() }
	if isolated {
		ns, err := netns.GetFromName(vpceID)
		if err != nil {
			t.Fatalf("netns.GetFromName(%q) failed: %v", vpceID, err)
		}
		t.Cleanup(func() { ns.Close() })

		nlh, err = netlink.NewHandleAt(ns)
		if err != nil {
			t.Fatalf("netlink.NewHandleAt failed: %v", err)
		}
		t.Cleanup(func() { nlh.Close() })
		inNetns = func(fn func() error) error { return cmd.WithNetns(ns, fn) }
	} else {
		nlh, err = netlink.NewHandle()
		if err != nil {
			t.Fatalf("netlink.NewHandle failed: %v", err)
		}
		t.Cleanup(func() { nlh.Close() })
	}

	innerLink, err := nlh.LinkByName(innerName)
	if err != nil {
		t.Fatalf("(*netlink.Handle).LinkByName(%q) failed: %v", innerName, err)
	}

	for _, b := range backendAddrs {
		addr, err := netlink.ParseAddr(b.cidr)
		if err != nil {
			t.Fatalf("netlink.ParseAddr(%q) failed: %v", b.cidr, err)
		}
		if b.nodad {
			addr.Flags |= unix.IFA_F_NODAD
		}
		if err := nlh.AddrAdd(innerLink, addr); err != nil {
			t.Fatalf("(*netlink.Handle).AddrAdd(%q) failed: %v", b.cidr, err)
		}
		// The listening socket is created *inside* the netns via inNetns, but
		// a socket's netns membership is fixed at creation time — the
		// goroutine reading/writing it below runs in the root netns fine.
		var conn *net.UDPConn
		if err := inNetns(func() error {
			var err error
			conn, err = net.ListenUDP(b.network, &net.UDPAddr{IP: net.ParseIP(b.echoIP), Port: echoPort})
			return err
		}); err != nil {
			t.Fatalf("starting the %s echo server for %q failed: %v", b.network, vpceID, err)
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 65536)
			for {
				n, raddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, _ = conn.WriteToUDP(transform(buf[:n]), raddr)
			}
		}()
		t.Cleanup(func() {
			conn.Close()
			<-done
		})
	}

	return eni{gwlbID: gwlbID, outerIfindex: uint32(outerIface.Index)}
}

// metricSum returns counterName's summed per-CPU value for ifindex — 0 if
// that row doesn't exist yet, since bpf.Metrics only returns rows that have
// seen at least one packet (see increment_metric in bpf/maps.h).
func metricSum(t *testing.T, counterName string, ifindex uint32) uint64 {
	t.Helper()
	metrics, err := bpf.Metrics()
	if err != nil {
		t.Fatalf("bpf.Metrics failed: %v", err)
	}
	var sum uint64
	for _, m := range metrics[counterName] {
		if m.Ifindex == ifindex {
			for _, v := range m.PerCPU {
				sum += v
			}
		}
	}
	return sum
}

// waitForReply reads frames on fd until one whose outer source MAC is
// uplinkMAC turns up, or timeout elapses without one (returning nil). Our
// own request loops back to this same socket too (any packet socket bound
// to an interface sees traffic leaving it, same as tcpdump would) — the
// real reply is told apart from that by source MAC: the request's source is
// this harness's own address, while the reply's source is the request's own
// destination MAC (uplinkMAC), swapped into place by encap (see _encap.c) —
// there's no separately configured uplink MAC to set at `setup` anymore.
func waitForReply(t *testing.T, fd int, uplinkMAC net.HardwareAddr, timeout time.Duration) *replyPacket {
	t.Helper()
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		t.Fatalf("unix.SetsockoptTimeval failed: %v", err)
	}

	buf := make([]byte, maxFrameLen)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, err := unix.Read(fd, buf)
		if err != nil {
			// EINTR: a signal interrupted the blocking read before
			// SO_RCVTIMEO elapsed — just retry. EAGAIN/EWOULDBLOCK: that
			// timeout itself firing — let the loop's own deadline check
			// decide whether to give up.
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			t.Fatalf("waiting for a GENEVE reply failed: %v", err)
		}
		rp, err := parseReply(buf[:n])
		if err != nil || !bytes.Equal(rp.outerSrcMAC, uplinkMAC) {
			continue // not it — e.g. our own request, looped back
		}
		return rp
	}
	return nil
}

// waitForICMPReply is waitForReply's ICMP analogue, for TestICMPEcho — same
// loop, same "tell it apart from our own looped-back request by outer
// source MAC" logic, just parsing each frame as an ICMP reply instead of a
// UDP one.
func waitForICMPReply(t *testing.T, fd int, uplinkMAC net.HardwareAddr, timeout time.Duration) *icmpReplyPacket {
	t.Helper()
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
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
			t.Fatalf("waiting for a GENEVE ICMP reply failed: %v", err)
		}
		rp, err := parseICMPReply(buf[:n])
		if err != nil || !bytes.Equal(rp.outerSrcMAC, uplinkMAC) {
			continue // not it — e.g. our own request, looped back
		}
		return rp
	}
	return nil
}

// sendGENEVE builds a GENEVE request for gwlbID carrying payload from
// fakeClientIP:fakeClientPort to echoServerIP:echoServerPort, sends it on
// fd, and returns it alongside the frame's own bytes (callers need both the
// frame, e.g. for its length, and its options, e.g. to check verbatim
// replay).
func sendGENEVE(t *testing.T, fd int, uplinkIface, gwlbIface *net.Interface, gwlbID uint64, payload []byte) (frame, opts []byte) {
	t.Helper()
	frame, err := buildRequestFrame(requestParams{
		outerSrcMAC:  gwlbIface.HardwareAddr,
		outerDstMAC:  uplinkIface.HardwareAddr,
		outerSrcIP:   net.ParseIP(fakeGWLBOuterSrcIP),
		outerDstIP:   net.ParseIP(fakeGWLBOuterDstIP),
		outerSrcPort: fakeOuterSrcPort,
		vni:          [3]byte{0, 0, 0}, // decap drops any nonzero VNI now — see _decap.c
		opts:         buildGeneveOptions(gwlbID, fakeAttachmentID, fakeFlowCookie),
		innerSrcIP:   net.ParseIP(fakeClientIP),
		innerDstIP:   net.ParseIP(echoServerIP),
		innerSrcPort: fakeClientPort,
		innerDstPort: echoServerPort,
		payload:      payload,
	})
	if err != nil {
		t.Fatalf("buildRequestFrame failed: %v", err)
	}

	// Read the options back off the frame we're actually about to send,
	// rather than returning what we asked buildRequestFrame for — this is
	// what assertValidReply's "verbatim replay" check wants to compare
	// against (see replyPacket's type comment).
	self, err := parseReply(frame)
	if err != nil {
		t.Fatalf("parsing our own just-built request frame failed: %v", err)
	}

	if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: gwlbIface.Index}); err != nil {
		t.Fatalf("unix.Sendto failed: %v", err)
	}
	return frame, self.opts
}

// assertValidReply checks a captured reply against the request it answers:
// outer addressing swapped and GENEVE header/options replayed verbatim
// (both by encap, see _encap.c), its recomputed outer IP checksum is
// actually valid and its outer UDP checksum is zeroed as documented, inner
// packet is the echo server's own reply (to fakeClientIP:fakeClientPort
// from echoServerIP:echoServerPort — see sendGENEVE), and the payload
// matches what was sent.
func assertValidReply(t *testing.T, reply *replyPacket, gwlbIface *net.Interface, reqOpts, payload []byte) {
	t.Helper()
	if !bytes.Equal(reply.outerDstMAC, gwlbIface.HardwareAddr) {
		t.Errorf("reply outer dst MAC = %v, want %v (this harness's own)", reply.outerDstMAC, gwlbIface.HardwareAddr)
	}
	if !reply.outerSrcIP.Equal(net.ParseIP(fakeGWLBOuterDstIP)) || !reply.outerDstIP.Equal(net.ParseIP(fakeGWLBOuterSrcIP)) {
		t.Errorf("reply outer IPs = %s -> %s, want %s -> %s (swapped)",
			reply.outerSrcIP, reply.outerDstIP, fakeGWLBOuterDstIP, fakeGWLBOuterSrcIP)
	}
	if reply.outerDstPort != genevePort {
		t.Errorf("reply outer UDP dst port = %d, want %d", reply.outerDstPort, genevePort)
	}
	if !reply.outerIPChecksumValid {
		t.Error("reply outer IP header checksum is invalid (encap's recomputed ipv4_checksum, see _encap.c)")
	}
	if reply.outerUDPChecksum != 0 {
		t.Errorf("reply outer UDP checksum = %#04x, want 0 (zeroed by encap, see _encap.c)", reply.outerUDPChecksum)
	}
	// A fresh datagram's TTL, ECN, DF and ID, not the request's (see the
	// rewrite in _decap.c and requestOuterTTL/TOS/ID in packet.go).
	if reply.outerTTL != 64 {
		t.Errorf("reply outer TTL = %d, want 64 (not the request's %d)", reply.outerTTL, requestOuterTTL)
	}
	if want := uint8(requestOuterTOS &^ 0x03); reply.outerTOS != want {
		t.Errorf("reply outer TOS = %#02x, want %#02x (request's DSCP kept, its ECN CE mark cleared)", reply.outerTOS, want)
	}
	if reply.outerFlags != layers.IPv4DontFragment {
		t.Errorf("reply outer IP flags = %v, want DF only", reply.outerFlags)
	}
	if reply.outerID != 0 {
		t.Errorf("reply outer IP ID = %#04x, want 0 (not the request's %#04x)", reply.outerID, requestOuterID)
	}
	if !bytes.Equal(reply.opts, reqOpts) {
		t.Errorf("reply GENEVE options = %x, want %x (verbatim replay of the request's)", reply.opts, reqOpts)
	}
	if !reply.innerSrcIP.Equal(net.ParseIP(echoServerIP)) || !reply.innerDstIP.Equal(net.ParseIP(fakeClientIP)) {
		t.Errorf("reply inner IPs = %s -> %s, want %s -> %s",
			reply.innerSrcIP, reply.innerDstIP, echoServerIP, fakeClientIP)
	}
	if reply.innerSrcPort != echoServerPort || reply.innerDstPort != fakeClientPort {
		t.Errorf("reply inner ports = %d -> %d, want %d -> %d",
			reply.innerSrcPort, reply.innerDstPort, echoServerPort, fakeClientPort)
	}
	if !reply.innerIPChecksumValid {
		t.Error("reply inner IP header checksum is invalid")
	}
	if !bytes.Equal(reply.payload, payload) {
		t.Errorf("reply payload = %q, want %q", reply.payload, payload)
	}
}

// assertOKMetrics checks that decap/encap incremented exactly the "ok"
// counters for one request/reply exchange, on the ENI's own veth-outer
// ifindex — see increment_metric in bpf/maps.h and the comment on
// provisionENI's outerIface lookup. reqFrameLen is the request frame's own
// length (decap_ok_bytes' basis) and payloadLen is the echoed payload's
// length (part of encap_ok_bytes' basis).
func assertOKMetrics(t *testing.T, outerIfindex uint32, reqFrameLen, payloadLen int) {
	t.Helper()
	if got := metricSum(t, "decap_ok_packets", outerIfindex); got != 1 {
		t.Errorf("decap_ok_packets[outer ifindex] = %d, want 1", got)
	}
	if got := metricSum(t, "decap_ok_bytes", outerIfindex); got != uint64(reqFrameLen) {
		t.Errorf("decap_ok_bytes[outer ifindex] = %d, want %d (the request frame's own length, captured by decap before it strips anything — see _decap.c)",
			got, reqFrameLen)
	}
	if got := metricSum(t, "encap_ok_packets", outerIfindex); got != 1 {
		t.Errorf("encap_ok_packets[outer ifindex] = %d, want 1", got)
	}
	// encap counts the reply as it leaves the uplink: the inner
	// IP(20)/UDP(8)/payload the echo server sent, behind the full 82-byte
	// outer eth/IP/UDP/GENEVE header encap restored (see _encap.c) — the
	// same basis decap_ok_bytes uses for the request.
	wantEncapBytes := uint64(82 + 20 + 8 + payloadLen)
	if got := metricSum(t, "encap_ok_bytes", outerIfindex); got != wantEncapBytes {
		t.Errorf("encap_ok_bytes[outer ifindex] = %d, want %d", got, wantEncapBytes)
	}
}

// TestEndToEnd drives decap and encap together, without a real GWLB: it
// synthesizes an AWS GWLB GENEVE packet and sends it into a veth playing the
// uplink's role, lets decap/encap and a real UDP echo server (running in the
// ENI's own netns, standing in for the backend/appliance) carry it end to
// end, and checks the GENEVE reply that comes back out the same veth — plus
// the metrics that exchange should have moved, and four ways a bad packet is
// supposed to be dropped rather than answered.
func TestEndToEnd(t *testing.T) {
	requireRoot(t)

	// Best-effort: CI environments and the dev container may not have
	// bpffs mounted yet (see the Makefile's `verify` target for the same
	// step). Ignore the error — a missing/failed mount surfaces clearly
	// anyway the moment RunSetup tries to create the pin directory.
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	one := provisionENI(t, gwlbID, true, echoServerPort, func(b []byte) []byte { return b })
	fd := openGWLBSocket(t, gwlbIface)

	payload := []byte("hello from gwlb-xdp e2e test")
	reqFrame, reqOpts := sendGENEVE(t, fd, uplinkIface, gwlbIface, gwlbID, payload)

	// 5. Wait for the reply.
	reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 5*time.Second)
	if reply == nil {
		t.Fatal("no GENEVE reply observed on the simulated uplink within 5s")
	}

	// 6. The full round trip, and 7. the metrics that exchange should have
	// moved — see assertValidReply/assertOKMetrics.
	assertValidReply(t, reply, gwlbIface, reqOpts, payload)
	assertOKMetrics(t, one.outerIfindex, len(reqFrame), len(payload))

	// 8. Negative paths: decap should drop, not answer, a packet for an ENI
	// it never provisioned or one that fails its own structural checks —
	// each keyed by the *uplink's* ifindex, since these are pre-ENI-lookup
	// events (see ingress_ifindex's use in _decap.c).
	t.Run("unknown ENI is dropped", func(t *testing.T) {
		badOpts := buildGeneveOptions(unknownGWLBID, fakeAttachmentID, fakeFlowCookie)
		badFrame, err := buildRequestFrame(requestParams{
			outerSrcMAC:  gwlbIface.HardwareAddr,
			outerDstMAC:  uplinkIface.HardwareAddr,
			outerSrcIP:   net.ParseIP(fakeGWLBOuterSrcIP),
			outerDstIP:   net.ParseIP(fakeGWLBOuterDstIP),
			outerSrcPort: fakeOuterSrcPort,
			vni:          [3]byte{0, 0, 0}, // decap drops any nonzero VNI now — see _decap.c
			opts:         badOpts,
			innerSrcIP:   net.ParseIP(fakeClientIP),
			innerDstIP:   net.ParseIP(echoServerIP),
			innerSrcPort: fakeClientPort,
			innerDstPort: echoServerPort,
			payload:      payload,
		})
		if err != nil {
			t.Fatalf("buildRequestFrame failed: %v", err)
		}
		if err := unix.Sendto(fd, badFrame, 0, &unix.SockaddrLinklayer{Ifindex: gwlbIface.Index}); err != nil {
			t.Fatalf("unix.Sendto failed: %v", err)
		}
		if reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 2*time.Second); reply != nil {
			t.Fatalf("got a GENEVE reply for an unprovisioned ENI ID, want none: %+v", reply)
		}
		if got := metricSum(t, "decap_drop_unknown_eni_packets", uint32(uplinkIface.Index)); got != 1 {
			t.Errorf("decap_drop_unknown_eni_packets[uplink ifindex] = %d, want 1", got)
		}
		if got := metricSum(t, "decap_drop_unknown_eni_bytes", uint32(uplinkIface.Index)); got != uint64(len(badFrame)) {
			t.Errorf("decap_drop_unknown_eni_bytes[uplink ifindex] = %d, want %d", got, len(badFrame))
		}
	})

	t.Run("malformed GENEVE version is dropped", func(t *testing.T) {
		badFrame, err := buildRequestFrame(requestParams{
			outerSrcMAC:  gwlbIface.HardwareAddr,
			outerDstMAC:  uplinkIface.HardwareAddr,
			outerSrcIP:   net.ParseIP(fakeGWLBOuterSrcIP),
			outerDstIP:   net.ParseIP(fakeGWLBOuterDstIP),
			outerSrcPort: fakeOuterSrcPort,
			geneveVer:    1,                // decap only accepts ver == 0 — see _decap.c
			vni:          [3]byte{0, 0, 0}, // decap drops any nonzero VNI now — see _decap.c
			opts:         buildGeneveOptions(gwlbID, fakeAttachmentID, fakeFlowCookie),
			innerSrcIP:   net.ParseIP(fakeClientIP),
			innerDstIP:   net.ParseIP(echoServerIP),
			innerSrcPort: fakeClientPort,
			innerDstPort: echoServerPort,
			payload:      payload,
		})
		if err != nil {
			t.Fatalf("buildRequestFrame failed: %v", err)
		}
		if err := unix.Sendto(fd, badFrame, 0, &unix.SockaddrLinklayer{Ifindex: gwlbIface.Index}); err != nil {
			t.Fatalf("unix.Sendto failed: %v", err)
		}
		if reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 2*time.Second); reply != nil {
			t.Fatalf("got a GENEVE reply for a malformed (bad version) packet, want none: %+v", reply)
		}
		if got := metricSum(t, "decap_drop_malformed_packets", uint32(uplinkIface.Index)); got != 1 {
			t.Errorf("decap_drop_malformed_packets[uplink ifindex] = %d, want 1", got)
		}
		if got := metricSum(t, "decap_drop_malformed_bytes", uint32(uplinkIface.Index)); got != uint64(len(badFrame)) {
			t.Errorf("decap_drop_malformed_bytes[uplink ifindex] = %d, want %d", got, len(badFrame))
		}
	})

	t.Run("nonzero attachment ID is dropped", func(t *testing.T) {
		badFrame, err := buildRequestFrame(requestParams{
			outerSrcMAC:  gwlbIface.HardwareAddr,
			outerDstMAC:  uplinkIface.HardwareAddr,
			outerSrcIP:   net.ParseIP(fakeGWLBOuterSrcIP),
			outerDstIP:   net.ParseIP(fakeGWLBOuterDstIP),
			outerSrcPort: fakeOuterSrcPort,
			vni:          [3]byte{0, 0, 0},
			opts:         buildGeneveOptions(gwlbID, 0xAAAABBBBCCCCDDDD, fakeFlowCookie), // decap only accepts attachment ID 0 — see _decap.c
			innerSrcIP:   net.ParseIP(fakeClientIP),
			innerDstIP:   net.ParseIP(echoServerIP),
			innerSrcPort: fakeClientPort,
			innerDstPort: echoServerPort,
			payload:      payload,
		})
		if err != nil {
			t.Fatalf("buildRequestFrame failed: %v", err)
		}
		// decap_drop_malformed_* already carries the "malformed GENEVE
		// version" subtest's count above, so check the delta this send
		// causes rather than an absolute value.
		beforePackets := metricSum(t, "decap_drop_malformed_packets", uint32(uplinkIface.Index))
		beforeBytes := metricSum(t, "decap_drop_malformed_bytes", uint32(uplinkIface.Index))
		if err := unix.Sendto(fd, badFrame, 0, &unix.SockaddrLinklayer{Ifindex: gwlbIface.Index}); err != nil {
			t.Fatalf("unix.Sendto failed: %v", err)
		}
		if reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 2*time.Second); reply != nil {
			t.Fatalf("got a GENEVE reply for a nonzero attachment ID, want none: %+v", reply)
		}
		if got := metricSum(t, "decap_drop_malformed_packets", uint32(uplinkIface.Index)); got != beforePackets+1 {
			t.Errorf("decap_drop_malformed_packets[uplink ifindex] = %d, want %d", got, beforePackets+1)
		}
		if got := metricSum(t, "decap_drop_malformed_bytes", uint32(uplinkIface.Index)); got != beforeBytes+uint64(len(badFrame)) {
			t.Errorf("decap_drop_malformed_bytes[uplink ifindex] = %d, want %d", got, beforeBytes+uint64(len(badFrame)))
		}
	})

	t.Run("nonzero GENEVE VNI is dropped", func(t *testing.T) {
		badFrame, err := buildRequestFrame(requestParams{
			outerSrcMAC:  gwlbIface.HardwareAddr,
			outerDstMAC:  uplinkIface.HardwareAddr,
			outerSrcIP:   net.ParseIP(fakeGWLBOuterSrcIP),
			outerDstIP:   net.ParseIP(fakeGWLBOuterDstIP),
			outerSrcPort: fakeOuterSrcPort,
			vni:          [3]byte{0, 0, 1}, // decap only accepts VNI 0 — see _decap.c
			opts:         buildGeneveOptions(gwlbID, fakeAttachmentID, fakeFlowCookie),
			innerSrcIP:   net.ParseIP(fakeClientIP),
			innerDstIP:   net.ParseIP(echoServerIP),
			innerSrcPort: fakeClientPort,
			innerDstPort: echoServerPort,
			payload:      payload,
		})
		if err != nil {
			t.Fatalf("buildRequestFrame failed: %v", err)
		}
		beforePackets := metricSum(t, "decap_drop_malformed_packets", uint32(uplinkIface.Index))
		beforeBytes := metricSum(t, "decap_drop_malformed_bytes", uint32(uplinkIface.Index))
		if err := unix.Sendto(fd, badFrame, 0, &unix.SockaddrLinklayer{Ifindex: gwlbIface.Index}); err != nil {
			t.Fatalf("unix.Sendto failed: %v", err)
		}
		if reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 2*time.Second); reply != nil {
			t.Fatalf("got a GENEVE reply for a nonzero VNI, want none: %+v", reply)
		}
		if got := metricSum(t, "decap_drop_malformed_packets", uint32(uplinkIface.Index)); got != beforePackets+1 {
			t.Errorf("decap_drop_malformed_packets[uplink ifindex] = %d, want %d", got, beforePackets+1)
		}
		if got := metricSum(t, "decap_drop_malformed_bytes", uint32(uplinkIface.Index)); got != beforeBytes+uint64(len(badFrame)) {
			t.Errorf("decap_drop_malformed_bytes[uplink ifindex] = %d, want %d", got, beforeBytes+uint64(len(badFrame)))
		}
	})

	t.Run("outer first fragment is dropped", func(t *testing.T) {
		badFrame, err := buildRequestFrame(requestParams{
			outerSrcMAC:  gwlbIface.HardwareAddr,
			outerDstMAC:  uplinkIface.HardwareAddr,
			outerSrcIP:   net.ParseIP(fakeGWLBOuterSrcIP),
			outerDstIP:   net.ParseIP(fakeGWLBOuterDstIP),
			outerSrcPort: fakeOuterSrcPort,
			vni:          [3]byte{0, 0, 0},
			opts:         buildGeneveOptions(gwlbID, fakeAttachmentID, fakeFlowCookie),
			innerSrcIP:   net.ParseIP(fakeClientIP),
			innerDstIP:   net.ParseIP(echoServerIP),
			innerSrcPort: fakeClientPort + 1, // a flow of its own, not yet cached
			innerDstPort: echoServerPort,
			payload:      payload,
		})
		if err != nil {
			t.Fatalf("buildRequestFrame failed: %v", err)
		}
		// Set the outer header's MF flag (offset 0), making this the first
		// fragment of a GENEVE packet decap would only ever see part of.
		// decap never checks the outer IP checksum, so it isn't redone.
		binary.BigEndian.PutUint16(badFrame[14+6:], 0x2000)

		flowsBefore := flowStateCount(t)
		beforePackets := metricSum(t, "decap_drop_malformed_packets", uint32(uplinkIface.Index))
		if err := unix.Sendto(fd, badFrame, 0, &unix.SockaddrLinklayer{Ifindex: gwlbIface.Index}); err != nil {
			t.Fatalf("unix.Sendto failed: %v", err)
		}
		if reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 2*time.Second); reply != nil {
			t.Fatalf("got a GENEVE reply for an outer first fragment, want none: %+v", reply)
		}
		if got := metricSum(t, "decap_drop_malformed_packets", uint32(uplinkIface.Index)); got != beforePackets+1 {
			t.Errorf("decap_drop_malformed_packets[uplink ifindex] = %d, want %d", got, beforePackets+1)
		}
		if got := flowStateCount(t); got != flowsBefore {
			t.Errorf("flow_state has %d entries after an outer fragment, want %d (nothing cached for it)", got, flowsBefore)
		}
	})
}

// TestOriginFiltering exercises --allowed-origin-cidr (decap.Config's
// AllowedOriginCIDR, wired from cmd.RunSetup — see cmd/setup.go): a request
// whose outer source IP falls inside the configured CIDR should be answered
// exactly as if filtering were off, and one from outside it should be
// dropped and counted, never reaching decap's ENI lookup — same pre-ENI,
// uplink-ifindex-keyed shape as the other TestEndToEnd negative subtests.
func TestOriginFiltering(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xF17E5)

	uplinkIface, gwlbIface := setupUplink(t)
	// fakeGWLBOuterSrcIP (198.51.100.1) falls inside this /30.
	if err := cmd.RunSetup(uplinkIfName, 8, 64, false, "198.51.100.0/30"); err != nil {
		t.Fatalf("cmd.RunSetup failed: %v", err)
	}
	t.Cleanup(func() {
		if err := cmd.RunTeardown(); err != nil {
			t.Errorf("cmd.RunTeardown failed: %v", err)
		}
	})
	one := provisionENI(t, gwlbID, true, echoServerPort, func(b []byte) []byte { return b })
	fd := openGWLBSocket(t, gwlbIface)

	payload := []byte("hello from the origin filtering test")

	t.Run("allowed origin is answered", func(t *testing.T) {
		reqFrame, reqOpts := sendGENEVE(t, fd, uplinkIface, gwlbIface, gwlbID, payload)
		reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 5*time.Second)
		if reply == nil {
			t.Fatal("no GENEVE reply observed for an allowed origin within 5s")
		}
		assertValidReply(t, reply, gwlbIface, reqOpts, payload)
		assertOKMetrics(t, one.outerIfindex, len(reqFrame), len(payload))
	})

	t.Run("disallowed origin is dropped", func(t *testing.T) {
		badFrame, err := buildRequestFrame(requestParams{
			outerSrcMAC:  gwlbIface.HardwareAddr,
			outerDstMAC:  uplinkIface.HardwareAddr,
			outerSrcIP:   net.ParseIP("203.0.113.1"), // outside 198.51.100.0/30
			outerDstIP:   net.ParseIP(fakeGWLBOuterDstIP),
			outerSrcPort: fakeOuterSrcPort,
			vni:          [3]byte{0, 0, 0},
			opts:         buildGeneveOptions(gwlbID, fakeAttachmentID, fakeFlowCookie),
			innerSrcIP:   net.ParseIP(fakeClientIP),
			innerDstIP:   net.ParseIP(echoServerIP),
			innerSrcPort: fakeClientPort,
			innerDstPort: echoServerPort,
			payload:      payload,
		})
		if err != nil {
			t.Fatalf("buildRequestFrame failed: %v", err)
		}
		if err := unix.Sendto(fd, badFrame, 0, &unix.SockaddrLinklayer{Ifindex: gwlbIface.Index}); err != nil {
			t.Fatalf("unix.Sendto failed: %v", err)
		}
		if reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 2*time.Second); reply != nil {
			t.Fatalf("got a GENEVE reply for a disallowed origin, want none: %+v", reply)
		}
		if got := metricSum(t, "decap_drop_origin_not_allowed_packets", uint32(uplinkIface.Index)); got != 1 {
			t.Errorf("decap_drop_origin_not_allowed_packets[uplink ifindex] = %d, want 1", got)
		}
		if got := metricSum(t, "decap_drop_origin_not_allowed_bytes", uint32(uplinkIface.Index)); got != uint64(len(badFrame)) {
			t.Errorf("decap_drop_origin_not_allowed_bytes[uplink ifindex] = %d, want %d", got, len(badFrame))
		}
	})
}

// TestOverlappingCIDRIsolation provisions two ENIs (two distinct VPC
// endpoints) whose backends deliberately reuse the exact same address —
// something README.md calls out as only safe because each isolated ENI gets
// its own netns; nothing then keeps two --no-netns ENIs' routing tables
// apart if their backend addressing overlaps. It sends a request to each
// with an otherwise byte-identical inner 5-tuple (same client, same backend
// address and port — only the GENEVE ENI ID differs) and checks that each
// reply actually came from its own ENI's backend, not the other one's —
// proof that ifindex, folded into decap/encap's flow_state key (see
// bpf/geneve_defs.h), is really what keeps the two apart, not something
// coincidental about the addressing.
func TestOverlappingCIDRIsolation(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	fd := openGWLBSocket(t, gwlbIface)

	const (
		gwlbIDA = 0xE2E
		gwlbIDB = 0xE2F // a wholly different VPC endpoint
	)
	tag := func(prefix string) func([]byte) []byte {
		return func(b []byte) []byte { return append([]byte(prefix), b...) }
	}
	// Same echoServerIP:echoServerPort and on-link fakeClientIP for both
	// ENIs — only their own netns keeps that from colliding.
	eniA := provisionENI(t, gwlbIDA, true, echoServerPort, tag("A:"))
	eniB := provisionENI(t, gwlbIDB, true, echoServerPort, tag("B:"))
	if eniA.outerIfindex == eniB.outerIfindex {
		t.Fatalf("both ENIs resolved to the same veth-outer ifindex (%d) — test setup is broken", eniA.outerIfindex)
	}

	sendGENEVE(t, fd, uplinkIface, gwlbIface, gwlbIDA, []byte("hello"))
	replyA := waitForReply(t, fd, uplinkIface.HardwareAddr, 5*time.Second)
	if replyA == nil {
		t.Fatal("no GENEVE reply observed for ENI A within 5s")
	}

	// Identical inner tuple to A's request above — the only thing that
	// tells decap/encap these are two different tenants is the GENEVE ENI
	// ID (for decap's ENI lookup) and, from there on, the ifindex it maps
	// to (for both programs' flow_state key).
	sendGENEVE(t, fd, uplinkIface, gwlbIface, gwlbIDB, []byte("hello"))
	replyB := waitForReply(t, fd, uplinkIface.HardwareAddr, 5*time.Second)
	if replyB == nil {
		t.Fatal("no GENEVE reply observed for ENI B within 5s")
	}

	if got, want := string(replyA.payload), "A:hello"; got != want {
		t.Errorf("ENI A reply payload = %q, want %q (answered by the wrong backend?)", got, want)
	}
	if got, want := string(replyB.payload), "B:hello"; got != want {
		t.Errorf("ENI B reply payload = %q, want %q (answered by the wrong backend?)", got, want)
	}

	// And not just the payload: each ENI's own ifindex should show exactly
	// its own round trip in decap/encap's metrics, confirming the isolation
	// holds at the flow_state/metrics layer too, not only in what the
	// backends happened to reply with.
	for _, e := range [...]eni{eniA, eniB} {
		if got := metricSum(t, "decap_ok_packets", e.outerIfindex); got != 1 {
			t.Errorf("decap_ok_packets[ifindex %d, ENI %#x] = %d, want 1", e.outerIfindex, e.gwlbID, got)
		}
		if got := metricSum(t, "encap_ok_packets", e.outerIfindex); got != 1 {
			t.Errorf("encap_ok_packets[ifindex %d, ENI %#x] = %d, want 1", e.outerIfindex, e.gwlbID, got)
		}
	}
}

// TestNoNetns is TestEndToEnd's happy path run through `add --no-netns`
// instead: both ends of the ENI's veth pair stay in the root netns (see
// cmd.RunAdd's isolated parameter and README.md's note on --no-netns),
// rather than a dedicated one — the whole reason provisionENI takes an
// isolated flag. Nothing here should differ from the isolated case except
// where the ENI's own interfaces live; decap/encap don't know or care
// either way.
func TestNoNetns(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	one := provisionENI(t, gwlbID, false, echoServerPort, func(b []byte) []byte { return b })
	fd := openGWLBSocket(t, gwlbIface)

	// Confirm --no-netns actually took: no netns was created for this ENI
	// at all (as opposed to, say, the round trip below happening to work
	// even if isolated were silently ignored somewhere).
	vpceID := cmd.FormatVPCEID(gwlbID)
	if ns, err := netns.GetFromName(vpceID); err == nil {
		ns.Close()
		t.Fatalf("a netns named %q exists, want none — --no-netns should never create one", vpceID)
	}

	// Both veth ends got their ENI-derived MAC (see cmd.FormatInterfaceMAC),
	// explicitly assigned (NET_ADDR_SET, 3) rather than kernel-random
	// (NET_ADDR_RANDOM, 1), which systemd-udevd could replace after decap
	// cached it — see RunAdd. With --no-netns both ends are in this netns,
	// so both show up here.
	for _, inner := range []bool{false, true} {
		name := cmd.FormatInterfaceName(gwlbID, inner)
		iface, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatalf("net.InterfaceByName(%q) failed: %v", name, err)
		}
		if want := cmd.FormatInterfaceMAC(gwlbID, inner); !bytes.Equal(iface.HardwareAddr, want) {
			t.Errorf("%s MAC = %v, want %v", name, iface.HardwareAddr, want)
		}
		b, err := os.ReadFile("/sys/class/net/" + name + "/addr_assign_type")
		if err != nil {
			t.Fatalf("reading %s's addr_assign_type failed: %v", name, err)
		}
		if got := string(bytes.TrimSpace(b)); got != "3" {
			t.Errorf("%s addr_assign_type = %s, want 3 (NET_ADDR_SET)", name, got)
		}
	}

	payload := []byte("hello from gwlb-xdp e2e test (--no-netns)")
	reqFrame, reqOpts := sendGENEVE(t, fd, uplinkIface, gwlbIface, gwlbID, payload)

	reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 5*time.Second)
	if reply == nil {
		t.Fatal("no GENEVE reply observed on the simulated uplink within 5s")
	}

	assertValidReply(t, reply, gwlbIface, reqOpts, payload)
	assertOKMetrics(t, one.outerIfindex, len(reqFrame), len(payload))
}

// TestICMPEcho drives an ICMP echo request through decap and back through
// encap as an echo reply — decap/encap's ICMP support (parse_l4 in
// bpf/geneve_defs.h) keys the flow by the echo's own id, the same way a
// TCP/UDP flow is keyed by port. Nothing needs to run in the ENI's netns to
// answer the ping: the kernel replies on its own to an echo request
// addressed to any of its interfaces' own IPs, which is exactly what
// provisionENI's AddrAdd gives echoServerIP — so this needs no echo server,
// unlike TestEndToEnd's UDP round trip.
func TestICMPEcho(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	one := provisionENI(t, gwlbID, true, echoServerPort, func(b []byte) []byte { return b })
	fd := openGWLBSocket(t, gwlbIface)

	const icmpID, icmpSeq = 0x1234, 1
	payload := []byte("hello from gwlb-xdp e2e test (icmp)")

	innerPacket, err := buildInnerICMPEchoRequest(net.ParseIP(fakeClientIP), net.ParseIP(echoServerIP), icmpID, icmpSeq, payload)
	if err != nil {
		t.Fatalf("buildInnerICMPEchoRequest failed: %v", err)
	}
	frame, err := buildRequestFrame(requestParams{
		outerSrcMAC:  gwlbIface.HardwareAddr,
		outerDstMAC:  uplinkIface.HardwareAddr,
		outerSrcIP:   net.ParseIP(fakeGWLBOuterSrcIP),
		outerDstIP:   net.ParseIP(fakeGWLBOuterDstIP),
		outerSrcPort: fakeOuterSrcPort,
		vni:          [3]byte{0, 0, 0},
		opts:         buildGeneveOptions(gwlbID, fakeAttachmentID, fakeFlowCookie),
		innerPacket:  innerPacket,
	})
	if err != nil {
		t.Fatalf("buildRequestFrame failed: %v", err)
	}
	if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: gwlbIface.Index}); err != nil {
		t.Fatalf("unix.Sendto failed: %v", err)
	}

	reply := waitForICMPReply(t, fd, uplinkIface.HardwareAddr, 5*time.Second)
	if reply == nil {
		t.Fatal("no GENEVE ICMP reply observed on the simulated uplink within 5s")
	}

	const icmpEchoReply = 0 // linux/icmp.h ICMP_ECHOREPLY
	if reply.icmpType != icmpEchoReply {
		t.Errorf("reply ICMP type = %d, want %d (echo reply)", reply.icmpType, icmpEchoReply)
	}
	if reply.icmpID != icmpID || reply.icmpSeq != icmpSeq {
		t.Errorf("reply ICMP id/seq = %d/%d, want %d/%d (the kernel echoes both back unchanged)",
			reply.icmpID, reply.icmpSeq, icmpID, icmpSeq)
	}
	if !bytes.Equal(reply.payload, payload) {
		t.Errorf("reply payload = %q, want %q", reply.payload, payload)
	}

	// Outer/inner addressing swapped exactly as a UDP reply's would be (see
	// assertValidReply) — decap's flow_key doesn't treat ICMP specially
	// beyond parse_l4, so the same NAT-orientation lookup applies.
	if !bytes.Equal(reply.outerDstMAC, gwlbIface.HardwareAddr) {
		t.Errorf("reply outer dst MAC = %v, want %v (this harness's own)", reply.outerDstMAC, gwlbIface.HardwareAddr)
	}
	if !reply.outerSrcIP.Equal(net.ParseIP(fakeGWLBOuterDstIP)) || !reply.outerDstIP.Equal(net.ParseIP(fakeGWLBOuterSrcIP)) {
		t.Errorf("reply outer IPs = %s -> %s, want %s -> %s (swapped)",
			reply.outerSrcIP, reply.outerDstIP, fakeGWLBOuterDstIP, fakeGWLBOuterSrcIP)
	}
	if reply.outerDstPort != genevePort {
		t.Errorf("reply outer UDP dst port = %d, want %d", reply.outerDstPort, genevePort)
	}
	if !reply.innerSrcIP.Equal(net.ParseIP(echoServerIP)) || !reply.innerDstIP.Equal(net.ParseIP(fakeClientIP)) {
		t.Errorf("reply inner IPs = %s -> %s, want %s -> %s",
			reply.innerSrcIP, reply.innerDstIP, echoServerIP, fakeClientIP)
	}

	if got := metricSum(t, "decap_ok_packets", one.outerIfindex); got != 1 {
		t.Errorf("decap_ok_packets[outer ifindex] = %d, want 1", got)
	}
	if got := metricSum(t, "encap_ok_packets", one.outerIfindex); got != 1 {
		t.Errorf("encap_ok_packets[outer ifindex] = %d, want 1", got)
	}
}

// waitForReplyV6 is waitForReply's inner-IPv6 analogue — same "tell the reply
// apart from our own looped-back request by outer source MAC" loop, parsing
// each frame as an outer-IPv4/inner-IPv6 reply (see parseUDPReplyV6).
func waitForReplyV6(t *testing.T, fd int, uplinkMAC net.HardwareAddr, timeout time.Duration) *udpReplyPacketV6 {
	t.Helper()
	tv := unix.NsecToTimeval(timeout.Nanoseconds())
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
			t.Fatalf("waiting for a GENEVE IPv6 reply failed: %v", err)
		}
		rp, err := parseUDPReplyV6(buf[:n])
		if err != nil || !bytes.Equal(rp.outerSrcMAC, uplinkMAC) {
			continue // not it — e.g. our own request, looped back
		}
		return rp
	}
	return nil
}

// TestEndToEndV6 is TestEndToEnd's happy path with an inner IPv6/UDP packet
// instead of IPv4 — exercising decap/encap's is_v6 branch and union flow_addr
// (bpf/geneve_defs.h), which every other test leaves untouched. The outer
// GENEVE tunnel is still IPv4 (GWLB always encapsulates over IPv4); only the
// inner packet, and the GENEVE proto_type decap reads to classify it, are v6.
func TestEndToEndV6(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	one := provisionENI(t, gwlbID, true, echoServerPort, func(b []byte) []byte { return b })
	fd := openGWLBSocket(t, gwlbIface)

	payload := []byte("hello from gwlb-xdp e2e test (ipv6)")
	innerPacket, err := buildInnerUDPv6(net.ParseIP(fakeClientIP6), net.ParseIP(echoServerIP6), fakeClientPort, echoServerPort, payload)
	if err != nil {
		t.Fatalf("buildInnerUDPv6 failed: %v", err)
	}
	frame, err := buildRequestFrame(requestParams{
		outerSrcMAC:    gwlbIface.HardwareAddr,
		outerDstMAC:    uplinkIface.HardwareAddr,
		outerSrcIP:     net.ParseIP(fakeGWLBOuterSrcIP),
		outerDstIP:     net.ParseIP(fakeGWLBOuterDstIP),
		outerSrcPort:   fakeOuterSrcPort,
		vni:            [3]byte{0, 0, 0},
		opts:           buildGeneveOptions(gwlbID, fakeAttachmentID, fakeFlowCookie),
		innerPacket:    innerPacket,
		innerEthertype: layers.EthernetTypeIPv6,
	})
	if err != nil {
		t.Fatalf("buildRequestFrame failed: %v", err)
	}
	if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: gwlbIface.Index}); err != nil {
		t.Fatalf("unix.Sendto failed: %v", err)
	}

	reply := waitForReplyV6(t, fd, uplinkIface.HardwareAddr, 5*time.Second)
	if reply == nil {
		t.Fatal("no GENEVE IPv6 reply observed on the simulated uplink within 5s")
	}

	// Outer addressing swapped and GENEVE options replayed verbatim, exactly
	// as the IPv4 case (assertValidReply) — the outer tunnel is family-blind.
	if !bytes.Equal(reply.outerDstMAC, gwlbIface.HardwareAddr) {
		t.Errorf("reply outer dst MAC = %v, want %v (this harness's own)", reply.outerDstMAC, gwlbIface.HardwareAddr)
	}
	if !reply.outerSrcIP.Equal(net.ParseIP(fakeGWLBOuterDstIP)) || !reply.outerDstIP.Equal(net.ParseIP(fakeGWLBOuterSrcIP)) {
		t.Errorf("reply outer IPs = %s -> %s, want %s -> %s (swapped)",
			reply.outerSrcIP, reply.outerDstIP, fakeGWLBOuterDstIP, fakeGWLBOuterSrcIP)
	}
	if reply.outerDstPort != genevePort {
		t.Errorf("reply outer UDP dst port = %d, want %d", reply.outerDstPort, genevePort)
	}
	if !reply.outerIPChecksumValid {
		t.Error("reply outer IP header checksum is invalid (encap's recomputed ipv4_checksum, see _encap.c)")
	}
	if reply.outerUDPChecksum != 0 {
		t.Errorf("reply outer UDP checksum = %#04x, want 0 (zeroed by encap, see _encap.c)", reply.outerUDPChecksum)
	}

	// Inner IPv6 5-tuple swapped by the echo server's own reply, payload echoed.
	if !reply.innerSrcIP.Equal(net.ParseIP(echoServerIP6)) || !reply.innerDstIP.Equal(net.ParseIP(fakeClientIP6)) {
		t.Errorf("reply inner IPs = %s -> %s, want %s -> %s",
			reply.innerSrcIP, reply.innerDstIP, echoServerIP6, fakeClientIP6)
	}
	if reply.innerSrcPort != echoServerPort || reply.innerDstPort != fakeClientPort {
		t.Errorf("reply inner ports = %d -> %d, want %d -> %d",
			reply.innerSrcPort, reply.innerDstPort, echoServerPort, fakeClientPort)
	}
	if !bytes.Equal(reply.payload, payload) {
		t.Errorf("reply payload = %q, want %q", reply.payload, payload)
	}

	if got := metricSum(t, "decap_ok_packets", one.outerIfindex); got != 1 {
		t.Errorf("decap_ok_packets[outer ifindex] = %d, want 1", got)
	}
	if got := metricSum(t, "encap_ok_packets", one.outerIfindex); got != 1 {
		t.Errorf("encap_ok_packets[outer ifindex] = %d, want 1", got)
	}
}

// TestRemove drives one ENI through a full round trip (so its flow_state cache
// and metrics rows are populated), then `remove`s it and checks that every
// piece is actually reversed: the eni_to_ifindex entry, the veth pair, the
// netns, and — the part remove exists to guarantee (see decap.SweepENI) — the
// flow_state and metrics entries keyed by the now-freed ifindex, so a later
// ENI recycling that ifindex can't inherit stale cache hits or counters.
func TestRemove(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	gwlbID := uint64(0xE2E)
	vpceID := cmd.FormatVPCEID(gwlbID)
	outerName := cmd.FormatInterfaceName(gwlbID, false)

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	one := provisionENI(t, gwlbID, true, echoServerPort, func(b []byte) []byte { return b })
	fd := openGWLBSocket(t, gwlbIface)

	// Populate flow_state + metrics for this ENI's ifindex.
	sendGENEVE(t, fd, uplinkIface, gwlbIface, gwlbID, []byte("populate"))
	if reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 5*time.Second); reply == nil {
		t.Fatal("no reply before remove — round trip is broken, nothing to test removal against")
	}
	if flowStateCount(t) == 0 {
		t.Fatal("expected a flow_state entry before remove")
	}
	if got := metricSum(t, "decap_ok_packets", one.outerIfindex); got == 0 {
		t.Fatal("expected decap_ok_packets before remove")
	}

	// A few flow_state entries belonging to some other ifindex, which the
	// sweep must leave alone.
	const otherIfindex = 0xFFFF
	const otherFlows = 3
	fs, err := ebpf.LoadPinnedMap(bpf.PinDir+"/flow_state", nil)
	if err != nil {
		t.Fatalf("loading pinned flow_state map failed: %v", err)
	}
	defer fs.Close()
	for i := range otherFlows {
		key := make([]byte, fs.KeySize())
		binary.NativeEndian.PutUint32(key, otherIfindex)
		key[4] = byte(i + 1) // distinct saddr
		if err := fs.Update(key, make([]byte, fs.ValueSize()), ebpf.UpdateAny); err != nil {
			t.Fatalf("(*ebpf.Map).Update for flow_state failed: %v", err)
		}
	}

	if err := cmd.RunRemove(vpceID); err != nil {
		t.Fatalf("cmd.RunRemove(%q) failed: %v", vpceID, err)
	}

	// eni_to_ifindex entry gone.
	ids, err := decap.ProvisionedENIs()
	if err != nil {
		t.Fatalf("decap.ProvisionedENIs failed: %v", err)
	}
	for _, id := range ids {
		if id == gwlbID {
			t.Errorf("ENI %#x still in eni_to_ifindex after remove", gwlbID)
		}
	}

	// veth pair gone (deleting the outer end takes the inner peer with it).
	if _, err := net.InterfaceByName(outerName); err == nil {
		t.Errorf("veth %q still exists after remove", outerName)
	}

	// netns gone.
	if ns, err := netns.GetFromName(vpceID); err == nil {
		ns.Close()
		t.Errorf("netns %q still exists after remove", vpceID)
	}

	// flow_state swept — the whole point of remove's sweep (see
	// decap.SweepENI) — and nothing else's entries with it.
	if n := flowStateCountFor(t, one.outerIfindex); n != 0 {
		t.Errorf("flow_state not swept after remove: %d entries for the freed ifindex, want 0", n)
	}
	if n := flowStateCountFor(t, otherIfindex); n != otherFlows {
		t.Errorf("flow_state has %d entries for an unrelated ifindex after remove, want %d (swept too much)", n, otherFlows)
	}

	// metrics rows for the freed ifindex swept, so serve stops pushing
	// series for an interface that no longer exists.
	if got := metricSum(t, "decap_ok_packets", one.outerIfindex); got != 0 {
		t.Errorf("decap_ok_packets[freed ifindex] = %d after remove, want 0 (metrics not swept)", got)
	}
	if got := metricSum(t, "encap_ok_packets", one.outerIfindex); got != 0 {
		t.Errorf("encap_ok_packets[freed ifindex] = %d after remove, want 0 (metrics not swept)", got)
	}
}
