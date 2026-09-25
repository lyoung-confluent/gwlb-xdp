package decap

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-g -O2 -I.. -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types" bpf _decap.c

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
)

// VpceInfo is vpce_to_ifindex's map value (struct vpce_info in _decap.c).
type VpceInfo = bpfVpceInfo

// PinLink is where Attach pins decap's XDP attachment, and teardown checks
// for before calling Detach.
const PinLink = bpf.PinDir + "/link_" + bpfProgDecap

// Config sizes and configures decap before it's loaded.
type Config struct {
	// MaxEndpoints sizes vpce_to_ifindex and metrics.
	MaxEndpoints uint32
	// MaxFlows sizes the one shared flow_state map — IPv4 and IPv6 flows
	// together, not each.
	MaxFlows uint32
	// MaxInnerLen is the largest inner packet decap delivers (see
	// bpf.MaxInnerLen); anything larger is dropped as oversize. Zero keeps
	// the compiled-in default.
	MaxInnerLen uint32
	// AllowedOriginCIDR, if valid (see netip.Prefix.IsValid), restricts
	// accepted GENEVE traffic to packets whose outer (GWLB) source IP falls
	// in this one IPv4 CIDR — anything else is dropped. The zero Prefix
	// (the default) accepts every origin, matching pre-existing behavior.
	AllowedOriginCIDR netip.Prefix
}

// Program is decap, loaded and pinned under /sys/fs/bpf/gwlb-xdp.
type Program struct {
	objs bpfObjects
}

// Load loads decap sized per cfg and pins its maps under /sys/fs/bpf/gwlb-xdp.
func Load(cfg Config) (*Program, error) {
	if err := bpf.CreatePinDir(); err != nil {
		return nil, fmt.Errorf("bpf.CreatePinDir failed: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loadBpf failed: %w", err)
	}

	spec.Maps[bpfMapVpceToIfindex].MaxEntries = cfg.MaxEndpoints
	spec.Maps[bpfMapFlowState].MaxEntries = max(cfg.MaxFlows, 1)
	spec.Maps[bpfMapMetrics].MaxEntries *= (cfg.MaxEndpoints + 1)

	if cfg.MaxInnerLen != 0 {
		if err := spec.Variables[bpfVarMaxInnerLen].Set(cfg.MaxInnerLen); err != nil {
			return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for max_inner_len failed: %w", err)
		}
	}

	// allowed_origin_addr/_mask default to all-zero bytes in the compiled
	// object, under which every packet passes (see _decap.c); only override
	// them here to actually turn filtering on.
	if cfg.AllowedOriginCIDR.IsValid() {
		bits := cfg.AllowedOriginCIDR.Bits()
		var maskBits uint32
		if bits > 0 {
			maskBits = ^uint32(0) << (32 - bits)
		}
		var mask [4]byte
		binary.BigEndian.PutUint32(mask[:], maskBits)

		if err := spec.Variables[bpfVarAllowedOriginAddr].Set(cfg.AllowedOriginCIDR.Addr().As4()); err != nil {
			return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for allowed_origin_addr failed: %w", err)
		}
		if err := spec.Variables[bpfVarAllowedOriginMask].Set(mask); err != nil {
			return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for allowed_origin_mask failed: %w", err)
		}
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpf.PinDir},
	}); err != nil {
		return nil, fmt.Errorf("(*ebpf.CollectionSpec).LoadAndAssign failed: %w", err)
	}
	// No objs.Close(): the maps are pinned to bpffs, which keeps the kernel
	// objects alive past this one-shot process.

	return &Program{objs: objs}, nil
}

// Attach attaches decap to ifindex/ifname and pins the resulting link at
// PinLink.
func (p *Program) Attach(ifindex int, ifname string) (link.Link, error) {
	return bpf.AttachXDP(p.objs.Decap, ifindex, PinLink)
}

// Detach reverses a prior (*Program).Attach.
func Detach() error {
	return bpf.DetachXDP(PinLink)
}

// Attached reports whether decap's pinned link still loads.
func Attached() bool {
	l, err := link.LoadPinnedLink(PinLink, nil)
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// UplinkIfindex returns the ifindex of the interface decap's pinned link is
// attached to — the uplink `setup` was run against.
func UplinkIfindex() (int, error) {
	l, err := link.LoadPinnedLink(PinLink, nil)
	if err != nil {
		return 0, fmt.Errorf("link.LoadPinnedLink for %q failed: %w", PinLink, err)
	}
	defer l.Close()

	info, err := l.Info()
	if err != nil {
		return 0, fmt.Errorf("(link.Link).Info for %q failed: %w", PinLink, err)
	}
	xdp := info.XDP()
	if xdp == nil {
		return 0, fmt.Errorf("%q isn't an XDP link", PinLink)
	}
	return int(xdp.Ifindex), nil
}

// ProvisionedEndpoints returns the VPC endpoint IDs currently in vpce_to_ifindex, or nil if
// the map isn't pinned or can't be read.
func ProvisionedEndpoints() ([]uint64, error) {
	m, err := ebpf.LoadPinnedMap(bpf.PinDir+"/"+bpfMapVpceToIfindex, nil)
	if err != nil {
		return nil, nil
	}
	defer m.Close()

	var ids []uint64
	var gwlbID uint64
	var info VpceInfo
	it := m.Iterate()
	for it.Next(&gwlbID, &info) {
		ids = append(ids, gwlbID)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("(*ebpf.Map.Iterator).Err for %s failed: %w", bpfMapVpceToIfindex, err)
	}
	return ids, nil
}

// AddEndpoint inserts gwlbID -> (ifindex, dstMac, srcMac) into vpce_to_ifindex,
// failing if the endpoint is already provisioned. dstMac is the veth peer's
// (inner) hwaddr and srcMac the veth-outer's own — decap synthesizes both
// into the Ethernet header it builds (see struct vpce_info in _decap.c).
func AddEndpoint(gwlbID uint64, ifindex uint32, dstMac, srcMac net.HardwareAddr) error {
	path := bpf.PinDir + "/" + bpfMapVpceToIfindex
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("ebpf.LoadPinnedMap for %q failed: %w", path, err)
	}
	defer m.Close()

	info := VpceInfo{Ifindex: ifindex}
	copy(info.Dst[:], dstMac)
	copy(info.Src[:], srcMac)
	if err := m.Update(&gwlbID, &info, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("(*ebpf.Map).Update for %s failed (endpoint already provisioned?): %w", bpfMapVpceToIfindex, err)
	}
	return nil
}

// LookupEndpoint returns gwlbID's vpce_to_ifindex entry. The error wraps
// ebpf.ErrKeyNotExist if the endpoint isn't provisioned, or os.ErrNotExist if
// setup hasn't pinned the map yet.
func LookupEndpoint(gwlbID uint64) (VpceInfo, error) {
	path := bpf.PinDir + "/" + bpfMapVpceToIfindex
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return VpceInfo{}, fmt.Errorf("ebpf.LoadPinnedMap for %q failed: %w", path, err)
	}
	defer m.Close()

	var info VpceInfo
	if err := m.Lookup(&gwlbID, &info); err != nil {
		return VpceInfo{}, fmt.Errorf("(*ebpf.Map).Lookup for %s failed: %w", bpfMapVpceToIfindex, err)
	}
	return info, nil
}

// RemoveEndpoint deletes gwlbID's entry from vpce_to_ifindex, so decap stops
// delivering to it, and returns the entry as it stood before deletion so the
// caller can tear down everything keyed on its ifindex (encap, the veth) and
// then call SweepEndpoint. The error wraps ebpf.ErrKeyNotExist if the endpoint isn't
// provisioned, or os.ErrNotExist if setup hasn't pinned the map yet.
func RemoveEndpoint(gwlbID uint64) (VpceInfo, error) {
	path := bpf.PinDir + "/" + bpfMapVpceToIfindex
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return VpceInfo{}, fmt.Errorf("ebpf.LoadPinnedMap for %q failed: %w", path, err)
	}
	defer m.Close()

	// Lookup then Delete rather than LookupAndDelete, which hash maps only
	// support from Linux 5.14.
	var info VpceInfo
	if err := m.Lookup(&gwlbID, &info); err != nil {
		return VpceInfo{}, fmt.Errorf("(*ebpf.Map).Lookup for %s failed: %w", bpfMapVpceToIfindex, err)
	}
	if err := m.Delete(&gwlbID); err != nil {
		return VpceInfo{}, fmt.Errorf("(*ebpf.Map).Delete for %s failed: %w", bpfMapVpceToIfindex, err)
	}
	return info, nil
}

// SweepEndpoint deletes every flow_state/frag_state entry and metrics row keyed by
// a removed endpoint's veth-outer ifindex, so a later endpoint that reuses the ifindex
// can't inherit stale cache hits or counters.
//
// Call it only once nothing can still write those keys: after RemoveEndpoint, and
// after the veth itself is deleted. Deleting the veth detaches encap and
// waits out an RCU grace period, so by then every decap or encap run that
// might still have been using that ifindex has finished. Sweeping any
// earlier lets those in-flight runs put entries back.
func SweepEndpoint(ifindex uint32) error {
	return errors.Join(
		bpf.FlowStateRemove(ifindex),
		bpf.FragStateRemove(ifindex),
		bpf.MetricsRemove(ifindex),
	)
}
