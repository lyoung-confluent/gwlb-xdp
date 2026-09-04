package decap

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-g -O2 -I.. -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types" bpf _decap.c

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
)

// EniInfo is eni_to_ifindex's map value (bpf/maps.h: struct eni_info).
type EniInfo = bpfEniInfo

// PinLink is where Attach pins decap's XDP attachment, and teardown checks
// for before calling Detach.
const PinLink = bpf.PinDir + "/link_" + bpfProgDecap

// Config sizes and configures decap before it's loaded.
type Config struct {
	// MaxENIs sizes eni_to_ifindex and metrics.
	MaxENIs uint32
	// MaxFlowsV4/V6 size flow_state_v4/v6; <=1 disables that family. A
	// disabled family's map is still created (the program needs it to
	// exist even though it never touches it), just clamped to 1 entry
	// instead of the full preallocated LRU.
	MaxFlowsV4 uint32
	MaxFlowsV6 uint32
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

	spec.Maps[bpfMapEniToIfindex].MaxEntries = cfg.MaxENIs
	spec.Maps[bpfMapFlowStateV4].MaxEntries = max(cfg.MaxFlowsV4, 1)
	spec.Maps[bpfMapFlowStateV6].MaxEntries = max(cfg.MaxFlowsV6, 1)
	spec.Maps[bpfMapMetrics].MaxEntries *= (cfg.MaxENIs + 1)

	// ipv4_enabled/ipv6_enabled default to true in the compiled object
	// (bpf/decap/_decap.c); only override here to disable one.
	if cfg.MaxFlowsV4 <= 1 {
		if err := spec.Variables[bpfVarIpv4Enabled].Set(uint8(0)); err != nil {
			return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for ipv4_enabled failed: %w", err)
		}
	}
	if cfg.MaxFlowsV6 <= 1 {
		if err := spec.Variables[bpfVarIpv6Enabled].Set(uint8(0)); err != nil {
			return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for ipv6_enabled failed: %w", err)
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

// ProvisionedENIs returns the ENI IDs currently in eni_to_ifindex, or nil if
// the map isn't pinned or can't be read.
func ProvisionedENIs() ([]uint64, error) {
	m, err := ebpf.LoadPinnedMap(bpf.PinDir+"/"+bpfMapEniToIfindex, nil)
	if err != nil {
		return nil, nil
	}
	defer m.Close()

	var ids []uint64
	var gwlbID uint64
	var info EniInfo
	it := m.Iterate()
	for it.Next(&gwlbID, &info) {
		ids = append(ids, gwlbID)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("(*ebpf.Map.Iterator).Err for %s failed: %w", bpfMapEniToIfindex, err)
	}
	return ids, nil
}

// AddENI inserts gwlbID -> (ifindex, dstMac, srcMac) into eni_to_ifindex,
// failing if the ENI is already provisioned. dstMac is the veth peer's
// (inner) hwaddr and srcMac the veth-outer's own — decap synthesizes both
// into the Ethernet header it builds (see struct eni_info in _decap.c).
func AddENI(gwlbID uint64, ifindex uint32, dstMac, srcMac net.HardwareAddr) error {
	path := bpf.PinDir + "/" + bpfMapEniToIfindex
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("ebpf.LoadPinnedMap for %q failed: %w", path, err)
	}
	defer m.Close()

	info := EniInfo{Ifindex: ifindex}
	copy(info.Dst[:], dstMac)
	copy(info.Src[:], srcMac)
	if err := m.Update(&gwlbID, &info, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("(*ebpf.Map).Update for %s failed (ENI already provisioned?): %w", bpfMapEniToIfindex, err)
	}
	return nil
}

// RemoveENI deletes gwlbID's entry from eni_to_ifindex and sweeps its
// flow_state_v4/v6 cache entries and metrics rows by ifindex (a recycled veth
// ifindex could otherwise match stale flow entries before the LRU ages them
// out, and stale metrics would keep being scraped). It returns the entry as it
// stood before deletion, so the caller can detach anything keyed on its
// ifindex (e.g. encap).
//
// A non-nil error doesn't mean the entry survived: a non-zero EniInfo with
// an error means the entry was deleted and only the sweep failed. Check
// EniInfo.Ifindex, not just the error, before treating removal as failed.
func RemoveENI(gwlbID uint64) (EniInfo, error) {
	path := bpf.PinDir + "/" + bpfMapEniToIfindex
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return EniInfo{}, fmt.Errorf("ebpf.LoadPinnedMap for %q failed: %w", path, err)
	}
	defer m.Close()

	var info EniInfo
	if err := m.Lookup(&gwlbID, &info); err != nil {
		return EniInfo{}, fmt.Errorf("(*ebpf.Map).Lookup for %s failed: %w", bpfMapEniToIfindex, err)
	}
	if err := m.Delete(&gwlbID); err != nil {
		return EniInfo{}, fmt.Errorf("(*ebpf.Map).Delete for %s failed: %w", bpfMapEniToIfindex, err)
	}

	sweepErr := errors.Join(
		bpf.FlowStateRemove(false, info.Ifindex),
		bpf.FlowStateRemove(true, info.Ifindex),
		bpf.MetricsRemove(info.Ifindex),
	)
	return info, sweepErr
}
