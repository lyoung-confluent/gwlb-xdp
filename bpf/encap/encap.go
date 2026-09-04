package encap

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-g -O2 -I.. -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types" bpf _encap.c

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
)

// Config configures encap before it's loaded. The shared maps aren't sized
// here — Load reads their sizes back from decap's pins (see Load).
type Config struct {
	// Transparent hardcodes every ENI on this box as a transparent
	// appliance (reply comes back with the same 5-tuple, not swapped).
	Transparent bool
	// Uplink is the physical interface encap sends replies out of.
	Uplink *net.Interface
}

// Program is encap, loaded but not yet attached to any interface — pin
// it with (*Program).Pin so `add` can attach it per ENI later.
type Program struct {
	objs bpfObjects
}

// pinProg is where Pin pins the loaded-but-unattached encap program for
// Attach to find and attach per ENI.
const pinProg = bpf.PinDir + "/prog_" + bpfProgEncap

// Load loads encap, configured per cfg. Requires decap.Load to have run
// first: it sizes its copies of the shared flow_state_v4/v6 and metrics maps
// to match the pins decap created (see matchPinnedMapSize).
func Load(cfg Config) (*Program, error) {
	if err := bpf.CreatePinDir(); err != nil {
		return nil, fmt.Errorf("bpf.CreatePinDir failed: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loadBpf failed: %w", err)
	}

	flowsV4, err := matchPinnedMapSize(spec, bpfMapFlowStateV4)
	if err != nil {
		return nil, err
	}
	flowsV6, err := matchPinnedMapSize(spec, bpfMapFlowStateV6)
	if err != nil {
		return nil, err
	}
	if _, err := matchPinnedMapSize(spec, bpfMapMetrics); err != nil {
		return nil, err
	}

	// ipv4_enabled/ipv6_enabled default to true in the compiled object
	// (bpf/encap/_encap.c); only override here to disable one. A disabled
	// family's flow_state map is the 1-entry placeholder decap.Load leaves
	// it at — see its doc comment for why that map still gets created.
	if flowsV4 <= 1 {
		if err := spec.Variables[bpfVarIpv4Enabled].Set(uint8(0)); err != nil {
			return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for ipv4_enabled failed: %w", err)
		}
	}
	if flowsV6 <= 1 {
		if err := spec.Variables[bpfVarIpv6Enabled].Set(uint8(0)); err != nil {
			return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for ipv6_enabled failed: %w", err)
		}
	}

	// eni_mode defaults to 0 (NAT/terminating) in the compiled object
	// (bpf/encap/_encap.c); only override here to make it transparent.
	if cfg.Transparent {
		if err := spec.Variables[bpfVarEniMode].Set(uint8(1)); err != nil {
			return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for eni_mode failed: %w", err)
		}
	}

	// Six scalars rather than one array-typed global — see their doc
	// comment in bpf/encap/_encap.c for why.
	uplinkMacVars := [6]string{
		bpfVarUplinkMac0, bpfVarUplinkMac1, bpfVarUplinkMac2,
		bpfVarUplinkMac3, bpfVarUplinkMac4, bpfVarUplinkMac5,
	}
	for idx, b := range cfg.Uplink.HardwareAddr {
		if err := spec.Variables[uplinkMacVars[idx]].Set(b); err != nil {
			return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for %s failed: %w", uplinkMacVars[idx], err)
		}
	}
	if err := spec.Variables[bpfVarUplinkIfindex].Set(uint32(cfg.Uplink.Index)); err != nil {
		return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for uplink_ifindex failed: %w", err)
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpf.PinDir},
	}); err != nil {
		return nil, fmt.Errorf("(*ebpf.CollectionSpec).LoadAndAssign failed: %w", err)
	}

	return &Program{objs: objs}, nil
}

// matchPinnedMapSize resizes spec's map named name to match the same-named
// map decap.Load already pinned, returning that size (so a disabled family's
// 1-entry placeholder can be told from a real size without a second lookup).
func matchPinnedMapSize(spec *ebpf.CollectionSpec, name string) (maxEntries uint32, rerr error) {
	path := bpf.PinDir + "/" + name
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return 0, fmt.Errorf("ebpf.LoadPinnedMap for %q failed: %w", path, err)
	}
	defer func() {
		if err := m.Close(); err != nil && rerr == nil {
			rerr = fmt.Errorf("(*ebpf.Map).Close for %q failed: %w", path, err)
		}
	}()

	maxEntries = m.MaxEntries()
	spec.Maps[name].MaxEntries = maxEntries
	return maxEntries, nil
}

// Pin pins encap at pinProg, not attached to anything — `add` attaches this
// same loaded program to each ENI's veth-outer as it's provisioned.
func (p *Program) Pin() error {
	if err := p.objs.Encap.Pin(pinProg); err != nil {
		return fmt.Errorf("(*ebpf.Program).Pin for %q failed: %w", pinProg, err)
	}
	return nil
}

// Attach attaches the pinned encap program (see (*Program).Pin) to
// ifindex/ifname — one ENI's veth-outer — and pins the resulting link at
// /sys/fs/bpf/gwlb-xdp/link_encap_<ifindex>.
func Attach(ifindex int) (_ link.Link, rerr error) {
	prog, err := ebpf.LoadPinnedProgram(pinProg, nil)
	if err != nil {
		return nil, fmt.Errorf("ebpf.LoadPinnedProgram for %q failed: %w", pinProg, err)
	}
	defer func() {
		if err := prog.Close(); err != nil && rerr == nil {
			rerr = fmt.Errorf("(*ebpf.Program).Close for %q failed: %w", pinProg, err)
		}
	}()

	pinPath := fmt.Sprintf(bpf.PinDir+"/link_encap_%d", ifindex)
	link, err := bpf.AttachXDP(prog, ifindex, pinPath)
	if err != nil {
		return nil, fmt.Errorf("bpf.AttachXDP failed: %w", err)
	}
	return link, nil
}

// Detach reverses a prior Attach for ifindex.
func Detach(ifindex int) error {
	pinPath := fmt.Sprintf(bpf.PinDir+"/link_encap_%d", ifindex)
	return bpf.DetachXDP(pinPath)
}
