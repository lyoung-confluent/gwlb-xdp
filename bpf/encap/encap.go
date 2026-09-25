package encap

//go:generate go tool bpf2go -target amd64,arm64 -cflags "-g -O2 -I.. -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types" bpf _encap.c

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
)

// Config configures encap before it's loaded. flow_state/metrics aren't
// sized here — Load reads their sizes back from decap's pins (see Load).
// frag_state is encap's own — MaxFragEntries sizes it.
type Config struct {
	// Transparent hardcodes every ENI on this box as a transparent
	// appliance (reply comes back with the same 5-tuple, not swapped).
	Transparent bool
	// Uplink is the physical interface encap sends replies out of. Its MTU
	// caps the largest reply encap will encapsulate (see max_inner_len in
	// _encap.c).
	Uplink *net.Interface
	// MaxFragEntries sizes frag_state, encap's own LRU map of in-flight
	// reply fragments (see _encap.c). Zero is treated as 1, same as
	// decap.Config's MaxFlows.
	MaxFragEntries uint32
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
// first: it sizes its copy of the shared flow_state and metrics maps to
// match the pins decap created (see matchPinnedMapSize).
func Load(cfg Config) (*Program, error) {
	if err := bpf.CreatePinDir(); err != nil {
		return nil, fmt.Errorf("bpf.CreatePinDir failed: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loadBpf failed: %w", err)
	}

	if err := matchPinnedMapSize(spec, bpfMapFlowState); err != nil {
		return nil, err
	}
	if err := matchPinnedMapSize(spec, bpfMapMetrics); err != nil {
		return nil, err
	}
	spec.Maps[bpfMapFragState].MaxEntries = max(cfg.MaxFragEntries, 1)

	// eni_mode defaults to 0 (NAT/terminating) in the compiled object
	// (bpf/encap/_encap.c); only override here to make it transparent.
	if cfg.Transparent {
		if err := spec.Variables[bpfVarEniMode].Set(uint8(1)); err != nil {
			return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for eni_mode failed: %w", err)
		}
	}

	if err := spec.Variables[bpfVarUplinkIfindex].Set(uint32(cfg.Uplink.Index)); err != nil {
		return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for uplink_ifindex failed: %w", err)
	}

	// The largest reply that still fits the uplink once encapsulated.
	maxInnerLen, err := bpf.MaxInnerLen(cfg.Uplink.MTU)
	if err != nil {
		return nil, fmt.Errorf("bpf.MaxInnerLen for %s failed: %w", cfg.Uplink.Name, err)
	}
	if err := spec.Variables[bpfVarMaxInnerLen].Set(uint32(maxInnerLen)); err != nil {
		return nil, fmt.Errorf("(*ebpf.VariableSpec).Set for max_inner_len failed: %w", err)
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
// map decap.Load already pinned — required for LoadAndAssign to attach to
// that existing pin rather than fail on a size mismatch.
func matchPinnedMapSize(spec *ebpf.CollectionSpec, name string) (rerr error) {
	path := bpf.PinDir + "/" + name
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return fmt.Errorf("ebpf.LoadPinnedMap for %q failed: %w", path, err)
	}
	defer func() {
		if err := m.Close(); err != nil && rerr == nil {
			rerr = fmt.Errorf("(*ebpf.Map).Close for %q failed: %w", path, err)
		}
	}()

	spec.Maps[name].MaxEntries = m.MaxEntries()
	return nil
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

	// A pin already at this path is left over from an earlier interface
	// that had the same ifindex and is gone now (its link can't still be
	// attached: ifindex is the caller's freshly created veth). It would make
	// the Pin below fail, so clear it first.
	pinPath := linkPinPath(ifindex)
	if _, err := os.Stat(pinPath); err == nil {
		if err := bpf.DetachXDP(pinPath); err != nil {
			return nil, fmt.Errorf("clearing stale pin %q failed: %w", pinPath, err)
		}
	}
	link, err := bpf.AttachXDP(prog, ifindex, pinPath)
	if err != nil {
		return nil, fmt.Errorf("bpf.AttachXDP failed: %w", err)
	}
	return link, nil
}

// Detach reverses a prior Attach for ifindex. The error wraps os.ErrNotExist
// if encap isn't attached (pinned) there.
func Detach(ifindex int) error {
	return bpf.DetachXDP(linkPinPath(ifindex))
}

// linkPinPath is where Attach pins encap's link on ifindex.
func linkPinPath(ifindex int) string {
	return fmt.Sprintf(bpf.PinDir+"/link_encap_%d", ifindex)
}
