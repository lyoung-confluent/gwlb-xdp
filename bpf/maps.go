// Package bpf holds helpers shared by the decap and encap XDP programs for
// managing the pinned BPF maps and links under /sys/fs/bpf/gwlb-xdp. Pins
// survive the loader process, so a later invocation finds what setup left.
package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

// PinDir is the bpffs directory holding every map and link the loader pins.
const PinDir = "/sys/fs/bpf/gwlb-xdp"

// CreatePinDir creates the bpffs pin directory. Called by decap.Load and
// encap.Load before pinning anything under it.
func CreatePinDir() error {
	if err := os.MkdirAll(PinDir, 0o755); err != nil {
		return fmt.Errorf("os.MkdirAll for %q failed: %w", PinDir, err)
	}
	return nil
}

// RemovePinDir removes the entire pin directory, unpinning every map and link
// setup created. Used by teardown.
func RemovePinDir() error {
	if err := os.RemoveAll(PinDir); err != nil {
		return fmt.Errorf("os.RemoveAll for %q failed: %w", PinDir, err)
	}
	return nil
}

// CounterNames indexes enum metric (bpf/maps.h) by position: a counter's
// enum value is the Counter field of metricKey, so this slice's order must
// track the enum exactly.
var CounterNames = []string{
	"decap_pass_not_geneve_packets",
	"decap_pass_not_geneve_bytes",
	"decap_drop_malformed_packets",
	"decap_drop_malformed_bytes",
	"decap_drop_unknown_eni_packets",
	"decap_drop_unknown_eni_bytes",
	"decap_drop_hdr_too_long_packets",
	"decap_drop_hdr_too_long_bytes",
	"decap_drop_family_disabled_packets",
	"decap_drop_family_disabled_bytes",
	"decap_ok_packets",
	"decap_ok_bytes",
	"encap_drop_malformed_packets",
	"encap_drop_malformed_bytes",
	"encap_drop_flow_miss_packets",
	"encap_drop_flow_miss_bytes",
	"encap_drop_family_disabled_packets",
	"encap_drop_family_disabled_bytes",
	"encap_ok_packets",
	"encap_ok_bytes",
}

// Metric is one interface's row for a counter: Ifindex identifies the
// interface and PerCPU holds that (ifindex, counter) key's per-CPU values.
// Metrics groups these under the counter name.
type Metric struct {
	Ifindex uint32
	PerCPU  []uint64
}

// Metrics reads the pinned metrics map and returns its rows grouped by counter
// name (from CounterNames) — the shape a Prometheus scrape wants, one series
// group per counter. A counter value beyond CounterNames (a newer program
// than this build knows) is skipped.
func Metrics() (map[string][]Metric, error) {
	path := PinDir + "/metrics"
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("ebpf.LoadPinnedMap for %q failed: %w", path, err)
	}
	defer m.Close()

	byName := make(map[string][]Metric, len(CounterNames))
	it := m.Iterate()
	var key struct {
		Ifindex uint32
		Counter uint32
	}
	var perCPU []uint64
	for it.Next(&key, &perCPU) {
		if int(key.Counter) >= len(CounterNames) {
			continue
		}
		name := CounterNames[key.Counter]
		// it reuses perCPU's backing array next iteration, so store a copy.
		byName[name] = append(byName[name], Metric{key.Ifindex, append([]uint64(nil), perCPU...)})
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("(*ebpf.Map.Iterator).Err for \"metrics\" map failed: %w", err)
	}
	return byName, nil
}

// flowKeyIsV6Offset is struct flow_key's is_v6 field's byte offset (native
// order): ifindex(4) + saddr(16) + daddr(16) + sport(2) + dport(2) +
// proto(1) — see bpf/geneve_defs.h. Used to tell a raw flow_state key's
// family apart without decoding the whole struct.
const flowKeyIsV6Offset = 4 + 16 + 16 + 2 + 2 + 1

// FlowStateEntries returns the number of live entries in the pinned
// flow_state map, split by address family using each key's own is_v6 tag
// (v4 and v6 flows share one map — see maps.h — so family isn't a property
// of which map you asked, only of which entries you find in it). Unlike
// before v4/v6 shared a map, there's no signal left here for "this family
// was disabled at setup": a disabled family simply never has any entries,
// indistinguishable from an enabled-but-idle one.
func FlowStateEntries() (v4Count, v6Count uint64, err error) {
	path := PinDir + "/flow_state"
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("ebpf.LoadPinnedMap for %q failed: %w", path, err)
	}
	defer m.Close()

	// LRU hashes expose no "current size", so count by walking the keys.
	var key interface{}
	for {
		next, err := m.NextKeyBytes(key)
		if err != nil {
			return 0, 0, fmt.Errorf("(*ebpf.Map).NextKeyBytes for %s failed: %w", m, err)
		}
		if next == nil {
			return v4Count, v6Count, nil
		}
		key = next
		if len(next) > flowKeyIsV6Offset && next[flowKeyIsV6Offset] != 0 {
			v6Count++
		} else {
			v4Count++
		}
	}
}

// FlowStateRemove deletes every entry in the pinned flow_state map belonging
// to ifindex — one removed ENI's cached flows, both address families in the
// one sweep since flow_state now holds both.
func FlowStateRemove(ifindex uint32) error {
	return sweepByIfindex("flow_state", ifindex)
}

// MetricsRemove deletes every entry in the pinned metrics map belonging to
// ifindex — one removed ENI's counter rows, so a scrape stops emitting series
// for an interface that no longer exists.
func MetricsRemove(ifindex uint32) error {
	return sweepByIfindex("metrics", ifindex)
}

// sweepByIfindex deletes every entry in the pinned map named mapName whose key
// begins with ifindex — its first 4 bytes in native byte order, the leading
// field of both struct flow_key and struct metric_key. Keys are collected
// first, then deleted, to avoid mutating the map mid-iteration.
//
// A missing pin is tolerated (returns nil): it just means nothing has been
// set up yet. Once the map is open, all iteration/delete errors are returned.
func sweepByIfindex(mapName string, ifindex uint32) error {
	path := PinDir + "/" + mapName
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil
	}
	defer m.Close()

	var toDelete [][]byte
	// nil interface means "first key" to NextKeyBytes; a typed-nil []byte
	// would be marshalled to 0 bytes and rejected.
	var cur interface{}
	for {
		next, err := m.NextKeyBytes(cur)
		if err != nil {
			return fmt.Errorf("(*ebpf.Map).NextKeyBytes for %s failed: %w", path, err)
		}
		if next == nil {
			break
		}
		cur = next
		if len(next) >= 4 && binary.NativeEndian.Uint32(next[:4]) == ifindex {
			toDelete = append(toDelete, append([]byte(nil), next...))
		}
	}

	var errs []error
	for _, k := range toDelete {
		if err := m.Delete(k); err != nil {
			errs = append(errs, fmt.Errorf("(*ebpf.Map).Delete for %s failed: %w", path, err))
		}
	}
	return errors.Join(errs...)
}
