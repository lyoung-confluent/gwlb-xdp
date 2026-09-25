// Package bpf holds helpers shared by the decap and encap XDP programs for
// managing the pinned BPF maps and links under /sys/fs/bpf/gwlb-xdp. Pins
// survive the loader process, so a later invocation finds what setup left.
package bpf

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// PinDir is the bpffs directory holding every map and link the loader pins.
const PinDir = "/sys/fs/bpf/gwlb-xdp"

// GWLBMTU is GWLB's documented MTU: the largest inner packet (IP header
// onward) it's guaranteed to carry, and the default MTU of an ENI's veth
// pair, so the netns sizes its own replies to it — GWLB sends no ICMP
// "fragmentation needed", so a DF-set reply it won't carry is silently lost.
// It is not a limit on what GWLB delivers: see MaxInnerLen.
const GWLBMTU = 8500

// GeneveOverhead is what encapsulation adds to an inner packet on the wire:
// outer IPv4(20) + UDP(8) + GENEVE(8) + GWLB's three options(32). Must match
// GENEVE_OVERHEAD in geneve_defs.h.
const GeneveOverhead = 68

// minInnerLen is the smallest MaxInnerLen allowed: Linux's minimum Ethernet
// MTU, below which an ENI's veth can't be created.
const minInnerLen = 68

// MaxInnerLen returns the largest inner packet (IP header onward) one GENEVE
// packet on an uplink with this MTU can carry. It's decap's and encap's
// max_inner_len and the most an ENI veth's MTU can be: GWLB doesn't hold
// what it delivers to GWLBMTU (including fragments it creates itself), so
// decap accepts anything the uplink can carry.
func MaxInnerLen(uplinkMTU int) (int, error) {
	n := uplinkMTU - GeneveOverhead
	if n < minInnerLen {
		return 0, fmt.Errorf("uplink MTU %d leaves no room for the %d-byte GENEVE encapsulation", uplinkMTU, GeneveOverhead)
	}
	return n, nil
}

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
	"decap_ok_packets",
	"decap_ok_bytes",
	"encap_drop_malformed_packets",
	"encap_drop_malformed_bytes",
	"encap_drop_flow_miss_packets",
	"encap_drop_flow_miss_bytes",
	"encap_ok_packets",
	"encap_ok_bytes",
	"decap_drop_origin_not_allowed_packets",
	"decap_drop_origin_not_allowed_bytes",
	"decap_drop_oversize_packets",
	"decap_drop_oversize_bytes",
	"encap_drop_oversize_packets",
	"encap_drop_oversize_bytes",
}

// Metric is one interface's row for a counter: Ifindex identifies the
// interface and PerCPU holds that (ifindex, counter) key's per-CPU values.
// Metrics groups these under the counter name.
type Metric struct {
	Ifindex uint32
	PerCPU  []uint64
}

// Metrics reads the pinned metrics map and returns its rows grouped by counter
// name (from CounterNames). A counter value beyond CounterNames (a newer program
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

// flowKey is struct flow_key (bpf/geneve_defs.h) as the sweep sees it: the
// leading ifindex it filters on, and the other 40 bytes left opaque. Rest
// must be a named field: encoding/binary skips a blank (_) field when
// decoding but writes it as zeros when encoding, which would turn every key
// handed back to Delete into one that doesn't exist.
type flowKey struct {
	Ifindex uint32
	Rest    [40]byte
}

// outerHdrCache is struct outer_hdr_cache (bpf/geneve_defs.h): 82 bytes,
// padded to 84 by its 4-byte alignment. Only read to satisfy BatchLookup.
type outerHdrCache [84]byte

// metricKey is struct metric_key (bpf/maps.h).
type metricKey struct {
	Ifindex uint32
	Counter uint32
}

// FlowStateRemove deletes every entry in the pinned flow_state map belonging
// to ifindex — one removed ENI's cached flows, both address families in the
// one sweep since flow_state holds both.
func FlowStateRemove(ifindex uint32) error {
	return sweepByIfindex[flowKey, outerHdrCache]("flow_state", ifindex, func(k flowKey) uint32 { return k.Ifindex })
}

// FragStateRemove deletes every entry in the pinned frag_state map (encap's
// in-flight reply fragment tracking) belonging to ifindex.
func FragStateRemove(ifindex uint32) error {
	return sweepByIfindex[flowKey, outerHdrCache]("frag_state", ifindex, func(k flowKey) uint32 { return k.Ifindex })
}

// MetricsRemove deletes every entry in the pinned metrics map belonging to
// ifindex — one removed ENI's counter rows, so serve stops pushing counters
// for an interface that no longer exists.
func MetricsRemove(ifindex uint32) error {
	return sweepByIfindex[metricKey, uint64]("metrics", ifindex, func(k metricKey) uint32 { return k.Ifindex })
}

// sweepBatchSize is how many entries each BPF_MAP_LOOKUP_BATCH call asks for.
// A hash map's batch lookup returns whole buckets and fails with ENOSPC if one
// doesn't fit, in which case sweepByIfindex doubles it and retries.
const sweepBatchSize = 4096

// sweepByIfindex deletes every entry in the pinned map named mapName whose key
// belongs to ifindex (per keyIfindex). K and V must match the map's key and
// value layout; V is one CPU's value for a per-CPU map.
//
// It walks the map with batch lookups rather than BPF_MAP_GET_NEXT_KEY. A
// hash map's get-next-key restarts from the first bucket whenever the key it
// was handed has been deleted since, which a busy LRU map (flow_state) does
// constantly as it evicts. A batch lookup's cursor is a bucket index instead,
// so the walk finishes in one pass however much the map churns meanwhile.
//
// Matching keys are collected first, then deleted. A key that's already gone
// by then (evicted, most likely) is not an error. A missing pin is tolerated
// (returns nil): it just means nothing has been set up yet.
func sweepByIfindex[K, V any](mapName string, ifindex uint32, keyIfindex func(K) uint32) error {
	path := PinDir + "/" + mapName
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil
	}
	defer m.Close()

	valuesPerKey := 1
	if m.Type() == ebpf.PerCPUHash || m.Type() == ebpf.LRUCPUHash {
		if valuesPerKey, err = ebpf.PossibleCPU(); err != nil {
			return fmt.Errorf("ebpf.PossibleCPU failed: %w", err)
		}
	}

	var toDelete []K
	var cursor ebpf.MapBatchCursor
	batch := sweepBatchSize
	keys := make([]K, batch)
	values := make([]V, batch*valuesPerKey)
	for {
		n, err := m.BatchLookup(&cursor, keys, values, nil)
		for _, k := range keys[:n] {
			if keyIfindex(k) == ifindex {
				toDelete = append(toDelete, k)
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break // end of the map
		}
		if errors.Is(err, unix.ENOSPC) && batch < int(m.MaxEntries()) {
			// A bucket bigger than the batch; the cursor still points at
			// it, so retry the same bucket with room for it.
			batch *= 2
			keys = make([]K, batch)
			values = make([]V, batch*valuesPerKey)
			continue
		}
		if err != nil {
			return fmt.Errorf("(*ebpf.Map).BatchLookup for %s failed: %w", path, err)
		}
	}

	var errs []error
	for _, k := range toDelete {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("(*ebpf.Map).Delete for %s failed: %w", path, err))
		}
	}
	return errors.Join(errs...)
}
