package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
)

// --listen: address for the HTTP liveness server (any path returns health).
var HealthAddr = ":6082"

// --statsd: host:port of the statsd endpoint BPF counters are pushed to. The
// default is the CloudWatch agent's standard statsd listener on localhost.
// Ignored when the push interval is disabled (see MetricsInterval).
var StatsdAddr = "127.0.0.1:8125"

// --interval: how often the BPF counters are sampled and pushed. Zero (the
// default) or negative disables pushing entirely — the command then only
// serves health.
var MetricsInterval time.Duration = 0

// ./gwlb-xdp serve
var ServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the HTTP liveness endpoint, and optionally push BPF counters to statsd",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunServe(cmd.Context(), HealthAddr, StatsdAddr, MetricsInterval)
	},
}

func init() {
	ServeCmd.Flags().StringVar(&HealthAddr, "listen", HealthAddr, "address[:port] for the HTTP liveness server (any path returns health)")
	ServeCmd.Flags().StringVar(&StatsdAddr, "statsd", StatsdAddr, "host:port of the statsd endpoint to push BPF counters to (typically the local CloudWatch agent); ignored when --interval <= 0")
	ServeCmd.Flags().DurationVar(&MetricsInterval, "interval", MetricsInterval, "how often to sample and push the BPF counters to statsd; 0 (the default) or negative disables pushing and serves only health")

	RootCmd.AddCommand(ServeCmd)
}

// counterKey identifies one BPF counter row: a specific interface's value for
// one enum metric (its index into bpf.CounterNames).
type counterKey struct {
	ifindex uint32
	counter int
}

// RunServe runs the HTTP liveness server on healthAddr — the command's primary
// job — and, when interval > 0, also samples the pinned BPF counter map every
// interval and pushes how much each counter grew since the previous sample to
// statsdAddr as a statsd counter (the shape the CloudWatch agent turns into a
// CloudWatch metric, summed per period), batching one interface's counters per
// datagram. When interval <= 0 no statsd connection is made and only health is
// served. Blocks until ctx is cancelled (SIGINT/SIGTERM) or the health server
// fails.
//
// Deltas rather than the BPF map's cumulative totals: the totals drop back to
// zero whenever an ENI is removed and re-added or the programs are reloaded,
// and CloudWatch has no reset-aware rate() to take over raw totals. The first
// sample only sets the baseline, so starting serve on a long-running box
// doesn't push everything counted so far as one burst.
func RunServe(ctx context.Context, healthAddr, statsdAddr string, interval time.Duration) error {
	// Metrics push is opt-out via a non-positive interval: dial statsd and arm
	// the ticker only when enabled. A nil tick channel never fires, so the
	// select below serves health-only with no special-casing. net.Dial for UDP
	// resolves the address but sends nothing, so it succeeds even before the
	// agent is up.
	var conn net.Conn
	var tick <-chan time.Time
	var prev map[counterKey]uint64 // nil until the first sample
	if interval > 0 {
		c, err := net.Dial("udp", statsdAddr)
		if err != nil {
			return fmt.Errorf("net.Dial(udp, %q) for statsd failed: %w", statsdAddr, err)
		}
		defer c.Close()
		conn = c

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		tick = ticker.C
	}

	srv := &http.Server{
		Addr: healthAddr,
		// Liveness on any path: 200 while decap is attached to an uplink
		// that's up with carrier, 503 otherwise.
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := checkHealth(); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	srvErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
			return
		}
		srvErr <- nil
	}()

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shutdownCtx)
		case err := <-srvErr:
			return fmt.Errorf("health server on %q failed: %w", healthAddr, err)
		case <-tick:
			var err error
			if prev, err = flushCounters(conn, prev); err != nil {
				// Keep the daemon alive across a transient failure so a
				// momentary hiccup doesn't take metrics down.
				fmt.Fprintf(os.Stderr, "gwlb-xdp: serve: %v\n", err)
			}
		}
	}
}

// flushCounters samples every counter and writes how much it grew since prev
// (the previous sample) to conn as statsd counters (see counterLines),
// batching all of one interface's counters into a single UDP datagram
// (newline-separated lines — the DogStatsD multi-metric form). It returns the
// new sample, to pass back as prev next time. With a nil prev nothing is
// written: this sample is only the baseline.
//
// A sampling failure returns prev unchanged, so the next tick's deltas still
// cover the whole gap. Per-datagram write failures are joined and returned
// once the rest have been tried (a dropped statsd datagram is a lost sample,
// inherent to UDP).
func flushCounters(conn net.Conn, prev map[counterKey]uint64) (map[counterKey]uint64, error) {
	cur, err := sampleCounters()
	if err != nil {
		return prev, err
	}
	if prev == nil {
		return cur, nil
	}
	labels, err := interfaceTags()
	if err != nil {
		return prev, err
	}

	var errs []error
	for _, lines := range counterLines(cur, prev, labels) {
		for _, datagram := range packLines(lines, maxStatsdDatagram) {
			if _, err := conn.Write([]byte(datagram)); err != nil {
				errs = append(errs, fmt.Errorf("writing to statsd endpoint failed: %w", err))
			}
		}
	}
	return cur, errors.Join(errs...)
}

// counterLines returns one DogStatsD counter line per row of cur — how much
// it grew since prev — grouped by ifindex so each interface's counters can go
// out together. labels holds each ifindex's pre-formatted "|#..." tag suffix
// (see interfaceTags).
//
// A row missing from prev is new since then and started at zero, so its
// delta is its whole value; so is a row whose value went down, which can
// only mean it was swept (ENI removed) and recreated in between.
func counterLines(cur, prev map[counterKey]uint64, labels map[uint32]string) map[uint32][]string {
	perIface := make(map[uint32][]string)
	for key, val := range cur {
		// A row whose ifindex has no live interface (e.g. a veth deleted
		// out-of-band, or a remove whose metrics sweep failed) has no tags —
		// skip it rather than emit a dimensionless series.
		tags, ok := labels[key.ifindex]
		if !ok {
			continue
		}
		delta := val
		if p := prev[key]; val >= p {
			delta = val - p
		}
		// gwlb_xdp.<name>:<delta>|c|#tag:val,...
		perIface[key.ifindex] = append(perIface[key.ifindex],
			fmt.Sprintf("gwlb_xdp.%s:%d|c%s", bpf.CounterNames[key.counter], delta, tags))
	}
	return perIface
}

// maxStatsdDatagram caps each statsd datagram's payload at the common safe
// size for a 1500-byte path MTU (1500 - IPv4 20 - UDP 8 - headroom), which
// statsd servers' default read buffers also accommodate. One interface's
// counters, each line carrying its full tag suffix, can exceed it.
const maxStatsdDatagram = 1432

// packLines joins lines with newlines into as few datagrams as possible,
// each at most max bytes. A single line longer than max still goes out, alone
// in its own datagram, rather than being dropped.
func packLines(lines []string, max int) []string {
	var datagrams []string
	var cur strings.Builder
	for _, line := range lines {
		if cur.Len() > 0 && cur.Len()+1+len(line) > max {
			datagrams = append(datagrams, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte('\n')
		}
		cur.WriteString(line)
	}
	if cur.Len() > 0 {
		datagrams = append(datagrams, cur.String())
	}
	return datagrams
}

// checkHealth reports why this box can't pass traffic, or nil if it can:
// decap must still be attached, and the uplink it's attached to must be up
// with carrier.
func checkHealth() error {
	ifindex, err := decap.UplinkIfindex()
	if err != nil {
		return fmt.Errorf("decap not attached: %w", err)
	}
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("uplink (ifindex %d) not found: %w", ifindex, err)
	}
	attrs := link.Attrs()
	if attrs.Flags&net.FlagUp == 0 || attrs.RawFlags&unix.IFF_LOWER_UP == 0 {
		return fmt.Errorf("uplink %s is down or has no carrier", attrs.Name)
	}
	return nil
}

// sampleCounters reads the pinned metrics map and returns each counter's
// current value, summed across CPUs. The per-CPU split the BPF map keeps is a
// datapath concern (lock-free per-CPU increments); nothing downstream of statsd
// wants it, so it's collapsed here.
func sampleCounters() (map[counterKey]uint64, error) {
	byName, err := bpf.Metrics()
	if err != nil {
		return nil, fmt.Errorf("bpf.Metrics failed: %w", err)
	}
	cur := make(map[counterKey]uint64)
	for i, name := range bpf.CounterNames {
		for _, m := range byName[name] {
			var sum uint64
			for _, v := range m.PerCPU {
				sum += v
			}
			cur[counterKey{ifindex: m.Ifindex, counter: i}] += sum
		}
	}
	return cur, nil
}

// interfaceTags maps each interface's ifindex to the DogStatsD tag suffix the
// CloudWatch agent turns into CloudWatch dimensions: interface always, plus
// gwlb_id when the interface is one of this box's provisioned ENIs. Rebuilt
// every tick since interfaces come and go as ENIs are added/removed.
func interfaceTags() (map[uint32]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces failed: %w", err)
	}
	tags := make(map[uint32]string, len(ifaces))
	for _, intf := range ifaces {
		suffix := "|#interface:" + intf.Name
		if gwlbID, ok := ParseInterfaceName(intf.Name); ok {
			suffix += ",gwlb_id:" + FormatVPCEID(gwlbID)
		}
		tags[uint32(intf.Index)] = suffix
	}
	return tags, nil
}
