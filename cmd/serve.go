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
// interval and pushes each counter's current value to statsdAddr as a statsd
// gauge (the shape the CloudWatch agent turns into a CloudWatch metric),
// batching one interface's counters per datagram. When interval <= 0 no statsd
// connection is made and only health is served. Blocks until ctx is cancelled
// (SIGINT) or the health server fails.
//
// Gauge values are the counters' running cumulative totals (they reset only
// when the programs are reloaded); take a rate/delta at query time for
// per-period numbers.
func RunServe(ctx context.Context, healthAddr, statsdAddr string, interval time.Duration) error {
	// Metrics push is opt-out via a non-positive interval: dial statsd and arm
	// the ticker only when enabled. A nil tick channel never fires, so the
	// select below serves health-only with no special-casing. net.Dial for UDP
	// resolves the address but sends nothing, so it succeeds even before the
	// agent is up.
	var conn net.Conn
	var tick <-chan time.Time
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
		// Liveness on any path: 200 while decap is attached, 503 otherwise.
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !decap.Attached() {
				http.Error(w, "decap not attached", http.StatusServiceUnavailable)
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
			if err := flushGauges(conn); err != nil {
				// Keep the daemon alive across a transient failure so a
				// momentary hiccup doesn't take metrics down.
				fmt.Fprintf(os.Stderr, "gwlb-xdp: serve: %v\n", err)
			}
		}
	}
}

// flushGauges samples every counter and writes its current value to conn as a
// statsd gauge, batching all of one interface's counters into a single UDP
// datagram (newline-separated lines — the DogStatsD multi-metric form). A
// sampling failure returns early; per-datagram write failures are joined and
// returned once the rest have been tried (a dropped statsd datagram is a lost
// sample, inherent to UDP).
func flushGauges(conn net.Conn) error {
	cur, err := sampleCounters()
	if err != nil {
		return err
	}
	labels, err := interfaceTags()
	if err != nil {
		return err
	}

	// Group each interface's counters so they go out as one datagram. One
	// interface has at most len(bpf.CounterNames) counters, so a datagram stays
	// well under any UDP size limit — no chunking needed.
	perIface := make(map[uint32][]string)
	for key, val := range cur {
		// A row whose ifindex has no live interface (e.g. a veth deleted
		// out-of-band, or a remove whose metrics sweep failed) has no tags —
		// skip it rather than emit a dimensionless series, matching what the
		// old Prometheus exporter did.
		tags, ok := labels[key.ifindex]
		if !ok {
			continue
		}
		// One DogStatsD gauge line: gwlb_xdp.<name>:<value>|g|#tag:val,... —
		// tags is the pre-formatted "|#..." suffix (see interfaceTags).
		perIface[key.ifindex] = append(perIface[key.ifindex],
			fmt.Sprintf("gwlb_xdp.%s:%d|g%s", bpf.CounterNames[key.counter], val, tags))
	}

	var errs []error
	for _, lines := range perIface {
		if _, err := conn.Write([]byte(strings.Join(lines, "\n"))); err != nil {
			errs = append(errs, fmt.Errorf("writing to statsd endpoint failed: %w", err))
		}
	}
	return errors.Join(errs...)
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
