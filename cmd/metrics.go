package cmd

import (
	"fmt"
	"net"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
)

// --listen
var MetricsAddr = ":6082"

// ./gwlb-xdp metrics
var MetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Serve the BPF packet counters as Prometheus metrics",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunMetrics(MetricsAddr)
	},
}

func init() {
	MetricsCmd.Flags().StringVar(&MetricsAddr, "listen", MetricsAddr, "address[:port] for the HTTP metrics/liveness server")

	RootCmd.AddCommand(MetricsCmd)
}

func RunMetrics(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !decap.Attached() {
			http.Error(w, "decap not attached", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/metrics", MetricsHandler)

	return http.ListenAndServe(addr, mux)
}

func MetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintln(w, "# HELP gwlb_decap_attached Whether decap is currently attached to the physical interface.")
	fmt.Fprintln(w, "# TYPE gwlb_decap_attached gauge")
	if decap.Attached() {
		fmt.Fprintln(w, "gwlb_decap_attached 1")
	} else {
		fmt.Fprintln(w, "gwlb_decap_attached 0")
	}

	byName, err := bpf.Metrics()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	labelCache := make(map[uint32]string, len(ifaces))
	for _, intf := range ifaces {
		labels := fmt.Sprintf("interface=%q", intf.Name)
		if gwlbID, ok := ParseInterfaceName(intf.Name); ok {
			labels = fmt.Sprintf("interface=%q,gwlb_id=%q", intf.Name, FormatVPCEID(gwlbID))
		}
		labelCache[uint32(intf.Index)] = labels
	}

	for _, name := range bpf.CounterNames {
		metric := "gwlb_xdp_" + name + "_total"
		fmt.Fprintf(w, "# HELP %s Packets counted by the gwlb-xdp BPF programs for the %q outcome, by originating interface and CPU. gwlb_id is added when that interface is one of this box's provisioned ENIs; decap events counted before an ENI is resolved are attributed to the uplink interface it's attached to.\n", metric, name)
		fmt.Fprintf(w, "# TYPE %s counter\n", metric)
		for _, e := range byName[name] {
			for cpu, v := range e.PerCPU {
				fmt.Fprintf(w, "%s{%s,cpu=\"%d\"} %d\n", metric, labelCache[e.Ifindex], cpu, v)
			}
		}
	}

	fmt.Fprintln(w, "# HELP gwlb_xdp_flow_cache_entries Current number of entries in the flow_state cache map, by address family. A family disabled at setup is omitted.")
	fmt.Fprintln(w, "# TYPE gwlb_xdp_flow_cache_entries gauge")
	if count, enabled, err := bpf.FlowStateEntries(false); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if enabled {
		fmt.Fprintf(w, "gwlb_xdp_flow_cache_entries{family=%q} %d\n", "v4", count)
	}
	if count, enabled, err := bpf.FlowStateEntries(true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if enabled {
		fmt.Fprintf(w, "gwlb_xdp_flow_cache_entries{family=%q} %d\n", "v6", count)
	}
}
