package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/safchain/ethtool"
	"github.com/spf13/cobra"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/encap"
)

var MaxENIs uint32 = 128
var MaxFlows uint32 = 1048576
var MaxFragEntries uint32 = 16384
var Transparent bool = false
var AllowedOriginCIDR string

// ./gwlb-xdp setup
var SetupCmd = &cobra.Command{
	Use:   "setup <uplink-ifname>",
	Short: "Load and attach the XDP pipeline to the physical interface",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withStateLock(func() error {
			return RunSetup(args[0], MaxENIs, MaxFlows, MaxFragEntries, Transparent, AllowedOriginCIDR)
		})
	},
}

func init() {
	RootCmd.AddCommand(SetupCmd)

	SetupCmd.Flags().Uint32Var(&MaxENIs, "max-enis", MaxENIs, "max concurrent ENIs this box can serve (sizes eni_to_ifindex)")
	SetupCmd.Flags().Uint32Var(&MaxFlows, "max-flows", MaxFlows, "max concurrent flows tracked, IPv4 and IPv6 combined (sizes the shared flow_state map)")
	SetupCmd.Flags().Uint32Var(&MaxFragEntries, "max-frag-entries", MaxFragEntries, "max in-flight reply fragments tracked at once (sizes encap's frag_state map)")
	SetupCmd.Flags().BoolVar(&Transparent, "transparent", Transparent, "hardcode every ENI on this box as a transparent appliance (reply comes back with the same 5-tuple, not swapped)")
	SetupCmd.Flags().StringVar(&AllowedOriginCIDR, "allowed-origin-cidr", "", "accept GENEVE traffic only from this outer source IPv4 CIDR — the GWLB's subnet(s) — and drop any other origin; pass 0.0.0.0/0 to accept every origin")
	// Required, with 0.0.0.0/0 as the explicit opt-out: anyone else who can
	// reach UDP 6081 could otherwise inject packets into an ENI's netns, or
	// overwrite a flow's cached outer header and redirect its replies.
	if err := SetupCmd.MarkFlagRequired("allowed-origin-cidr"); err != nil {
		panic(err)
	}
}

func RunSetup(intfName string, maxENIs, maxFlows, maxFragEntries uint32, transparent bool, allowedOriginCIDR string) (err error) {
	intf, err := net.InterfaceByName(intfName)
	if err != nil {
		return fmt.Errorf("net.InterfaceByName for %q failed: %w", intfName, err)
	}

	var originCIDR netip.Prefix
	if allowedOriginCIDR != "" {
		originCIDR, err = ParseIPv4CIDR(allowedOriginCIDR)
		if err != nil {
			return fmt.Errorf("--allowed-origin-cidr: %w", err)
		}
	}

	// decap, encap and every ENI veth are sized from the uplink's MTU (see
	// bpf.MaxInnerLen), so a nonsensical one fails here, before anything is
	// loaded.
	maxInnerLen, err := bpf.MaxInnerLen(intf.MTU)
	if err != nil {
		return fmt.Errorf("bpf.MaxInnerLen for %q failed: %w", intfName, err)
	}

	// GWLB's documented 8500-byte inner packets need 8568 bytes on the
	// uplink once GENEVE's 68 are added. Warn only — plenty of deployments
	// never see packets that large.
	if minMTU := bpf.GWLBMTU + bpf.GeneveOverhead; intf.MTU < minMTU {
		fmt.Fprintf(os.Stderr,
			"gwlb-xdp: warning: %s's MTU is %d, below the %d GWLB's %d-byte "+
				"packets need once encapsulated — large packets will be dropped. "+
				"Raise %s's MTU (e.g. to 9001) if you need to support them.\n",
			intfName, intf.MTU, minMTU, bpf.GWLBMTU, intfName)
	}

	// decap usually runs as generic XDP (at a jumbo MTU, most NICs, ENA
	// included, refuse native XDP), which runs after GRO. With UDP GRO
	// forwarding enabled on the uplink, GENEVE packets can reach decap
	// merged into one oversized packet, which it can only drop. Warn rather
	// than change the uplink's own settings.
	warnUplinkUDPGRO(intfName)

	decapProg, err := decap.Load(decap.Config{
		MaxENIs:           maxENIs,
		MaxFlows:          maxFlows,
		MaxInnerLen:       uint32(maxInnerLen),
		AllowedOriginCIDR: originCIDR,
	})
	if err != nil {
		return fmt.Errorf("decap.Load failed: %w", err)
	}
	if _, err := decapProg.Attach(intf.Index, intfName); err != nil {
		return fmt.Errorf("(*decap.Program).Attach for %q failed: %w", intfName, err)
	}

	// From here on decap is attached and its maps are pinned. If a later step
	// fails, tear all of that back down so `setup` stays re-runnable rather
	// than wedging on the leftover decap link/pins the next time around.
	defer func() {
		if err != nil {
			if e := RunTeardown(); e != nil {
				err = errors.Join(err, fmt.Errorf("rollback: RunTeardown failed: %w", e))
			}
		}
	}()

	encapProg, err := encap.Load(encap.Config{
		Transparent:    transparent,
		Uplink:         intf,
		MaxFragEntries: maxFragEntries,
	})
	if err != nil {
		return fmt.Errorf("encap.Load failed: %w", err)
	}

	// Not attached here — `add` attaches this program per ENI veth-outer.
	if err := encapProg.Pin(); err != nil {
		return fmt.Errorf("(*encap.Program).Pin failed: %w", err)
	}
	return nil
}

// warnUplinkUDPGRO warns if any feature that lets GRO merge plain UDP
// datagrams (and so GENEVE packets, with no GENEVE tunnel device to
// terminate them) is enabled on ifname. Best-effort: failing to read the
// features just skips the warning.
func warnUplinkUDPGRO(ifname string) {
	et, err := ethtool.NewEthtool()
	if err != nil {
		return
	}
	defer et.Close()

	features, err := et.Features(ifname)
	if err != nil {
		return
	}
	for _, name := range [...]string{"rx-udp-gro-forwarding", "rx-gro-list"} {
		if features[name] {
			fmt.Fprintf(os.Stderr,
				"gwlb-xdp: warning: %s has %s enabled, which can merge GENEVE packets "+
					"into one before decap sees them — decap drops those as oversize "+
					"(decap_drop_oversize_*). Disable it (ethtool -K %s %s off).\n",
				ifname, name, ifname, name)
		}
	}
}
