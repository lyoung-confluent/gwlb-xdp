package cmd

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/encap"
)

var MaxENIs uint32 = 128
var MaxFlows uint32 = 1048576
var Transparent bool = false
var AllowedOriginCIDR string

// ./gwlb-xdp setup
var SetupCmd = &cobra.Command{
	Use:   "setup <uplink-ifname>",
	Short: "Load and attach the XDP pipeline to the physical interface",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunSetup(args[0], MaxENIs, MaxFlows, Transparent, AllowedOriginCIDR)
	},
}

func init() {
	RootCmd.AddCommand(SetupCmd)

	SetupCmd.Flags().Uint32Var(&MaxENIs, "max-enis", MaxENIs, "max concurrent ENIs this box can serve (sizes eni_to_ifindex)")
	SetupCmd.Flags().Uint32Var(&MaxFlows, "max-flows", MaxFlows, "max concurrent flows tracked, IPv4 and IPv6 combined (sizes the shared flow_state map)")
	SetupCmd.Flags().BoolVar(&Transparent, "transparent", Transparent, "hardcode every ENI on this box as a transparent appliance (reply comes back with the same 5-tuple, not swapped)")
	SetupCmd.Flags().StringVar(&AllowedOriginCIDR, "allowed-origin-cidr", "", "restrict accepted GENEVE traffic to this outer source IPv4 CIDR (any other origin is dropped); if unset, every origin is accepted")
}

func RunSetup(intfName string, maxENIs, maxFlows uint32, transparent bool, allowedOriginCIDR string) (err error) {
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

	// AWS recommends an MTU of at least 8564 for GWLB's full 8500-byte
	// packets. Warn only — plenty of deployments never see packets that large.
	if intf.MTU < 8564 {
		fmt.Fprintf(os.Stderr,
			"gwlb-xdp: warning: %s's MTU is %d, below the 8564 AWS recommends "+
				"for GWLB's full 8500-byte packet support — large packets may be "+
				"dropped. Raise %s's MTU (e.g. to 9001) if you need to support them.\n",
			intfName, intf.MTU, intfName)
	}

	decapProg, err := decap.Load(decap.Config{
		MaxENIs:           maxENIs,
		MaxFlows:          maxFlows,
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
		Transparent: transparent,
		Uplink:      intf,
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
