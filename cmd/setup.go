package cmd

import (
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"

	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/encap"
)

var MaxENIs uint32 = 128
var MaxFlowsV4 uint32 = 1048576
var MaxFlowsV6 uint32 = 1
var Transparent bool = false

// ./gwlb-xdp setup
var SetupCmd = &cobra.Command{
	Use:   "setup <uplink-ifname>",
	Short: "Load and attach the XDP pipeline to the physical interface",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunSetup(args[0], MaxENIs, MaxFlowsV4, MaxFlowsV6, Transparent)
	},
}

func init() {
	RootCmd.AddCommand(SetupCmd)

	SetupCmd.Flags().Uint32Var(&MaxENIs, "max-enis", MaxENIs, "max concurrent ENIs this box can serve (sizes eni_to_ifindex)")
	SetupCmd.Flags().Uint32Var(&MaxFlowsV4, "max-flows-v4", MaxFlowsV4, "max concurrent IPv4 flows tracked (sizes flow_state_v4); <=1 disables IPv4")
	SetupCmd.Flags().Uint32Var(&MaxFlowsV6, "max-flows-v6", MaxFlowsV6, "max concurrent IPv6 flows tracked (sizes flow_state_v6); <=1 disables IPv6")
	SetupCmd.Flags().BoolVar(&Transparent, "transparent", Transparent, "hardcode every ENI on this box as a transparent appliance (reply comes back with the same 5-tuple, not swapped)")
}

func RunSetup(intfName string, maxENIs, maxFlowsV4, maxFlowsV6 uint32, transparent bool) error {
	intf, err := net.InterfaceByName(intfName)
	if err != nil {
		return fmt.Errorf("net.InterfaceByName for %q failed: %w", intfName, err)
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
		MaxENIs:    maxENIs,
		MaxFlowsV4: maxFlowsV4,
		MaxFlowsV6: maxFlowsV6,
	})
	if err != nil {
		return fmt.Errorf("decap.Load failed: %w", err)
	}
	if _, err := decapProg.Attach(intf.Index, intfName); err != nil {
		return fmt.Errorf("(*decap.Program).Attach for %q failed: %w", intfName, err)
	}

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
