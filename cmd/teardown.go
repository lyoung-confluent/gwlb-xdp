package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
)

// ./gwlb-xdp teardown
var TeardownCmd = &cobra.Command{
	Use:   "teardown",
	Short: `Reverse "setup"`,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunTeardown()
	},
}

func init() {
	RootCmd.AddCommand(TeardownCmd)
}

// RunTeardown reverses setup: it deprovisions any remaining ENIs, detaches
// decap, and removes everything pinned under /sys/fs/bpf/gwlb-xdp.
//
// Best-effort throughout: every step runs regardless of the previous, so a
// partially-initialized or already-torn-down box is still fully cleaned. Any
// errors along the way are joined and returned.
func RunTeardown() error {
	var errs []error

	gwlbIDs, err := decap.ProvisionedENIs()
	if err != nil {
		errs = append(errs, fmt.Errorf("listing provisioned ENIs: %w", err))
	}
	for _, gwlbID := range gwlbIDs {
		vpceID := FormatVPCEID(gwlbID)
		if err := RunRemove(vpceID); err != nil {
			errs = append(errs, fmt.Errorf("deprovisioning %s: %w", vpceID, err))
		}
	}

	// Only if the pin exists, so tearing down an uninitialized box stays quiet.
	if _, err := os.Stat(decap.PinLink); err == nil {
		if err := decap.Detach(); err != nil {
			errs = append(errs, fmt.Errorf("detaching decap: %w", err))
		}
	}

	if err := bpf.RemovePinDir(); err != nil {
		errs = append(errs, fmt.Errorf("bpf.RemovePinDir failed: %w", err))
	}

	return errors.Join(errs...)
}
