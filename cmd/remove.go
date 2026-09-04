package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/encap"
)

// ./gwlb-xdp remove
var RemoveCmd = &cobra.Command{
	Use:   "remove <vpce-0000000aabbccddee>",
	Short: `Reverse "add"`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunRemove(args[0])
	},
}

func init() {
	RootCmd.AddCommand(RemoveCmd)
}

func RunRemove(vpceID string) error {
	gwlbID, err := ParseVPCEID(vpceID)
	if err != nil {
		return fmt.Errorf("ParseVPCEID for %q failed: %w", vpceID, err)
	}
	ifname := FormatInterfaceName(gwlbID)

	// A non-zero Ifindex means the entry was deleted even if the error is set
	// (see RemoveENI), so that — not the error — gates detaching encap.
	info, removeErr := decap.RemoveENI(gwlbID)
	errs := []error{removeErr}
	if info.Ifindex != 0 {
		if err := encap.Detach(int(info.Ifindex)); err != nil {
			errs = append(errs, fmt.Errorf("encap.Detach for ifindex %d failed: %w", info.Ifindex, err))
		}
	}

	// Deleting the outer end removes its netns peer too; then drop the netns.
	// Both best-effort — a missing link or netns just means nothing to clean.
	if link, err := netlink.LinkByName(ifname); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			errs = append(errs, fmt.Errorf("netlink.LinkDel for %q failed: %w", ifname, err))
		}
	}
	if err := netns.DeleteNamed(vpceID); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("netns.DeleteNamed for %q failed: %w", vpceID, err))
	}

	return errors.Join(errs...)
}
