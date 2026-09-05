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

// RunRemove doesn't need to know whether the ENI was added with --no-netns:
// the outer veth is found by ifindex (from the BPF map, when present) or by
// trying every naming scheme add could have used, rather than by
// reconstructing a name that depends on the mode.
func RunRemove(vpceID string) error {
	gwlbID, err := ParseVPCEID(vpceID)
	if err != nil {
		return fmt.Errorf("ParseVPCEID for %q failed: %w", vpceID, err)
	}

	// A non-zero Ifindex means the entry was deleted even if the error is set
	// (see RemoveENI), so that — not the error — gates detaching encap and
	// finding the veth by ifindex below.
	info, removeErr := decap.RemoveENI(gwlbID)
	errs := []error{removeErr}
	if info.Ifindex != 0 {
		if err := encap.Detach(int(info.Ifindex)); err != nil {
			errs = append(errs, fmt.Errorf("encap.Detach for ifindex %d failed: %w", info.Ifindex, err))
		}

		// Deleting the outer end removes its peer too (veth ends are linked
		// by ifindex) — regardless of whether that peer sits in a netns or
		// alongside it in the root netns. Best-effort: a missing link just
		// means nothing to clean up.
		if link, err := netlink.LinkByIndex(int(info.Ifindex)); err == nil {
			if err := netlink.LinkDel(link); err != nil {
				errs = append(errs, fmt.Errorf("netlink.LinkDel for ifindex %d failed: %w", info.Ifindex, err))
			}
		}
	} else {
		// No map entry to read an ifindex from (e.g. a repeated remove, or
		// the ENI was never provisioned) — fall back to name-based lookup
		// across every naming scheme add could have used, so any leftover
		// veth still gets cleaned up.
		for _, ifname := range []string{FormatInterfaceName(gwlbID, true, false), FormatInterfaceName(gwlbID, false, false)} {
			if link, err := netlink.LinkByName(ifname); err == nil {
				if err := netlink.LinkDel(link); err != nil {
					errs = append(errs, fmt.Errorf("netlink.LinkDel for %q failed: %w", ifname, err))
				}
			}
		}
	}

	// Best-effort: no netns exists at all for a --no-netns ENI, which
	// netns.DeleteNamed reports as os.ErrNotExist — not an error here.
	if err := netns.DeleteNamed(vpceID); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("netns.DeleteNamed for %q failed: %w", vpceID, err))
	}

	return errors.Join(errs...)
}
