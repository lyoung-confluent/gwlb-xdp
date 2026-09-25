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
		return withStateLock(func() error { return RunRemove(args[0]) })
	},
}

func init() {
	RootCmd.AddCommand(RemoveCmd)
}

// RunRemove doesn't need to know whether the endpoint was added with --no-netns:
// the outer veth is found by ifindex (from the BPF map, when present) or by
// its name, which — unlike the netns it and its peer end up in — doesn't
// depend on the mode.
//
// Teardown runs in the order that lets nothing repopulate what the endpoint
// cached: stop decap delivering to it, detach encap, delete the veth, and
// only then sweep its flow_state/frag_state/metrics entries (see
// decap.SweepEndpoint).
func RunRemove(vpceID string) error {
	gwlbID, err := ParseVPCEID(vpceID)
	if err != nil {
		return fmt.Errorf("ParseVPCEID for %q failed: %w", vpceID, err)
	}
	// The netns was named after the canonical spelling (see RunAdd).
	vpceID = FormatVPCEID(gwlbID)

	var errs []error
	info, err := decap.RemoveEndpoint(gwlbID)
	if err != nil {
		errs = append(errs, err)
	}

	// No map entry to read an ifindex from (e.g. a repeated remove, or an
	// add that failed partway) — fall back to the outer end's name (the same
	// regardless of --no-netns), so a leftover veth and encap pin still get
	// cleaned up.
	ifindex := int(info.Ifindex)
	fromMap := ifindex != 0
	if !fromMap {
		if link, err := netlink.LinkByName(FormatInterfaceName(gwlbID, false)); err == nil {
			ifindex = link.Attrs().Index
		}
	}

	if ifindex != 0 {
		// Without a map entry, encap may never have been attached at all.
		if err := encap.Detach(ifindex); err != nil && (fromMap || !errors.Is(err, os.ErrNotExist)) {
			errs = append(errs, fmt.Errorf("encap.Detach for ifindex %d failed: %w", ifindex, err))
		}

		// Deleting the outer end removes its peer too (veth ends are linked
		// by ifindex) — regardless of whether that peer sits in a netns or
		// alongside it in the root netns. A missing link just means nothing
		// to clean up.
		if link, err := netlink.LinkByIndex(ifindex); err == nil {
			if err := netlink.LinkDel(link); err != nil {
				errs = append(errs, fmt.Errorf("netlink.LinkDel for ifindex %d failed: %w", ifindex, err))
			}
		}

		if err := decap.SweepEndpoint(uint32(ifindex)); err != nil {
			errs = append(errs, fmt.Errorf("decap.SweepEndpoint for ifindex %d failed: %w", ifindex, err))
		}
	}

	// Best-effort: no netns exists at all for a --no-netns endpoint, which
	// netns.DeleteNamed reports as os.ErrNotExist — not an error here.
	if err := netns.DeleteNamed(vpceID); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("netns.DeleteNamed for %q failed: %w", vpceID, err))
	}

	return errors.Join(errs...)
}
