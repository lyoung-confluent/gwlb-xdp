package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
	"github.com/safchain/ethtool"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/encap"
)

// --script
var ScriptPath string

// --no-netns
var NoNetns bool

// ./gwlb-xdp add
var AddCmd = &cobra.Command{
	Use:   "add <vpce-0000000aabbccddee>",
	Short: "Provision one ENI on the fly",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunAdd(args[0], ScriptPath, !NoNetns)
	},
}

func init() {
	AddCmd.Flags().StringVar(&ScriptPath, "script", "", "run this executable after the veth (and netns, unless --no-netns) are up but before traffic can reach this ENI (see above)")
	AddCmd.Flags().BoolVar(&NoNetns, "no-netns", false, "keep this ENI's veth pair in the root netns instead of a dedicated one — only safe when this ENI's backend addressing doesn't overlap any other ENI's on this box")
	RootCmd.AddCommand(AddCmd)
}

// RunAdd provisions one ENI's veth pair. When isolated, the veth-inner peer
// moves into a dedicated netns named vpceID (the normal case); when not, it
// stays alongside veth-outer in the root netns — only safe when no other ENI
// on this box has overlapping backend addressing, since nothing then
// separates their routing tables.
func RunAdd(vpceID string, scriptPath string, isolated bool) (err error) {
	if scriptPath != "" {
		if _, err := os.Stat(scriptPath); err != nil {
			return fmt.Errorf("os.Stat for --script %q failed: %w", scriptPath, err)
		}
	}

	gwlbID, err := ParseVPCEID(vpceID)
	if err != nil {
		return fmt.Errorf("ParseVPCEID for %q failed: %w", vpceID, err)
	}

	outerName := FormatInterfaceName(gwlbID, false)
	innerName := FormatInterfaceName(gwlbID, true)

	var newns netns.NsHandle
	var nsh *netlink.Handle
	if isolated {
		newns, err = CreateNamedNetns(vpceID)
		if err != nil {
			return fmt.Errorf("CreateNamedNetns for %q failed: %w", vpceID, err)
		}
		defer newns.Close()

		nsh, err = netlink.NewHandleAt(newns)
	} else {
		nsh, err = netlink.NewHandle()
	}
	if err != nil {
		return fmt.Errorf("getting a netlink handle for %q failed: %w", vpceID, err)
	}
	defer nsh.Close()

	// Roll back partial state on any error. Deleting the outer end also
	// removes its peer (veth ends are linked by ifindex), so this cleans up
	// no matter how far below we fail. Cleanup failures are joined onto err
	// so a leaked veth/netns doesn't vanish silently.
	defer func() {
		if err != nil {
			// If AddENI already ran (it's the second-to-last step), its
			// eni_to_ifindex entry would otherwise outlive the veth we're
			// about to delete — leaving decap redirecting this ENI's traffic
			// to a dead (and eventually recycled) ifindex, and blocking any
			// re-add since AddENI refuses to overwrite. Sweep it too. A
			// not-yet-inserted entry just isn't found (ErrKeyNotExist), and a
			// failure so early that setup's map pin doesn't exist yet
			// (os.ErrNotExist) likewise means there's nothing to undo — neither
			// is a rollback failure.
			if _, e := decap.RemoveENI(gwlbID); e != nil &&
				!errors.Is(e, ebpf.ErrKeyNotExist) && !errors.Is(e, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("rollback: decap.RemoveENI for %q failed: %w", vpceID, e))
			}
			if link, e := netlink.LinkByName(outerName); e == nil {
				if e := netlink.LinkDel(link); e != nil {
					err = errors.Join(err, fmt.Errorf("rollback: netlink.LinkDel for %q failed: %w", outerName, e))
				}
			}
			if isolated {
				if e := netns.DeleteNamed(vpceID); e != nil && !errors.Is(e, os.ErrNotExist) {
					err = errors.Join(err, fmt.Errorf("rollback: netns.DeleteNamed for %q failed: %w", vpceID, e))
				}
			}
		}
	}()

	// MTU 9001 (jumbo): the decapped inner packet can be nearly the full
	// 8568-byte GENEVE payload, and veth forwarding silently drops over-MTU
	// frames.
	//
	// Both ends already have their final, distinct names (outer and inner
	// never collide, isolated or not), so they're created in place in the
	// root netns with no rename needed — isolated just additionally migrates
	// the inner end into its dedicated netns afterwards.
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: outerName, MTU: 9001},
		PeerName:  innerName,
		PeerMTU:   9001,
	}); err != nil {
		return fmt.Errorf("netlink.LinkAdd for veth pair %s/%s failed: %w", outerName, innerName, err)
	}

	if isolated {
		peer, err := netlink.LinkByName(innerName)
		if err != nil {
			return fmt.Errorf("netlink.LinkByName for %q failed: %w", innerName, err)
		}
		if err := netlink.LinkSetNsFd(peer, int(newns)); err != nil {
			return fmt.Errorf("netlink.LinkSetNsFd for %q into netns %s failed: %w", innerName, vpceID, err)
		}
	}

	inner, err := nsh.LinkByName(innerName)
	if err != nil {
		return fmt.Errorf("(*netlink.Handle).LinkByName for %q failed: %w", innerName, err)
	}

	// Bring up both the inner/outer interfaces.
	outer, err := netlink.LinkByName(outerName)
	if err != nil {
		return fmt.Errorf("netlink.LinkByName for %q failed: %w", outerName, err)
	}
	if err := netlink.LinkSetUp(outer); err != nil {
		return fmt.Errorf("netlink.LinkSetUp for %q failed: %w", outerName, err)
	}
	if err := nsh.LinkSetUp(inner); err != nil {
		return fmt.Errorf("(*netlink.Handle).LinkSetUp for %q failed: %w", innerName, err)
	}

	// Disable TX checksum offload so the egress path writes real L4
	// checksums into the bytes — encap can't compute them in BPF.
	disableChecksumOffload := func() error {
		et, err := ethtool.NewEthtool()
		if err != nil {
			return fmt.Errorf("ethtool.NewEthtool failed: %w", err)
		}
		defer et.Close()

		if err := et.Change(innerName, map[string]bool{
			"tx-checksum-ip-generic": false,
		}); err != nil {
			return fmt.Errorf("(*ethtool.Ethtool).Change for %q failed: %w", innerName, err)
		}
		return nil
	}
	if isolated {
		if err := WithNetns(newns, disableChecksumOffload); err != nil {
			return fmt.Errorf("WithNetns for %q failed: %w", vpceID, err)
		}
	} else if err := disableChecksumOffload(); err != nil {
		return err
	}

	mac := inner.Attrs().HardwareAddr
	if len(mac) == 0 {
		return fmt.Errorf("inner interface %s has no hardware address", innerName)
	}

	// Last chance to finish backend setup before this ENI is wired up and
	// reachable below (see the --script flag).
	if scriptPath != "" {
		cmd := exec.Command(scriptPath, vpceID, innerName)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("(*exec.Cmd).Run for --script %q failed: %w", scriptPath, err)
		}
	}

	// Insert into eni_to_ifindex and attach encap — this makes the ENI
	// reachable, so it happens last.
	outerIface, err := net.InterfaceByName(outerName)
	if err != nil {
		return fmt.Errorf("net.InterfaceByName for %q failed: %w", outerName, err)
	}

	if err := decap.AddENI(gwlbID, uint32(outerIface.Index), mac, outerIface.HardwareAddr); err != nil {
		return fmt.Errorf("decap.AddENI for %q failed: %w", outerName, err)
	}

	if _, err := encap.Attach(outerIface.Index); err != nil {
		return fmt.Errorf("encap.Attach for %q failed: %w", outerName, err)
	}

	return nil
}
