package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/safchain/ethtool"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/encap"
)

// --script
var ScriptPath string

// ./gwlb-xdp add
var AddCmd = &cobra.Command{
	Use:   "add <vpce-0000000aabbccddee>",
	Short: "Provision one ENI on the fly",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunAdd(args[0], ScriptPath)
	},
}

func init() {
	AddCmd.Flags().StringVar(&ScriptPath, "script", "", "run this executable after the netns/veth are up but before traffic can reach this ENI (see above)")
	RootCmd.AddCommand(AddCmd)
}

func RunAdd(vpceID string, scriptPath string) (err error) {
	if scriptPath != "" {
		if _, err := os.Stat(scriptPath); err != nil {
			return fmt.Errorf("os.Stat for --script %q failed: %w", scriptPath, err)
		}
	}

	gwlbID, err := ParseVPCEID(vpceID)
	if err != nil {
		return fmt.Errorf("ParseVPCEID for %q failed: %w", vpceID, err)
	}

	ifname := FormatInterfaceName(gwlbID)
	peerTmp := fmt.Sprintf("gwlb-tmp%d", os.Getpid())

	newns, err := CreateNamedNetns(vpceID)
	if err != nil {
		return fmt.Errorf("CreateNamedNetns for %q failed: %w", vpceID, err)
	}
	defer newns.Close()

	// Roll back partial state on any error. Deleting the outer end also
	// removes its peer in the netns (veth ends are linked by ifindex), so
	// this cleans up no matter how far below we fail. Cleanup failures are
	// joined onto err so a leaked veth/netns doesn't vanish silently.
	defer func() {
		if err != nil {
			if link, e := netlink.LinkByName(ifname); e == nil {
				if e := netlink.LinkDel(link); e != nil {
					err = errors.Join(err, fmt.Errorf("rollback: netlink.LinkDel for %q failed: %w", ifname, e))
				}
			}
			if e := netns.DeleteNamed(vpceID); e != nil && !errors.Is(e, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("rollback: netns.DeleteNamed for %q failed: %w", vpceID, e))
			}
		}
	}()

	// MTU 9001 (jumbo): the decapped inner packet can be nearly the full
	// 8568-byte GENEVE payload, and veth forwarding silently drops over-MTU
	// frames.
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: ifname, MTU: 9001},
		PeerName:  peerTmp,
		PeerMTU:   9001,
	}); err != nil {
		return fmt.Errorf("netlink.LinkAdd for veth pair %s/%s failed: %w", ifname, peerTmp, err)
	}

	// Migrate the peer into the new netns.
	peer, err := netlink.LinkByName(peerTmp)
	if err != nil {
		return fmt.Errorf("netlink.LinkByName for %q failed: %w", peerTmp, err)
	}
	if err := netlink.LinkSetNsFd(peer, int(newns)); err != nil {
		return fmt.Errorf("netlink.LinkSetNsFd for %q into netns %s failed: %w", peerTmp, vpceID, err)
	}

	nsh, err := netlink.NewHandleAt(newns)
	if err != nil {
		return fmt.Errorf("netlink.NewHandleAt for netns %q failed: %w", vpceID, err)
	}
	defer nsh.Close()

	// Rename the peer to match the outer interface name.
	inner, err := nsh.LinkByName(peerTmp)
	if err != nil {
		return fmt.Errorf("(*netlink.Handle).LinkByName for %q in netns %s failed: %w", peerTmp, vpceID, err)
	}
	if err := nsh.LinkSetName(inner, ifname); err != nil {
		return fmt.Errorf("(*netlink.Handle).LinkSetName for %q to %q in netns %s failed: %w", peerTmp, ifname, vpceID, err)
	}
	inner, err = nsh.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("(*netlink.Handle).LinkByName for %q in netns %s failed: %w", ifname, vpceID, err)
	}

	// Bring up both the inner/outer interfaces.
	if outer, err := netlink.LinkByName(ifname); err != nil {
		return fmt.Errorf("netlink.LinkByName for %q failed: %w", ifname, err)
	} else if err := netlink.LinkSetUp(outer); err != nil {
		return fmt.Errorf("netlink.LinkSetUp for %q failed: %w", ifname, err)
	}
	if err := nsh.LinkSetUp(inner); err != nil {
		return fmt.Errorf("(*netlink.Handle).LinkSetUp for %q in netns %s failed: %w", ifname, vpceID, err)
	}

	// Disable TX checksum offload so the netns egress path writes real L4
	// checksums into the bytes — encap can't compute them in BPF.
	if err := WithNetns(newns, func() error {
		et, err := ethtool.NewEthtool()
		if err != nil {
			return fmt.Errorf("ethtool.NewEthtool failed: %w", err)
		}
		defer et.Close()

		if err := et.Change(ifname, map[string]bool{
			"tx-checksum-ip-generic": false,
		}); err != nil {
			return fmt.Errorf("(*ethtool.Ethtool).Change for %q failed: %w", ifname, err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("WithNetns for %q failed: %w", vpceID, err)
	}

	mac := inner.Attrs().HardwareAddr
	if len(mac) == 0 {
		return fmt.Errorf("inner interface %s in netns %s has no hardware address", ifname, vpceID)
	}

	// Last chance to finish backend setup before this ENI is wired up and
	// reachable below (see the --script flag).
	if scriptPath != "" {
		cmd := exec.Command(scriptPath, vpceID, ifname)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("(*exec.Cmd).Run for --script %q failed: %w", scriptPath, err)
		}
	}

	// Insert into eni_to_ifindex and attach encap — this makes the ENI
	// reachable, so it happens last.
	outerIface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("net.InterfaceByName for %q failed: %w", ifname, err)
	}

	if err := decap.AddENI(gwlbID, uint32(outerIface.Index), mac, outerIface.HardwareAddr); err != nil {
		return fmt.Errorf("decap.AddENI for %q failed: %w", ifname, err)
	}

	if _, err := encap.Attach(outerIface.Index); err != nil {
		return fmt.Errorf("encap.Attach for %q failed: %w", ifname, err)
	}

	return nil
}
