package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/cilium/ebpf"
	"github.com/safchain/ethtool"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
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
		return withStateLock(func() error { return RunAdd(args[0], ScriptPath, !NoNetns) })
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
	// Name the netns (and everything else) after the canonical spelling —
	// the one teardown derives back from the ENI ID — rather than whatever
	// case/width was typed here.
	vpceID = FormatVPCEID(gwlbID)

	outerName := FormatInterfaceName(gwlbID, false)
	innerName := FormatInterfaceName(gwlbID, true)

	// The veth's MTU comes from the uplink decap is attached to (see the
	// LinkAdd below), so `setup` must already have run.
	vethMTU, err := uplinkVethMTU()
	if err != nil {
		return err
	}

	// Refuse an ENI that's already provisioned before touching anything, so
	// a repeated or retried add fails cleanly and leaves the live one alone.
	if _, err := decap.LookupENI(gwlbID); err == nil {
		return fmt.Errorf("%s is already provisioned (remove it first)", vpceID)
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("decap.LookupENI for %q failed: %w", vpceID, err)
	}

	// Roll back partial state on any error — but only what this call itself
	// created, tracked by the flags below. Anything that already existed
	// (a veth or netns by the same name, say) belongs to someone else and is
	// left alone. Cleanup failures are joined onto err so a leaked
	// veth/netns doesn't vanish silently.
	var (
		createdNetns bool
		outerIfindex int // set once this call has created the veth pair
		insertedENI  bool
	)
	defer func() {
		if err == nil {
			return
		}
		// First stop decap delivering to the ENI, then delete the veth
		// (which also removes its peer, wherever it is, and detaches
		// encap), and only then sweep what the ENI cached — see
		// decap.SweepENI for why that order matters.
		if insertedENI {
			if _, e := decap.RemoveENI(gwlbID); e != nil {
				err = errors.Join(err, fmt.Errorf("rollback: decap.RemoveENI for %q failed: %w", vpceID, e))
			}
		}
		if outerIfindex != 0 {
			if link, e := netlink.LinkByIndex(outerIfindex); e == nil {
				if e := netlink.LinkDel(link); e != nil {
					err = errors.Join(err, fmt.Errorf("rollback: netlink.LinkDel for %q failed: %w", outerName, e))
				}
			}
		}
		if insertedENI {
			if e := decap.SweepENI(uint32(outerIfindex)); e != nil {
				err = errors.Join(err, fmt.Errorf("rollback: decap.SweepENI for %q failed: %w", outerName, e))
			}
		}
		if createdNetns {
			if e := netns.DeleteNamed(vpceID); e != nil && !errors.Is(e, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("rollback: netns.DeleteNamed for %q failed: %w", vpceID, e))
			}
		}
	}()

	var newns netns.NsHandle
	var nsh *netlink.Handle
	if isolated {
		newns, err = CreateNamedNetns(vpceID)
		if err != nil {
			return fmt.Errorf("CreateNamedNetns for %q failed: %w", vpceID, err)
		}
		createdNetns = true
		defer newns.Close()

		nsh, err = netlink.NewHandleAt(newns)
	} else {
		nsh, err = netlink.NewHandle()
	}
	if err != nil {
		return fmt.Errorf("getting a netlink handle for %q failed: %w", vpceID, err)
	}
	defer nsh.Close()

	// MTU vethMTU: the uplink's MTU minus GENEVE's 68 bytes, the largest
	// inner packet decap delivers and encap sends (see bpf.MaxInnerLen). It
	// has to be that large: veth drops a frame over the receiving end's MTU,
	// and GWLB can deliver anything up to it. The netns sizes its own
	// replies to GWLB's documented 8500 with a route MTU instead (see
	// README.md) — the interface MTU governs what it can receive.
	//
	// Both ends get MACs derived from the ENI ID (see FormatInterfaceMAC)
	// rather than the kernel's random ones, so they're recognizable and the
	// same every time this ENI is added. Being explicitly assigned also
	// keeps systemd-udevd off them: its default MACAddressPolicy=persistent
	// replaces a kernel-random MAC asynchronously after the device appears
	// — possibly after decap has cached the old one below — but leaves an
	// assigned one alone.
	//
	// Both ends already have their final, distinct names (outer and inner
	// never collide, isolated or not), so they're created in place in the
	// root netns with no rename needed — isolated just additionally migrates
	// the inner end into its dedicated netns afterwards.
	if err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs:        netlink.LinkAttrs{Name: outerName, MTU: vethMTU, HardwareAddr: FormatInterfaceMAC(gwlbID, false)},
		PeerName:         innerName,
		PeerMTU:          uint32(vethMTU),
		PeerHardwareAddr: FormatInterfaceMAC(gwlbID, true),
	}); err != nil {
		return fmt.Errorf("netlink.LinkAdd for veth pair %s/%s failed: %w", outerName, innerName, err)
	}
	outer, err := netlink.LinkByName(outerName)
	if err != nil {
		// Just created, so this can't normally fail. If it does, the veth
		// can't be rolled back by ifindex, so do it by name instead.
		if link, e := netlink.LinkByName(outerName); e == nil {
			_ = netlink.LinkDel(link)
		}
		return fmt.Errorf("netlink.LinkByName for %q failed: %w", outerName, err)
	}
	outerIfindex = outer.Attrs().Index

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
	if err := netlink.LinkSetUp(outer); err != nil {
		return fmt.Errorf("netlink.LinkSetUp for %q failed: %w", outerName, err)
	}
	if err := nsh.LinkSetUp(inner); err != nil {
		return fmt.Errorf("(*netlink.Handle).LinkSetUp for %q failed: %w", innerName, err)
	}

	// Disable TX checksum offload and every segmentation/GRO offload on both
	// ends (see vethDisabledFeatures), before encap is attached.
	if isolated {
		if err := WithNetns(newns, func() error { return disableVethOffloads(innerName) }); err != nil {
			return fmt.Errorf("WithNetns for %q failed: %w", vpceID, err)
		}
	} else if err := disableVethOffloads(innerName); err != nil {
		return err
	}
	if err := disableVethOffloads(outerName); err != nil {
		return err
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

	// Read both ends' MACs only now, after --script: the script is where the
	// netns's interface gets configured, and it may well set the inner
	// end's address itself. decap writes the inner MAC into every frame it
	// delivers, and the netns drops any frame not addressed to it.
	inner, err = nsh.LinkByName(innerName)
	if err != nil {
		return fmt.Errorf("(*netlink.Handle).LinkByName for %q failed: %w", innerName, err)
	}
	innerMAC := inner.Attrs().HardwareAddr
	if len(innerMAC) == 0 {
		return fmt.Errorf("inner interface %s has no hardware address", innerName)
	}
	outer, err = netlink.LinkByIndex(outerIfindex)
	if err != nil {
		return fmt.Errorf("netlink.LinkByIndex for %q failed: %w", outerName, err)
	}

	// Insert into eni_to_ifindex and attach encap — this makes the ENI
	// reachable, so it happens last.
	if err := decap.AddENI(gwlbID, uint32(outerIfindex), innerMAC, outer.Attrs().HardwareAddr); err != nil {
		return fmt.Errorf("decap.AddENI for %q failed: %w", outerName, err)
	}
	insertedENI = true

	if _, err := encap.Attach(outerIfindex); err != nil {
		return fmt.Errorf("encap.Attach for %q failed: %w", outerName, err)
	}

	return nil
}

// uplinkVethMTU returns the MTU for a new ENI's veth pair: bpf.MaxInnerLen of
// the MTU of the uplink decap is attached to. That's the same value `setup`
// gave decap and encap, unless the uplink's MTU has changed since — in which
// case re-run `setup`.
func uplinkVethMTU() (int, error) {
	ifindex, err := decap.UplinkIfindex()
	if err != nil {
		return 0, fmt.Errorf("finding the uplink failed (has setup run?): %w", err)
	}
	uplink, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return 0, fmt.Errorf("netlink.LinkByIndex for uplink ifindex %d failed: %w", ifindex, err)
	}
	mtu, err := bpf.MaxInnerLen(uplink.Attrs().MTU)
	if err != nil {
		return 0, fmt.Errorf("bpf.MaxInnerLen for uplink %s failed: %w", uplink.Attrs().Name, err)
	}
	return mtu, nil
}

// vethDisabledFeatures are the ethtool features disableVethOffloads turns off
// on both ends of an ENI's veth pair.
//
// tx-checksum-ip-generic: encap can't compute an inner L4 checksum in BPF, so
// the netns egress path must write the real one into the bytes itself.
//
// The rest: every packet crossing the veth must be a single wire-sized
// packet. encap (generic XDP, after linearizing) and decap's redirect only
// ever see one buffer — a GSO super-packet or GRO-merged skb reaching either
// would be encapsulated, or delivered, as one oversized packet and then
// dropped past the programs' view. Turning these off makes the netns stack
// segment everything in software before it reaches the veth.
var vethDisabledFeatures = []string{
	"tx-checksum-ip-generic",
	"tx-tcp-segmentation",
	"tx-tcp-ecn-segmentation",
	"tx-tcp-mangleid-segmentation",
	"tx-tcp6-segmentation",
	"tx-udp-segmentation",
	"tx-gso-list",
	"tx-generic-segmentation",
	"rx-gro",
	"rx-gro-list",
	"rx-udp-gro-forwarding",
}

// disableVethOffloads turns off vethDisabledFeatures on ifname, which must be
// in the calling thread's netns. Features this kernel's veth doesn't know
// are skipped rather than failing.
func disableVethOffloads(ifname string) error {
	et, err := ethtool.NewEthtool()
	if err != nil {
		return fmt.Errorf("ethtool.NewEthtool failed: %w", err)
	}
	defer et.Close()

	known, err := et.FeatureNames(ifname)
	if err != nil {
		return fmt.Errorf("(*ethtool.Ethtool).FeatureNames for %q failed: %w", ifname, err)
	}
	change := make(map[string]bool, len(vethDisabledFeatures))
	for _, name := range vethDisabledFeatures {
		if _, ok := known[name]; ok {
			change[name] = false
		}
	}
	if err := et.Change(ifname, change); err != nil {
		return fmt.Errorf("(*ethtool.Ethtool).Change for %q failed: %w", ifname, err)
	}
	return nil
}
