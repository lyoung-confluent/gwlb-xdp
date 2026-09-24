package cmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/mr-tron/base58"
	"github.com/vishvananda/netns"
)

// ParseIPv4CIDR parses cidr (as passed via --allowed-origin-cidr) into its
// canonical network prefix (host bits zeroed), rejecting anything that isn't
// an IPv4 prefix — GWLB's outer GENEVE tunnel is always IPv4 (see
// geneve_defs.h), so an IPv6 CIDR could never match and almost certainly
// indicates a mistake.
func ParseIPv4CIDR(cidr string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q isn't a valid CIDR: %w", cidr, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q isn't an IPv4 CIDR (GWLB's outer GENEVE origin is always IPv4)", cidr)
	}
	return p.Masked(), nil
}

// ParseVPCEID parses a VPC endpoint ID into the GWLB ID decap matches
// against GENEVE's ENI ID option: its hex suffix, in either AWS's current
// 17-hex-digit form (vpce-0123456789abcdef0) or the legacy 8-hex-digit one
// (vpce-1a2b3c4d). Hex digits may be either case.
func ParseVPCEID(vpceID string) (gwlbID uint64, err error) {
	hex, ok := strings.CutPrefix(vpceID, "vpce-")
	if !ok || (len(hex) != 17 && len(hex) != 8) {
		return 0, fmt.Errorf("%q isn't a valid vpce id (want vpce-<17 or 8 hex digits>)", vpceID)
	}
	gwlbID, err = strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("%q isn't a valid vpce id (want vpce-<17 or 8 hex digits>)", vpceID)
	}
	return gwlbID, nil
}

// FormatVPCEID is ParseVPCEID's inverse, producing the canonical lowercase
// spelling. An ID that fits in 32 bits is rendered in the legacy 8-digit
// form: a current-form ID would need 13 leading zero digits to fit, which
// its random suffix never has in practice, so this recovers the form AWS
// actually issued rather than zero-padding a legacy ID to 17 digits.
func FormatVPCEID(gwlbID uint64) string {
	if gwlbID <= math.MaxUint32 {
		return fmt.Sprintf("vpce-%08x", gwlbID)
	}
	return fmt.Sprintf("vpce-%017x", gwlbID)
}

// Interface name prefixes, the same in both isolated and --no-netns modes:
// gwlbPrefix names the inner end — the one the backend/appliance actually
// sends and receives on — and gxdpPrefix names the outer end, which only
// decap/encap ever touch by name (or ifindex). Both are 4 chars so that,
// combined with the up-to-11-char base58 ID, names never exceed IFNAMSIZ-1
// (15 chars) — see FormatInterfaceName.
const (
	gwlbPrefix = "gwlb" // veth-inner: backend/appliance side
	gxdpPrefix = "gxdp" // veth-outer: decap/encap side
)

// FormatInterfaceName returns the name of one end of gwlbID's veth pair.
// inner selects which end: true for the backend/appliance-facing end, false
// for the decap/encap-facing end. The naming doesn't depend on whether the
// ENI is namespace-isolated — only which netns the inner end ends up in does.
func FormatInterfaceName(gwlbID uint64, inner bool) string {
	prefix := gxdpPrefix
	if inner {
		prefix = gwlbPrefix
	}
	return prefix + encodeGWLBID(gwlbID)
}

func encodeGWLBID(gwlbID uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], gwlbID)
	return base58.Encode(buf[:])
}

// ParseInterfaceName reverses FormatInterfaceName, recognizing both prefixes
// it can produce. ok is false if name doesn't have one of them or isn't a
// validly-encoded ID — e.g. a physical interface's own name.
func ParseInterfaceName(name string) (gwlbID uint64, ok bool) {
	for _, prefix := range [...]string{gwlbPrefix, gxdpPrefix} {
		suffix, found := strings.CutPrefix(name, prefix)
		if !found {
			continue
		}
		buf, err := base58.Decode(suffix)
		if err != nil || len(buf) != 8 {
			return 0, false
		}
		return binary.BigEndian.Uint64(buf), true
	}
	return 0, false
}

// withLockedOSThread runs fn pinned to its OS thread, restoring the thread's
// original netns afterwards so a later goroutine can't inherit a leftover
// netns change fn made.
//
// The thread is only unlocked once its original netns is known to be restored:
// if that restore fails, leaving the thread locked lets the Go runtime destroy
// it when this goroutine exits, rather than returning a thread still in fn's
// netns to the pool where a later goroutine would silently inherit it. A
// restore failure is always reported (joined with fn's own error), never
// swallowed — a thread stuck in the wrong netns is too dangerous to lose.
func withLockedOSThread(fn func() error) error {
	runtime.LockOSThread()

	orig, err := netns.Get()
	if err != nil {
		// Never entered another netns, so the thread is safe to reuse.
		runtime.UnlockOSThread()
		return fmt.Errorf("netns.Get failed: %w", err)
	}
	defer orig.Close()

	fnErr := fn()
	if err := netns.Set(orig); err != nil {
		// Thread deliberately left locked (not unlocked) — see the doc comment.
		return errors.Join(fnErr, fmt.Errorf("netns.Set for %q failed (OS thread abandoned): %w", orig, err))
	}
	runtime.UnlockOSThread()
	return fnErr
}

// WithNetns runs fn with the calling thread switched into ns, restoring the
// original netns afterwards.
func WithNetns(ns netns.NsHandle, fn func() error) error {
	return withLockedOSThread(func() error {
		if err := netns.Set(ns); err != nil {
			return fmt.Errorf("netns.Set for %q failed: %w", ns, err)
		}
		return fn()
	})
}

// CreateNamedNetns creates a named network namespace under /run/netns,
// restoring the calling thread's original netns before returning (and
// tearing the new netns down if that restore fails).
func CreateNamedNetns(name string) (netns.NsHandle, error) {
	var newns netns.NsHandle
	if err := withLockedOSThread(func() error {
		var err error
		newns, err = netns.NewNamed(name)
		return err
	}); err != nil {
		if newns.IsOpen() {
			newns.Close()
			if e := netns.DeleteNamed(name); e != nil && !errors.Is(e, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("netns.DeleteNamed for %q failed: %w", name, e))
			}
		}
		return netns.None(), fmt.Errorf("creating netns %s failed (already exists?): %w", name, err)
	}
	return newns, nil
}
