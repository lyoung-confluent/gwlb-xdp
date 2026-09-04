package cmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/mr-tron/base58"
	"github.com/vishvananda/netns"
)

func ParseVPCEID(vpceID string) (gwlbID uint64, err error) {
	hex, ok := strings.CutPrefix(vpceID, "vpce-")
	if !ok || len(hex) != 17 {
		return 0, fmt.Errorf("%q isn't a valid vpce id (want vpce-<17 hex digits>)", vpceID)
	}
	gwlbID, err = strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("%q isn't a valid vpce id (want vpce-<17 hex digits>)", vpceID)
	}
	return gwlbID, nil
}

func FormatVPCEID(gwlbID uint64) string {
	return fmt.Sprintf("vpce-%017x", gwlbID)
}

func FormatInterfaceName(gwlbID uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], gwlbID)
	return "gwlb" + base58.Encode(buf[:])
}

// ParseInterfaceName reverses FormatInterfaceName. ok is false if name
// doesn't have the "gwlb" prefix or isn't a validly-encoded ID — e.g. a
// physical interface's own name.
func ParseInterfaceName(name string) (gwlbID uint64, ok bool) {
	suffix, found := strings.CutPrefix(name, "gwlb")
	if !found {
		return 0, false
	}
	buf, err := base58.Decode(suffix)
	if err != nil || len(buf) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(buf), true
}

// withLockedOSThread runs fn pinned to its OS thread, restoring the thread's
// original netns afterwards so a later goroutine can't inherit a leftover
// netns change fn made. fn's own error takes priority over a restore error.
func withLockedOSThread(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := netns.Get()
	if err != nil {
		return fmt.Errorf("netns.Get failed: %w", err)
	}
	defer orig.Close()

	fnErr := fn()
	if err := netns.Set(orig); err != nil && fnErr == nil {
		return fmt.Errorf("netns.Set for %q failed: %w", orig, err)
	}
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
