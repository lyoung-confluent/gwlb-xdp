package bpf

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// AttachXDP attaches prog to ifindex as XDP and pins the resulting link
// at pinPath so it survives this process exiting. Tries native (driver) mode
// first, falling back to generic/SKB mode since not every driver supports
// native XDP.
//
// Set GWLB_XDP_MODE=generic to skip the native attempt entirely — for
// environments where native XDP *attach* succeeds but redirect between the
// specific devices involved doesn't work at packet time.
func AttachXDP(prog *ebpf.Program, ifindex int, pinPath string) (link.Link, error) {
	attach := func(flags link.XDPAttachFlags) (link.Link, error) {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifindex,
			Flags:     flags,
		})
		if err != nil {
			return nil, fmt.Errorf("link.AttachXDP for %q failed: %w", pinPath, err)
		}
		if err := l.Pin(pinPath); err != nil {
			return nil, errors.Join(
				fmt.Errorf("(link.Link).Pin for %q failed: %w", pinPath, err),
				l.Close(),
			)
		}
		return l, nil
	}

	if os.Getenv("GWLB_XDP_MODE") == "generic" {
		return attach(link.XDPGenericMode)
	}

	l, err := attach(link.XDPDriverMode)
	if err == nil {
		return l, nil
	}
	return attach(link.XDPGenericMode)
}

// DetachXDP reverses a pinned AttachXDP call.
func DetachXDP(pinPath string) error {
	l, err := link.LoadPinnedLink(pinPath, nil)
	if err != nil {
		return fmt.Errorf("link.LoadPinnedLink for %q failed: %w", pinPath, err)
	}
	if err := l.Unpin(); err != nil {
		return errors.Join(
			fmt.Errorf("(link.Link).Unpin for %q failed: %w", pinPath, err),
			l.Close(),
		)
	}
	if err := l.Close(); err != nil {
		return fmt.Errorf("(link.Link).Close for %q failed: %w", pinPath, err)
	}
	return nil
}
