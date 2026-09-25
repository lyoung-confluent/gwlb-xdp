//go:build e2e

package e2e

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/lyoung-confluent/gwlb-xdp/bpf"
	"github.com/lyoung-confluent/gwlb-xdp/bpf/decap"
	"github.com/lyoung-confluent/gwlb-xdp/cmd"
)

// writeScript writes body to an executable shell script in a temp dir and
// returns its path, for use as `add --script`.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("os.WriteFile for %q failed: %v", path, err)
	}
	return path
}

// assertRoundTrip sends one request to gwlbID and checks its reply.
func assertRoundTrip(t *testing.T, fd int, uplinkIface, gwlbIface *net.Interface, gwlbID uint64) {
	t.Helper()
	payload := []byte("round trip")
	_, reqOpts := sendGENEVE(t, fd, uplinkIface, gwlbIface, gwlbID, payload)
	reply := waitForReply(t, fd, uplinkIface.HardwareAddr, 5*time.Second)
	if reply == nil {
		t.Fatal("no GENEVE reply observed on the simulated uplink within 5s")
	}
	assertValidReply(t, reply, gwlbIface, reqOpts, payload)
}

// assertNotProvisioned checks that nothing of gwlbID's is left behind: no
// eni_to_ifindex entry, veth, netns or encap link pin.
func assertNotProvisioned(t *testing.T, gwlbID uint64) {
	t.Helper()
	vpceID := cmd.FormatVPCEID(gwlbID)
	if _, err := decap.LookupENI(gwlbID); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("decap.LookupENI(%s) = %v, want ErrKeyNotExist", vpceID, err)
	}
	for _, inner := range []bool{false, true} {
		name := cmd.FormatInterfaceName(gwlbID, inner)
		if _, err := net.InterfaceByName(name); err == nil {
			t.Errorf("veth end %q exists, want none", name)
		}
	}
	if ns, err := netns.GetFromName(vpceID); err == nil {
		ns.Close()
		t.Errorf("netns %q exists, want none", vpceID)
	}
}

// encapPins returns the encap link pins under the pin directory.
func encapPins(t *testing.T) []string {
	t.Helper()
	pins, err := filepath.Glob(bpf.PinDir + "/link_encap_*")
	if err != nil {
		t.Fatalf("filepath.Glob failed: %v", err)
	}
	return pins
}

// TestAddAlreadyProvisioned checks that running `add` for an ENI that's
// already provisioned — a retry, or the other netns mode — fails without
// touching the live ENI: its map entry, veth and netns all survive, and it
// keeps answering.
func TestAddAlreadyProvisioned(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	for _, isolated := range []bool{true, false} {
		name := "isolated"
		if !isolated {
			name = "no-netns"
		}
		t.Run(name, func(t *testing.T) {
			gwlbID := uint64(0xE2E)
			vpceID := cmd.FormatVPCEID(gwlbID)

			uplinkIface, gwlbIface := setupUplink(t)
			runSetup(t, 8)
			one := provisionENI(t, gwlbID, isolated, echoServerPort, func(b []byte) []byte { return b })
			fd := openGWLBSocket(t, gwlbIface)

			for _, again := range []bool{isolated, !isolated} {
				if err := cmd.RunAdd(vpceID, "", again); err == nil {
					t.Errorf("cmd.RunAdd(%q, isolated=%v) of a provisioned ENI succeeded, want an error", vpceID, again)
				}
			}

			info, err := decap.LookupENI(gwlbID)
			if err != nil {
				t.Fatalf("decap.LookupENI after the repeated adds failed: %v", err)
			}
			if info.Ifindex != one.outerIfindex {
				t.Errorf("eni_to_ifindex ifindex = %d, want %d (unchanged)", info.Ifindex, one.outerIfindex)
			}
			if _, err := net.InterfaceByIndex(int(one.outerIfindex)); err != nil {
				t.Errorf("the live ENI's veth is gone: %v", err)
			}
			ns, err := netns.GetFromName(vpceID)
			if isolated && err != nil {
				t.Errorf("the live ENI's netns is gone: %v", err)
			} else if !isolated && err == nil {
				t.Errorf("a netns %q appeared for a --no-netns ENI", vpceID)
			}
			if err == nil {
				ns.Close()
			}

			assertRoundTrip(t, fd, uplinkIface, gwlbIface, gwlbID)
		})
	}
}

// TestAddRollback checks that an `add` that fails partway (here: its
// --script fails, after the netns and veth exist) removes everything it
// created, leaves an unrelated ENI alone, and can simply be run again.
func TestAddRollback(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")

	for _, isolated := range []bool{true, false} {
		name := "isolated"
		if !isolated {
			name = "no-netns"
		}
		t.Run(name, func(t *testing.T) {
			bystanderID := uint64(0xE2E)
			failingID := uint64(0xE2F)

			uplinkIface, gwlbIface := setupUplink(t)
			runSetup(t, 8)
			provisionENI(t, bystanderID, true, echoServerPort, func(b []byte) []byte { return b })
			fd := openGWLBSocket(t, gwlbIface)
			pinsBefore := encapPins(t)

			failing := writeScript(t, "exit 1")
			if err := cmd.RunAdd(cmd.FormatVPCEID(failingID), failing, isolated); err == nil {
				t.Fatal("cmd.RunAdd with a failing --script succeeded, want an error")
			}
			assertNotProvisioned(t, failingID)
			if pins := encapPins(t); len(pins) != len(pinsBefore) {
				t.Errorf("encap link pins = %v after a failed add, want %v", pins, pinsBefore)
			}

			assertRoundTrip(t, fd, uplinkIface, gwlbIface, bystanderID)

			// Nothing left over to trip up a retry.
			vpceID := cmd.FormatVPCEID(failingID)
			if err := cmd.RunAdd(vpceID, "", isolated); err != nil {
				t.Fatalf("cmd.RunAdd(%q) after a rolled-back add failed: %v", vpceID, err)
			}
			if err := cmd.RunRemove(vpceID); err != nil {
				t.Fatalf("cmd.RunRemove(%q) failed: %v", vpceID, err)
			}
		})
	}
}

// TestAddScriptSetsMAC checks that decap delivers to the inner veth's MAC as
// it stands after --script ran, not as it was before: a script that sets
// its own address on the interface must not leave decap addressing frames
// to the old one (which the netns would drop as not its own).
func TestAddScriptSetsMAC(t *testing.T) {
	requireRoot(t)
	_ = unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("needs iproute2's ip")
	}

	gwlbID := uint64(0xE2E)
	const scriptMAC = "02:aa:bb:cc:dd:ee"

	uplinkIface, gwlbIface := setupUplink(t)
	runSetup(t, 8)
	script := writeScript(t, `exec ip -n "$1" link set dev "$2" address `+scriptMAC)
	provisionENIWithScript(t, gwlbID, true, script, echoServerPort, func(b []byte) []byte { return b })
	fd := openGWLBSocket(t, gwlbIface)

	info, err := decap.LookupENI(gwlbID)
	if err != nil {
		t.Fatalf("decap.LookupENI failed: %v", err)
	}
	want, _ := net.ParseMAC(scriptMAC)
	if !bytes.Equal(info.Dst[:], want) {
		t.Errorf("eni_to_ifindex dst MAC = %v, want %v (as set by --script)", net.HardwareAddr(info.Dst[:]), want)
	}

	assertRoundTrip(t, fd, uplinkIface, gwlbIface, gwlbID)
}
