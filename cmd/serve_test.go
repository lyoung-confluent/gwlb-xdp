package cmd

import (
	"slices"
	"strings"
	"testing"
)

func TestPackLines(t *testing.T) {
	line := func(n int) string { return strings.Repeat("x", n) }

	for _, tc := range []struct {
		name  string
		lines []string
		max   int
		want  []string
	}{
		{"empty", nil, 10, nil},
		{"all fit", []string{"a", "b", "c"}, 10, []string{"a\nb\nc"}},
		{"exact fit", []string{line(4), line(5)}, 10, []string{line(4) + "\n" + line(5)}},
		{"split", []string{line(4), line(6)}, 10, []string{line(4), line(6)}},
		{"oversize line alone", []string{"a", line(12), "b"}, 10, []string{"a", line(12), "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := packLines(tc.lines, tc.max)
			if !slices.Equal(got, tc.want) {
				t.Errorf("packLines = %q, want %q", got, tc.want)
			}
			for _, d := range got {
				if len(d) > tc.max && strings.Contains(d, "\n") {
					t.Errorf("datagram %q packs several lines past max %d", d, tc.max)
				}
			}
		})
	}
}

func TestCounterLines(t *testing.T) {
	const (
		okPackets   = 6 // decap_ok_packets
		dropPackets = 2 // decap_drop_malformed_packets
	)
	labels := map[uint32]string{1: "|#interface:eth0", 7: "|#interface:gxdp1"}
	prev := map[counterKey]uint64{
		{1, okPackets}:   100,
		{7, okPackets}:   50,
		{9, dropPackets}: 3, // ifindex 9 has no live interface
	}
	cur := map[counterKey]uint64{
		{1, okPackets}:   130, // grew by 30
		{1, dropPackets}: 4,   // new since prev: all of it
		{7, okPackets}:   5,   // went down: swept and recreated, so all of it
		{9, dropPackets}: 8,   // untagged: skipped
	}

	got := counterLines(cur, prev, labels)
	for _, lines := range got {
		slices.Sort(lines)
	}
	want := map[uint32][]string{
		1: {
			"gwlb_xdp.decap_drop_malformed_packets:4|c|#interface:eth0",
			"gwlb_xdp.decap_ok_packets:30|c|#interface:eth0",
		},
		7: {"gwlb_xdp.decap_ok_packets:5|c|#interface:gxdp1"},
	}
	if len(got) != len(want) {
		t.Fatalf("counterLines = %v, want %v", got, want)
	}
	for ifindex, lines := range want {
		if !slices.Equal(got[ifindex], lines) {
			t.Errorf("counterLines[%d] = %q, want %q", ifindex, got[ifindex], lines)
		}
	}
}
