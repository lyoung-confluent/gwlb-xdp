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
