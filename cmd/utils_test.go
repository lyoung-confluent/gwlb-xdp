package cmd

import "testing"

func TestParseVPCEID(t *testing.T) {
	for _, tc := range []struct {
		in        string
		want      uint64
		canonical string
	}{
		{"vpce-0123456789abcdef0", 0x123456789abcdef0, "vpce-0123456789abcdef0"},
		{"vpce-0123456789ABCDEF0", 0x123456789abcdef0, "vpce-0123456789abcdef0"},
		{"vpce-1a2b3c4d", 0x1a2b3c4d, "vpce-1a2b3c4d"},
		{"vpce-0000000a", 0xa, "vpce-0000000a"},
	} {
		got, err := ParseVPCEID(tc.in)
		if err != nil {
			t.Errorf("ParseVPCEID(%q) failed: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseVPCEID(%q) = %#x, want %#x", tc.in, got, tc.want)
		}
		if s := FormatVPCEID(got); s != tc.canonical {
			t.Errorf("FormatVPCEID(ParseVPCEID(%q)) = %q, want %q", tc.in, s, tc.canonical)
		}
	}

	for _, bad := range []string{
		"",
		"vpce-",
		"0123456789abcdef0",
		"vpce-123456789abcdef0",   // 16 digits
		"vpce-00123456789abcdef0", // 18 digits
		"vpce-1a2b3c4",            // 7 digits
		"vpce-1a2b3c4d5",          // 9 digits
		"vpce-1a2b3c4g",           // not hex
		"vpce-fffffffffffffffff",  // 17 digits, overflows 64 bits
	} {
		if got, err := ParseVPCEID(bad); err == nil {
			t.Errorf("ParseVPCEID(%q) = %#x, want an error", bad, got)
		}
	}
}

func TestFormatInterfaceMAC(t *testing.T) {
	for _, tc := range []struct {
		vpceID       string
		outer, inner string
	}{
		{"vpce-0123456789abcdef0", "02:78:9a:bc:de:f0", "06:78:9a:bc:de:f0"},
		{"vpce-1a2b3c4d", "02:00:1a:2b:3c:4d", "06:00:1a:2b:3c:4d"},
	} {
		gwlbID, err := ParseVPCEID(tc.vpceID)
		if err != nil {
			t.Fatalf("ParseVPCEID(%q) failed: %v", tc.vpceID, err)
		}
		if got := FormatInterfaceMAC(gwlbID, false).String(); got != tc.outer {
			t.Errorf("FormatInterfaceMAC(%s, outer) = %s, want %s", tc.vpceID, got, tc.outer)
		}
		if got := FormatInterfaceMAC(gwlbID, true).String(); got != tc.inner {
			t.Errorf("FormatInterfaceMAC(%s, inner) = %s, want %s", tc.vpceID, got, tc.inner)
		}
	}
}
