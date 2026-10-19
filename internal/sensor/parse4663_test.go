//go:build windows

package sensor

import "testing"

func TestParse4663(t *testing.T) {
	raw := `
Event[0]
  Object Name: C:\lab\canary.env
  Access Mask: 0x1
  Process Name: C:\Windows\System32\notepad.exe
`
	targets := []Target{{Path: `C:\lab\canary.env`, TokenID: "abc"}}
	got := parse4663(raw, targets)
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].Action != "read" {
		t.Fatalf("action %s", got[0].Action)
	}
	if got[0].Extra["process_name"] != `C:\Windows\System32\notepad.exe` {
		t.Fatalf("process %q", got[0].Extra["process_name"])
	}
}

func TestMapAccessMaskBits(t *testing.T) {
	cases := []struct {
		mask string
		want string
	}{
		{"0x1", "read"},
		{"0x2", "modify"},
		{"0x4", "modify"},
		{"0x10000", "delete"},
		{"0x100001", "read"},   // READ | SYNCHRONIZE, not DELETE
		{"0x100002", "modify"}, // WRITE | SYNCHRONIZE
		{"0x100000", "open"},   // SYNCHRONIZE only
		{"0x80", "open"},       // FILE_READ_ATTRIBUTES probe
		{"0x80000000", "read"}, // GENERIC_READ
		{"0x40000000", "modify"},
		{"0x10000000", "modify"}, // GENERIC_ALL
	}
	for _, tc := range cases {
		if got := mapAccessMask(tc.mask); got != tc.want {
			t.Fatalf("mask %s got %q want %q", tc.mask, got, tc.want)
		}
	}
}
