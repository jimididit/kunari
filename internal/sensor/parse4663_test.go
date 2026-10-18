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
}
