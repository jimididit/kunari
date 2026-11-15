//go:build windows

package sensor

import (
	"strings"
	"testing"
)

func TestParse4663(t *testing.T) {
	raw := `
Event[0]
  Object Name: C:\lab\canary.env
  Access Mask: 0x1
  Process Name: C:\Windows\System32\notepad.exe
  Event Record ID: 42
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
	if got[0].Extra["event_record_id"] != "42" {
		t.Fatalf("record id %q", got[0].Extra["event_record_id"])
	}
}

func TestParse4663XML(t *testing.T) {
	raw := `<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4663</EventID>
    <EventRecordID>1001</EventRecordID>
  </System>
  <EventData>
    <Data Name="ObjectName">\\?\C:\lab\decoy.env</Data>
    <Data Name="AccessMask">0x1</Data>
    <Data Name="ProcessName">C:\Windows\System32\notepad.exe</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4663</EventID>
    <EventRecordID>1002</EventRecordID>
  </System>
  <EventData>
    <Data Name="ObjectName">C:\lab\decoy.env</Data>
    <Data Name="AccessMask">0x1</Data>
    <Data Name="ProcessName">C:\Windows\System32\notepad.exe</Data>
  </EventData>
</Event>`
	got := parse4663(raw, []Target{{Path: `C:\lab\decoy.env`, TokenID: "abc"}})
	if len(got) != 2 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].Action != "read" || got[1].Action != "read" {
		t.Fatalf("actions %s %s", got[0].Action, got[1].Action)
	}
	if got[0].Extra["event_record_id"] != "1001" || got[1].Extra["event_record_id"] != "1002" {
		t.Fatalf("ids %q %q", got[0].Extra["event_record_id"], got[1].Extra["event_record_id"])
	}
}

func TestParse4663RenderedMasks(t *testing.T) {
	raw := `
Event[0]
        Object Name:            C:\lab\decoy.env
        Process Name:           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
        Accesses:               WriteData (or AddFile)
        Access Mask:            0x2
Event[1]
        Object Name:            C:\lab\decoy.env
        Accesses:               ReadData (or ListDirectory)
        Access Mask:            0x1
Event[2]
        Object Name:            C:\lab\decoy.env
        Accesses:               DELETE
        Access Mask:            0x10000
Event[3]
        Object Name:            C:\lab\decoy.env
        Accesses:               ReadAttributes
        Access Mask:            0x80
`
	got := parse4663(raw, []Target{{Path: `C:\lab\decoy.env`, TokenID: "abc"}})
	want := []string{"modify", "read", "delete", "open"}
	if len(got) != len(want) {
		t.Fatalf("got %d", len(got))
	}
	for i, action := range want {
		if got[i].Action != action {
			t.Fatalf("event %d action %s want %s mask %s", i, got[i].Action, action, got[i].Extra["access_mask"])
		}
	}
}

func TestParse4663StripsMaskNUL(t *testing.T) {
	raw := "Event[0]\n  Object Name: C:\\lab\\decoy.env\n  Access Mask: 0x1\x00\r\n  Process Name: C:\\Windows\\System32\\notepad.exe\n"
	got := parse4663(raw, []Target{{Path: `C:\lab\decoy.env`, TokenID: "abc"}})
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].Action != "read" {
		t.Fatalf("action %s", got[0].Action)
	}
	if got[0].Extra["access_mask"] != "0x1" {
		t.Fatalf("mask %q", got[0].Extra["access_mask"])
	}
}

func TestXPath4663FiltersObjectName(t *testing.T) {
	q, err := xpath4663([]Target{{Path: `C:\lab\canary.env`}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(q, `ObjectName']='C:\lab\canary.env'`) {
		t.Fatalf("query %s", q)
	}
	if !strings.Contains(q, `ObjectName']='\\?\C:\lab\canary.env'`) {
		t.Fatalf("query missing long-path variant: %s", q)
	}
	if !strings.Contains(q, "EventID=4663") {
		t.Fatalf("query %s", q)
	}
	if _, err := xpath4663([]Target{{Path: `C:\lab\canary.env'`}}); err == nil {
		t.Fatal("expected reject for quote in path")
	}
}

func TestRememberRecordAllowsRepeatReads(t *testing.T) {
	w := &event4663Watcher{seen: map[string]struct{}{}}
	if w.rememberRecord("1") {
		t.Fatal("first sighting should be new")
	}
	if !w.rememberRecord("1") {
		t.Fatal("same record id should be seen")
	}
	if w.rememberRecord("2") {
		t.Fatal("different record id should be new (repeat read)")
	}
}

func TestNormalizeWinPathStripsLongPrefix(t *testing.T) {
	if got := normalizeWinPath(`\\?\C:\Lab\Decoy.env`); got != `c:\lab\decoy.env` {
		t.Fatalf("got %q", got)
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
