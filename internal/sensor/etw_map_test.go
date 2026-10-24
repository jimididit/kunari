package sensor

import "testing"

func TestETWAction(t *testing.T) {
	cases := map[uint16]string{
		etwIDCreate:        "open",
		etwIDRead:          "read",
		etwIDWrite:         "modify",
		etwIDCreateNewFile: "modify",
		etwIDDeletePath:    "delete",
		etwIDNameDelete:    "delete",
		etwIDRenamePath:    "rename",
	}
	for id, want := range cases {
		got, ok := etwAction(id)
		if !ok || got != want {
			t.Fatalf("id %d: got %q ok=%v want %q", id, got, ok, want)
		}
	}
	if _, ok := etwAction(99); ok {
		t.Fatal("unknown id should be false")
	}
}

func TestETWPathMatches(t *testing.T) {
	target := `C:\ProgramData\KunariAgent\decoys\bait.env`
	if !etwPathMatches(`C:\ProgramData\KunariAgent\decoys\bait.env`, target) {
		t.Fatal("exact match")
	}
	if !etwPathMatches(`\device\harddiskvolume3\programdata\kunariagent\decoys\bait.env`, target) {
		t.Fatal("device path with drive-stripped suffix")
	}
	if etwPathMatches(`C:\other\file.env`, target) {
		t.Fatal("should not match other path")
	}
	// Must not treat a full Win32 target as a free suffix (lookalike volume path).
	if etwPathMatches(`D:\backup\C:\ProgramData\KunariAgent\decoys\bait.env`, target) {
		t.Fatal("should not suffix-match a nested drive string")
	}
	// Mid-component: \myprogramdata\... must not match \programdata\...
	if etwPathMatches(`\device\harddiskvolume3\myprogramdata\kunariagent\decoys\bait.env`, target) {
		t.Fatal("should not match mid-component suffix")
	}
}

func TestETWHasPathSuffix(t *testing.T) {
	if !etwHasPathSuffix(`\vol\data\file`, `\data\file`) {
		t.Fatal("want boundary match")
	}
	if etwHasPathSuffix(`\vol\mydata\file`, `\data\file`) {
		t.Fatal("mid-component must fail")
	}
	if !etwHasPathSuffix(`\data\file`, `\data\file`) {
		t.Fatal("exact")
	}
}

func TestETWPropString(t *testing.T) {
	props := map[string]interface{}{"FileName": `C:\a\b.env`, "FileObject": 12345}
	if got := etwPropString(props, "FileName"); got != `C:\a\b.env` {
		t.Fatalf("got %q", got)
	}
	if got := etwPropString(props, "Missing", "FileObject"); got != "12345" {
		t.Fatalf("got %q", got)
	}
}
