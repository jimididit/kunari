package sensor

import (
	"testing"
	"time"
)

func TestCopyCorrelatorPIDWindow(t *testing.T) {
	c := newCopyCorrelator(5 * time.Second)
	t0 := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	if c.Suspect(Touch{PID: 7, Path: "/tmp/a", Action: "open", Occurred: t0}, "/bin/cat") {
		t.Fatal("first open alone not copy")
	}
	if !c.Suspect(Touch{PID: 7, Path: "/tmp/b", Action: "modify", Occurred: t0.Add(time.Second)}, "/bin/cat") {
		t.Fatal("open then modify other path should suspect copy")
	}
}

func TestCopyCorrelatorCopyTool(t *testing.T) {
	c := newCopyCorrelator(5 * time.Second)
	if !c.Suspect(Touch{PID: 1, Path: "/tmp/a", Action: "open", Occurred: time.Now().UTC()}, `/usr/bin/cp`) {
		t.Fatal("cp open should suspect copy")
	}
}

func TestCopyCorrelatorDifferentPID(t *testing.T) {
	c := newCopyCorrelator(5 * time.Second)
	t0 := time.Now().UTC()
	_ = c.Suspect(Touch{PID: 1, Path: "/tmp/a", Action: "open", Occurred: t0}, "")
	if c.Suspect(Touch{PID: 2, Path: "/tmp/b", Action: "modify", Occurred: t0.Add(time.Second)}, "") {
		t.Fatal("different PID must not correlate")
	}
}
