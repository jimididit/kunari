package hub

import (
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/event"
)

func TestAgentTrackerMissingAndRecovery(t *testing.T) {
	dir := t.TempDir()
	tr, err := newAgentTracker(dir, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: "agent-1", Hostname: "lab", OS: "linux", AgentVersion: "test"}
	ev.ObservedAt = time.Now().UTC()
	tr.NoteHeartbeat(ev)

	if got := tr.CheckMissing(time.Now().UTC()); len(got) != 0 {
		t.Fatalf("expected no missing yet, got %#v", got)
	}
	miss := tr.CheckMissing(time.Now().UTC().Add(200 * time.Millisecond))
	if len(miss) != 1 || miss[0].ID != "agent-1" || !miss[0].Missing {
		t.Fatalf("expected one missing alert, got %#v", miss)
	}
	// Second check should not re-alert.
	if got := tr.CheckMissing(time.Now().UTC().Add(300 * time.Millisecond)); len(got) != 0 {
		t.Fatalf("expected no re-alert, got %#v", got)
	}

	ev2 := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev2.Host = &event.HostInfo{ID: "agent-1", Hostname: "lab", OS: "linux"}
	ev2.ObservedAt = time.Now().UTC().Add(400 * time.Millisecond)
	tr.NoteHeartbeat(ev2)
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].Missing {
		t.Fatalf("expected recovered agent, got %#v", snap)
	}
}

func TestAgentTrackerDisabled(t *testing.T) {
	tr, err := newAgentTracker(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: "x"}
	tr.NoteHeartbeat(ev)
	if len(tr.Snapshot()) != 0 {
		t.Fatal("disabled tracker should ignore heartbeats")
	}
}

func TestAgentKeyFallback(t *testing.T) {
	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{Hostname: "host-a", OS: "windows"}
	if got := agentKey(ev); got != "host-a|windows" {
		t.Fatalf("got %q", got)
	}
}
