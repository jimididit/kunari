package hub

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/event"
)

func TestRecordIngestActionHeartbeatDoesNotBypassAlerts(t *testing.T) {
	dir := t.TempDir()
	h, err := New(Config{
		HTTPListen:      "127.0.0.1:0",
		DataDir:         dir,
		RegistryDB:      filepath.Join(dir, "reg.db"),
		KeyPath:         filepath.Join(dir, "key"),
		AgentStaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })

	ev := event.New("real-token-id-abcdef", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: "should-not-track", Hostname: "x", OS: "linux"}
	if err := h.recordIngest(ev); err != nil {
		t.Fatal(err)
	}
	if len(h.agents.Snapshot()) != 0 {
		t.Fatal("action=heartbeat alone must not be treated as control-plane heartbeat")
	}
	// Should have been enqueued as a normal alert (unknown token still alerts).
	if h.queue.Stats().Pending < 1 {
		t.Fatalf("expected alert enqueue, queue=%#v", h.queue.Stats())
	}
}

func TestNoteHeartbeatIgnoresFutureObservedAt(t *testing.T) {
	tr, err := newAgentTracker(t.TempDir(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: "a1", Hostname: "h", OS: "linux"}
	ev.ObservedAt = time.Now().UTC().Add(24 * time.Hour)
	before := time.Now().UTC()
	tr.NoteHeartbeat(ev)
	after := time.Now().UTC()
	snap := tr.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("want 1 agent, got %#v", snap)
	}
	if snap[0].LastSeen.After(after.Add(time.Second)) || snap[0].LastSeen.Before(before.Add(-time.Second)) {
		t.Fatalf("last_seen must use hub clock, got %v", snap[0].LastSeen)
	}
}
