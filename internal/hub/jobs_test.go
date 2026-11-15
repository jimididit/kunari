package hub

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/event"
)

func TestJobStoreEnqueuePullComplete(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("0123456789abcdef0123456789abcdef")
	s, err := newJobStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	j, err := s.Enqueue("agent-a", VerbStatusDump, "operator", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if j.Sig == "" || j.Status != jobStatusQueued {
		t.Fatalf("bad job: %+v", j)
	}
	if err := VerifyJobSig(secret, j); err != nil {
		t.Fatal(err)
	}
	got, err := s.Pull("agent-a", 5)
	if err != nil || len(got) != 1 || got[0].ID != j.ID {
		t.Fatalf("pull: %v %+v", err, got)
	}
	done, err := s.Complete("agent-a", j.ID, `{"ok":true}`, "")
	if err != nil || done.Status != jobStatusDone {
		t.Fatalf("complete: %v %+v", err, done)
	}
	again, _ := s.Pull("agent-a", 5)
	if len(again) != 0 {
		t.Fatalf("expected empty pull, got %d", len(again))
	}
}

func TestJobStoreRejectsUnknownVerb(t *testing.T) {
	s, err := newJobStore(t.TempDir(), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue("a", "shell_exec", "op", nil); err == nil {
		t.Fatal("expected reject")
	}
}

func TestJobStoreExpire(t *testing.T) {
	s, err := newJobStore(t.TempDir(), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	j, err := s.Enqueue("agent-a", VerbReloadConfig, "op", nil)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.jobs[j.ID].ExpiresAt = time.Now().UTC().Add(-time.Minute)
	s.mu.Unlock()
	got, err := s.Pull("agent-a", 5)
	if err != nil || len(got) != 0 {
		t.Fatalf("expected expired skip: %v %+v", err, got)
	}
}

func TestJobStorePersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	secret := []byte("0123456789abcdef0123456789abcdef")
	s, err := newJobStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue("agent-b", VerbSetTargets, "op", json.RawMessage(`{"targets":[]}`)); err != nil {
		t.Fatal(err)
	}
	s2, err := newJobStore(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.ListForAgent("agent-b", 10)) != 1 {
		t.Fatal("persist lost jobs")
	}
	if _, err := filepath.Rel(dir, s.path); err != nil {
		t.Fatal(err)
	}
}

func TestAgentTrackerAckMissing(t *testing.T) {
	tr, err := newAgentTracker(t.TempDir(), 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: "ack-agent", Hostname: "lab", OS: "linux"}
	tr.NoteHeartbeat(ev)
	_ = tr.CheckMissing(time.Now().UTC().Add(200 * time.Millisecond))
	tr.MarkMissingAlerted("ack-agent")
	if err := tr.AckMissing("ack-agent"); err != nil {
		t.Fatal(err)
	}
	if got := tr.CheckMissing(time.Now().UTC().Add(300 * time.Millisecond)); len(got) != 0 {
		t.Fatalf("acked agent should not re-alert: %+v", got)
	}
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].Missing || !snap[0].Acked {
		t.Fatalf("snapshot after ack: %+v", snap)
	}
}
