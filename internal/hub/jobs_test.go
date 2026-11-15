package hub

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/event"
	kcrypto "github.com/jimididit/kunari/internal/crypto"
)

func testJobKeys(t *testing.T) *kcrypto.KeyPair {
	t.Helper()
	keys, err := kcrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestJobStoreEnqueuePullComplete(t *testing.T) {
	dir := t.TempDir()
	keys := testJobKeys(t)
	s, err := newJobStore(dir, keys)
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
	if err := VerifyJobSig(keys.Public, j); err != nil {
		t.Fatal(err)
	}
	got, err := s.Pull("agent-a", 5)
	if err != nil || len(got) != 1 || got[0].ID != j.ID || got[0].Status != jobStatusInflight {
		t.Fatalf("pull: %v %+v", err, got)
	}
	leased, _ := s.Pull("agent-a", 5)
	if len(leased) != 0 {
		t.Fatalf("expected lease to suppress re-pull, got %d", len(leased))
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

func TestJobStoreCanonicalArgsSig(t *testing.T) {
	keys := testJobKeys(t)
	s, err := newJobStore(t.TempDir(), keys)
	if err != nil {
		t.Fatal(err)
	}
	j, err := s.Enqueue("a", VerbSetTargets, "op", json.RawMessage("{\n  \"targets\": []\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if string(j.Args) != `{"targets":[]}` {
		t.Fatalf("args not compacted: %s", j.Args)
	}
	if err := VerifyJobSig(keys.Public, j); err != nil {
		t.Fatal(err)
	}
}

func TestJobStoreAckMissingNotPullable(t *testing.T) {
	keys := testJobKeys(t)
	s, err := newJobStore(t.TempDir(), keys)
	if err != nil {
		t.Fatal(err)
	}
	j, err := s.Enqueue("agent-a", VerbAckMissing, "op", nil)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != jobStatusHubPending {
		t.Fatalf("want hub_pending, got %s", j.Status)
	}
	got, err := s.Pull("agent-a", 5)
	if err != nil || len(got) != 0 {
		t.Fatalf("ack_missing must not be pullable: %v %+v", err, got)
	}
	done, err := s.Complete("agent-a", j.ID, "acked by operator", "")
	if err != nil || done.Status != jobStatusDone {
		t.Fatalf("complete hub_pending: %v %+v", err, done)
	}
}

func TestJobStoreRejectsUnknownVerb(t *testing.T) {
	s, err := newJobStore(t.TempDir(), testJobKeys(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue("a", "shell_exec", "op", nil); err == nil {
		t.Fatal("expected reject")
	}
}

func TestJobStoreExpire(t *testing.T) {
	s, err := newJobStore(t.TempDir(), testJobKeys(t))
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
	keys := testJobKeys(t)
	s, err := newJobStore(dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue("agent-b", VerbSetTargets, "op", json.RawMessage(`{"targets":[]}`)); err != nil {
		t.Fatal(err)
	}
	s2, err := newJobStore(dir, keys)
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

func TestJobStoreTrimAuditIndependent(t *testing.T) {
	s, err := newJobStore(t.TempDir(), testJobKeys(t))
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for i := 0; i < maxJobsPersisted+50; i++ {
		s.audit = append(s.audit, AuditEntry{JobID: "x", Verb: "status_dump"})
	}
	s.trimLocked()
	if len(s.audit) > maxJobsPersisted {
		t.Fatalf("audit not trimmed: %d", len(s.audit))
	}
	s.mu.Unlock()
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
	if !tr.ClaimMissingAlert("ack-agent") {
		t.Fatal("expected claim")
	}
	if tr.ClaimMissingAlert("ack-agent") {
		t.Fatal("double claim must fail")
	}
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
	ev2 := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev2.Host = &event.HostInfo{ID: "healthy", Hostname: "lab", OS: "linux"}
	tr.NoteHeartbeat(ev2)
	if err := tr.AckMissing("healthy"); err == nil {
		t.Fatal("expected reject ack on healthy agent")
	}
}
