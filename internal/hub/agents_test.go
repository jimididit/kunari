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
	// Until MarkMissingAlerted, CheckMissing keeps returning the candidate.
	if got := tr.CheckMissing(time.Now().UTC().Add(250 * time.Millisecond)); len(got) != 1 {
		t.Fatalf("expected retry candidate before mark, got %#v", got)
	}
	if !tr.ClaimMissingAlert("agent-1") {
		t.Fatal("expected claim before mark")
	}
	tr.MarkMissingAlerted("agent-1")
	if got := tr.CheckMissing(time.Now().UTC().Add(300 * time.Millisecond)); len(got) != 0 {
		t.Fatalf("expected no re-alert after mark, got %#v", got)
	}

	ev2 := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev2.Host = &event.HostInfo{ID: "agent-1", Hostname: "lab", OS: "linux"}
	ev2.ObservedAt = time.Now().UTC().Add(400 * time.Millisecond)
	if !tr.NoteHeartbeat(ev2) {
		t.Fatal("expected recovered=true on heartbeat after missing alert")
	}
	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].Missing {
		t.Fatalf("expected recovered agent, got %#v", snap)
	}
}

func TestAgentTrackerRecoverRequiresMissingAlert(t *testing.T) {
	tr, err := newAgentTracker(t.TempDir(), 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: "agent-r", Hostname: "r", OS: "linux"}
	tr.NoteHeartbeat(ev)
	_ = tr.CheckMissing(time.Now().UTC().Add(100 * time.Millisecond))
	ev2 := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev2.Host = &event.HostInfo{ID: "agent-r", Hostname: "r", OS: "linux"}
	if tr.NoteHeartbeat(ev2) {
		t.Fatal("recovered must be false when agent_missing was never emitted")
	}
}

func TestAgentTrackerRecoverPendingRetry(t *testing.T) {
	tr, err := newAgentTracker(t.TempDir(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: "agent-p", Hostname: "p", OS: "linux"}
	tr.NoteHeartbeat(ev)
	tr.MarkRecoverPending("agent-p")
	ev2 := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev2.Host = &event.HostInfo{ID: "agent-p", Hostname: "p", OS: "linux"}
	if !tr.NoteHeartbeat(ev2) {
		t.Fatal("expected recovered=true when RecoverPending is set")
	}
}

func TestAgentTrackerNeedsMissingAlert(t *testing.T) {
	tr, err := newAgentTracker(t.TempDir(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: "agent-n", Hostname: "n", OS: "linux"}
	tr.NoteHeartbeat(ev)
	if tr.NeedsMissingAlert("agent-n") {
		t.Fatal("fresh agent should not need missing alert")
	}
	_ = tr.CheckMissing(time.Now().UTC().Add(2 * time.Minute))
	if !tr.NeedsMissingAlert("agent-n") {
		t.Fatal("stale unalerted agent should need missing alert")
	}
	if !tr.ClaimMissingAlert("agent-n") {
		t.Fatal("expected claim before mark")
	}
	tr.MarkMissingAlerted("agent-n")
	if tr.NeedsMissingAlert("agent-n") {
		t.Fatal("alerted missing agent should not need another alert")
	}
}

func TestAgentTrackerRetire(t *testing.T) {
	dir := t.TempDir()
	tr, err := newAgentTracker(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: "agent-2", Hostname: "zebra", OS: "windows", AgentVersion: "0.5.1"}
	tr.NoteHeartbeat(ev)
	evB := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	evB.Host = &event.HostInfo{ID: "agent-1", Hostname: "alpha", OS: "linux"}
	tr.NoteHeartbeat(evB)
	snap := tr.Snapshot()
	if len(snap) != 2 || snap[0].Hostname != "alpha" {
		t.Fatalf("expected hostname sort, got %#v", snap)
	}
	if err := tr.Retire("agent-2"); err != nil {
		t.Fatal(err)
	}
	snap = tr.Snapshot()
	if len(snap) != 1 || snap[0].ID != "agent-1" {
		t.Fatalf("expected retired host hidden, got %#v", snap)
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

func TestParseHeartbeatMeta(t *testing.T) {
	meta, ok := parseHeartbeatMeta("heartbeat;every=60s;watches=2;caps=open/read; needs admin")
	if !ok || !meta.HasWatches || meta.Watches != 2 || meta.Caps != "open/read; needs admin" {
		t.Fatalf("got ok=%v meta=%+v", ok, meta)
	}
	capsOnly, ok := parseHeartbeatMeta("heartbeat;every=60s;caps=open/read")
	if !ok || capsOnly.HasWatches || capsOnly.Caps != "open/read" {
		t.Fatalf("caps-only got ok=%v meta=%+v", ok, capsOnly)
	}
	if _, ok := parseHeartbeatMeta("heartbeat;every=60s"); ok {
		t.Fatal("expected no meta")
	}
}

func TestNoteHeartbeatStoresCapabilities(t *testing.T) {
	dir := t.TempDir()
	tr, err := newAgentTracker(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("heartbeat", "sentinel", "win-sacl-4663", "heartbeat")
	ev.Host = &event.HostInfo{ID: "agent-caps", Hostname: "lab", OS: "windows"}
	ev.Memo = "heartbeat;every=60s;watches=1;caps=open/read via 4663; needs SACL"
	tr.NoteHeartbeat(ev)
	snap := tr.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d", len(snap))
	}
	if snap[0].WatchCount != 1 || snap[0].Capabilities != "open/read via 4663; needs SACL" {
		t.Fatalf("watches=%d caps=%q", snap[0].WatchCount, snap[0].Capabilities)
	}
	if snap[0].Tier != "win-sacl-4663" {
		t.Fatalf("tier %q", snap[0].Tier)
	}
	ev2 := event.New("heartbeat", "sentinel", "win-sacl-4663", "heartbeat")
	ev2.Host = &event.HostInfo{ID: "agent-caps", Hostname: "lab", OS: "windows"}
	ev2.Memo = "heartbeat;every=60s;watches=0;caps=idle"
	tr.NoteHeartbeat(ev2)
	snap = tr.Snapshot()
	if snap[0].WatchCount != 0 {
		t.Fatalf("expected watches cleared to 0, got %d", snap[0].WatchCount)
	}
	ev3 := event.New("heartbeat", "sentinel", "win-sacl-4663", "heartbeat")
	ev3.Host = &event.HostInfo{ID: "agent-caps", Hostname: "lab", OS: "windows"}
	ev3.Memo = "heartbeat;every=60s;watches=3;caps=open/read"
	tr.NoteHeartbeat(ev3)
	ev4 := event.New("heartbeat", "sentinel", "win-sacl-4663", "heartbeat")
	ev4.Host = &event.HostInfo{ID: "agent-caps", Hostname: "lab", OS: "windows"}
	ev4.Memo = "heartbeat;every=60s;caps=open/read only"
	tr.NoteHeartbeat(ev4)
	snap = tr.Snapshot()
	if snap[0].WatchCount != 3 {
		t.Fatalf("caps-only must not clear watches; got %d", snap[0].WatchCount)
	}
}
