package hub

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/event"
)

func TestScanEventsPagingDoesNotSkipMatches(t *testing.T) {
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

	host := &event.HostInfo{ID: "host-page", Hostname: "p", OS: "linux"}
	for i := 0; i < 5; i++ {
		ev := event.New("tok", "sentinel", "inotify", "open")
		ev.Host = host
		if err := h.chain.Append(ev); err != nil {
			t.Fatal(err)
		}
	}

	page1, next, err := h.scanEvents(0, 2, "host-page", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 2 {
		t.Fatalf("page1 len=%d want 2", len(page1))
	}
	page2, _, err := h.scanEvents(next, 10, "host-page", true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 3 {
		t.Fatalf("page2 len=%d want 3 (no skipped matches)", len(page2))
	}
	if page2[0].Integrity.Seq <= page1[len(page1)-1].Integrity.Seq {
		t.Fatalf("page2 should continue after page1: p1=%d p2=%d", page1[len(page1)-1].Integrity.Seq, page2[0].Integrity.Seq)
	}
}

func TestScanEventsLatestStartsNearTip(t *testing.T) {
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

	// Seed enough events that a head-only 10k window would miss a late host match
	// if after stayed at 0 on a huge chain. Here we assert the tip-relative start
	// by placing the only host match after a gap of heartbeats and using latest.
	for i := 0; i < 3; i++ {
		hb := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
		hb.Host = &event.HostInfo{ID: "other", Hostname: "o", OS: "linux"}
		if err := h.chain.Append(hb); err != nil {
			t.Fatal(err)
		}
	}
	ev := event.New("tok", "sentinel", "inotify", "open")
	ev.Host = &event.HostInfo{ID: "host-tip", Hostname: "t", OS: "linux"}
	if err := h.chain.Append(ev); err != nil {
		t.Fatal(err)
	}
	got, _, err := h.scanEvents(0, 1, "host-tip", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Host == nil || got[0].Host.ID != "host-tip" {
		t.Fatalf("latest should find tip host match, got %#v", got)
	}
}

func TestScanEventsLatestKeepsNewest(t *testing.T) {
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

	host := &event.HostInfo{ID: "host-latest", Hostname: "l", OS: "linux"}
	var last uint64
	for i := 0; i < 5; i++ {
		ev := event.New("tok", "sentinel", "inotify", "open")
		ev.Host = host
		if err := h.chain.Append(ev); err != nil {
			t.Fatal(err)
		}
		last = ev.Integrity.Seq
	}
	got, _, err := h.scanEvents(0, 2, "host-latest", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d want 2", len(got))
	}
	if got[len(got)-1].Integrity.Seq != last {
		t.Fatalf("latest window should end at %d, got %d", last, got[len(got)-1].Integrity.Seq)
	}
}
