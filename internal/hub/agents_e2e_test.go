package hub_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/collect"
	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/hub"
	"github.com/jimididit/kunari/internal/sink"
)

func TestMissingAgentAlertE2E(t *testing.T) {
	dir := t.TempDir()
	lnAddr := freeHTTPAddr(t)
	data := filepath.Join(dir, "data")

	h, err := hub.New(hub.Config{
		HTTPListen:      lnAddr,
		DataDir:         data,
		RegistryDB:      filepath.Join(dir, "reg.db"),
		KeyPath:         filepath.Join(dir, "key"),
		Collect:         collect.Standard,
		AgentStaleAfter: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = h.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("hub.Run did not exit")
		}
		_ = h.Close()
	})
	waitHealthz(t, lnAddr)

	secret, err := readIngestSecret(filepath.Join(data, "ingest.secret"))
	if err != nil {
		t.Fatal(err)
	}
	apiTok, err := os.ReadFile(filepath.Join(data, "api.token"))
	if err != nil {
		t.Fatal(err)
	}

	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: "e2e-agent", Hostname: "ci-host", OS: "linux", AgentVersion: "e2e"}
	body, err := sink.MarshalEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequest(http.MethodPost, "http://"+lnAddr+"/api/v1/ingest", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(sink.HeaderTimestamp, ts)
	req.Header.Set(sink.HeaderSignature, "sha256="+sink.SignBody(secret, ts, body))
	req.Header.Set(sink.HeaderEventID, ev.EventID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("ingest status %d", resp.StatusCode)
	}

	// Status should list the agent as present.
	stReq, _ := http.NewRequest(http.MethodGet, "http://"+lnAddr+"/api/v1/status", nil)
	stReq.Header.Set("Authorization", "Bearer "+string(bytes.TrimSpace(apiTok)))
	stResp, err := http.DefaultClient.Do(stReq)
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if err := json.NewDecoder(stResp.Body).Decode(&status); err != nil {
		stResp.Body.Close()
		t.Fatal(err)
	}
	stResp.Body.Close()
	agents, _ := status["agents"].([]any)
	if len(agents) != 1 {
		t.Fatalf("want 1 agent in status, got %#v", status["agents"])
	}

	// Wait for stale + watch tick, then look for agent_missing in alerts.jsonl.
	deadline := time.Now().Add(5 * time.Second)
	alertsPath := filepath.Join(data, "alerts.jsonl")
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(alertsPath)
		if err == nil && bytes.Contains(b, []byte(`"action":"agent_missing"`)) && bytes.Contains(b, []byte("e2e-agent")) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for agent_missing alert")
}
