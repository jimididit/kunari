package hub_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/collect"
	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/hub"
	"github.com/jimididit/kunari/internal/sink"
)

func TestControlPlaneJobsAPI(t *testing.T) {
	dir := t.TempDir()
	lnAddr := freeHTTPAddr(t)
	data := filepath.Join(dir, "data")
	h, err := hub.New(hub.Config{
		HTTPListen:      lnAddr,
		DataDir:         data,
		RegistryDB:      filepath.Join(dir, "reg.db"),
		KeyPath:         filepath.Join(dir, "key"),
		AgentStaleAfter: time.Minute,
		Collect:         collect.Standard,
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
	apiTokRaw, err := os.ReadFile(filepath.Join(data, "api.token"))
	if err != nil {
		t.Fatal(err)
	}
	apiTok := string(bytes.TrimSpace(apiTokRaw))

	agentID := "job-agent-1"
	base := "http://" + lnAddr

	ev := event.New("heartbeat", "sentinel", "inotify", "heartbeat")
	ev.Host = &event.HostInfo{ID: agentID, Hostname: "job-host", OS: "linux", AgentVersion: "test"}
	body, err := sink.MarshalEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	resp := hmacPost(t, base+"/api/v1/ingest", secret, body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("heartbeat ingest: %d", resp.StatusCode)
	}

	enqBody, _ := json.Marshal(map[string]any{"verb": "status_dump", "args": map[string]any{}})
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/agents/"+agentID+"/jobs", bytes.NewReader(enqBody))
	req.Header.Set("Authorization", "Bearer "+apiTok)
	req.Header.Set("Content-Type", "application/json")
	enqResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer enqResp.Body.Close()
	if enqResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(enqResp.Body)
		t.Fatalf("enqueue: %s %s", enqResp.Status, b)
	}
	var enq struct {
		Job struct {
			ID  string `json:"id"`
			Sig string `json:"sig"`
		} `json:"job"`
	}
	if err := json.NewDecoder(enqResp.Body).Decode(&enq); err != nil {
		t.Fatal(err)
	}
	if enq.Job.ID == "" || enq.Job.Sig == "" {
		t.Fatalf("missing job fields: %+v", enq)
	}

	pullBody, _ := json.Marshal(map[string]any{"agent_id": agentID, "limit": 5})
	pullResp := hmacPost(t, base+"/api/v1/jobs/pull", secret, pullBody)
	defer pullResp.Body.Close()
	if pullResp.StatusCode != 200 {
		b, _ := io.ReadAll(pullResp.Body)
		t.Fatalf("pull: %s %s", pullResp.Status, b)
	}
	var pulled struct {
		Jobs []struct {
			ID string `json:"id"`
		} `json:"jobs"`
	}
	if err := json.NewDecoder(pullResp.Body).Decode(&pulled); err != nil {
		t.Fatal(err)
	}
	if len(pulled.Jobs) != 1 || pulled.Jobs[0].ID != enq.Job.ID {
		t.Fatalf("pull jobs: %+v", pulled)
	}

	resBody, _ := json.Marshal(map[string]any{
		"agent_id": agentID,
		"job_id":   enq.Job.ID,
		"result":   `{"ok":true}`,
	})
	resResp := hmacPost(t, base+"/api/v1/jobs/result", secret, resBody)
	defer resResp.Body.Close()
	if resResp.StatusCode != 200 {
		b, _ := io.ReadAll(resResp.Body)
		t.Fatalf("result: %s %s", resResp.Status, b)
	}

	bad, _ := json.Marshal(map[string]any{"verb": "shell_exec"})
	badReq, _ := http.NewRequest(http.MethodPost, base+"/api/v1/agents/"+agentID+"/jobs", bytes.NewReader(bad))
	badReq.Header.Set("Authorization", "Bearer "+apiTok)
	badReq.Header.Set("Content-Type", "application/json")
	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode == http.StatusCreated {
		t.Fatal("shell_exec must be rejected")
	}

	audReq, _ := http.NewRequest(http.MethodGet, base+"/api/v1/jobs/audit", nil)
	audReq.Header.Set("Authorization", "Bearer "+apiTok)
	audResp, err := http.DefaultClient.Do(audReq)
	if err != nil {
		t.Fatal(err)
	}
	defer audResp.Body.Close()
	var aud struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(audResp.Body).Decode(&aud)
	if aud.Count < 1 {
		t.Fatal("expected audit entries")
	}
}

func hmacPost(t *testing.T, url string, secret, body []byte) *http.Response {
	t.Helper()
	ts := fmt.Sprintf("%d", time.Now().Unix())
	sig := "sha256=" + sink.SignBody(secret, ts, body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(sink.HeaderTimestamp, ts)
	req.Header.Set(sink.HeaderSignature, sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
