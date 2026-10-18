package hub_test

import (
	"bytes"
	"context"
	"encoding/hex"
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

func TestSentinelIngestHMAC(t *testing.T) {
	dir := t.TempDir()
	lnAddr := freeHTTPAddr(t)
	data := filepath.Join(dir, "data")

	h, err := hub.New(hub.Config{
		HTTPListen: lnAddr,
		DataDir:    data,
		RegistryDB: filepath.Join(dir, "reg.db"),
		KeyPath:    filepath.Join(dir, "key"),
		Collect:    collect.Standard,
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

	ev := event.New("tok-ingest", "sentinel", "inotify", "open")
	ev.Memo = "lab"
	body, err := sink.MarshalEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := sink.SignBody(secret, ts, body)

	req, err := http.NewRequest(http.MethodPost, "http://"+lnAddr+"/api/v1/ingest", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(sink.HeaderTimestamp, ts)
	req.Header.Set(sink.HeaderSignature, "sha256="+sig)
	req.Header.Set(sink.HeaderEventID, ev.EventID)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.Hits() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if h.Hits() < 1 {
		t.Fatalf("expected ingest hit, got %d", h.Hits())
	}

	// Replay same event_id -> 204, no extra hit.
	reqReplay, err := http.NewRequest(http.MethodPost, "http://"+lnAddr+"/api/v1/ingest", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	reqReplay.Header.Set("Content-Type", "application/json")
	reqReplay.Header.Set(sink.HeaderTimestamp, ts)
	reqReplay.Header.Set(sink.HeaderSignature, "sha256="+sig)
	reqReplay.Header.Set(sink.HeaderEventID, ev.EventID)
	resp, err = http.DefaultClient.Do(reqReplay)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("replay status %d", resp.StatusCode)
	}
	if h.Hits() != 1 {
		t.Fatalf("dedupe failed: hits=%d", h.Hits())
	}

	req2, _ := http.NewRequest(http.MethodPost, "http://"+lnAddr+"/api/v1/ingest", bytes.NewReader(body))
	req2.Header.Set(sink.HeaderTimestamp, ts)
	req2.Header.Set(sink.HeaderSignature, "sha256=00")
	req2.Header.Set(sink.HeaderEventID, ev.EventID)
	resp, err = http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestHubPushSinkToIngest(t *testing.T) {
	dir := t.TempDir()
	lnAddr := freeHTTPAddr(t)
	data := filepath.Join(dir, "data")

	h, err := hub.New(hub.Config{
		HTTPListen: lnAddr,
		DataDir:    data,
		RegistryDB: filepath.Join(dir, "reg.db"),
		KeyPath:    filepath.Join(dir, "key"),
		Collect:    collect.Standard,
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
		<-done
		_ = h.Close()
	})
	waitHealthz(t, lnAddr)

	secret, err := readIngestSecret(filepath.Join(data, "ingest.secret"))
	if err != nil {
		t.Fatal(err)
	}
	push, err := sink.NewHubPushSink("http://"+lnAddr+"/api/v1/ingest", secret)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("tok2", "sentinel", "inotify", "read")
	if err := push.Deliver(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.Hits() >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected hit via HubPushSink, got %d", h.Hits())
}

func waitHealthz(t *testing.T, lnAddr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := http.Get("http://" + lnAddr + "/healthz")
		if err == nil {
			var body struct {
				OK     bool `json:"ok"`
				Ingest bool `json:"ingest"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
			if resp.StatusCode == 200 && body.OK && body.Ingest {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("hub did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func readIngestSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(string(bytes.TrimSpace(raw)))
}
