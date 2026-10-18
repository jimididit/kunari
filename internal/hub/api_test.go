package hub_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/beacon"
	"github.com/jimididit/kunari/internal/collect"
	"github.com/jimididit/kunari/internal/forge"
	"github.com/jimididit/kunari/internal/hub"
)

func TestEventsAPIAuthAndPull(t *testing.T) {
	dir := t.TempDir()
	lnAddr := freeHTTPAddr(t)
	data := filepath.Join(dir, "data")
	reg := filepath.Join(dir, "reg.db")
	key := filepath.Join(dir, "key")

	h, err := hub.New(hub.Config{
		HTTPListen: lnAddr,
		DataDir:    data,
		RegistryDB: reg,
		KeyPath:    key,
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
	waitHealthzAPI(t, lnAddr)

	// Unauthorized
	resp, err := http.Get("http://" + lnAddr + "/api/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}

	tokenHex, err := os.ReadFile(filepath.Join(data, "api.token"))
	if err != nil {
		t.Fatal(err)
	}
	token := string(bytes.TrimSpace(tokenHex))

	res, err := forge.Run(forge.Options{
		Type: "env", Name: "lab", Detect: "beacon",
		Collector: "http://" + lnAddr, AuthzRef: "LAB",
		OutDir: filepath.Join(dir, "out"), KeyPath: key, RegistryDB: reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	url, err := beacon.HTTPSURL("http://"+lnAddr, res.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	bres, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	bres.Body.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.Hits() < 1 {
		time.Sleep(20 * time.Millisecond)
	}

	req, err := http.NewRequest(http.MethodGet, "http://"+lnAddr+"/api/v1/events?limit=10", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var body struct {
		Count  int `json:"count"`
		Events []struct {
			TokenID string `json:"token_id"`
			Action  string `json:"action"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Count < 1 || body.Events[0].Action != "beacon_fetch" {
		t.Fatalf("unexpected body: %+v", body)
	}

	// Query token must not work on pull API.
	resp, err = http.Get("http://" + lnAddr + "/api/v1/events?token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("query token on pull want 401, got %d", resp.StatusCode)
	}
}

func TestEventsSSE(t *testing.T) {
	dir := t.TempDir()
	lnAddr := freeHTTPAddr(t)
	data := filepath.Join(dir, "data")
	reg := filepath.Join(dir, "reg.db")
	key := filepath.Join(dir, "key")

	h, err := hub.New(hub.Config{
		HTTPListen: lnAddr,
		DataDir:    data,
		RegistryDB: reg,
		KeyPath:    key,
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
	waitHealthzAPI(t, lnAddr)

	tokenHex, _ := os.ReadFile(filepath.Join(data, "api.token"))
	token := string(bytes.TrimSpace(tokenHex))

	sseCtx, sseCancel := context.WithCancel(context.Background())
	defer sseCancel()
	req, err := http.NewRequestWithContext(sseCtx, http.MethodGet, "http://"+lnAddr+"/api/v1/events/stream?token="+token, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("sse status %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("content-type %s", resp.Header.Get("Content-Type"))
	}

	res, err := forge.Run(forge.Options{
		Type: "env", Name: "sse", Detect: "beacon",
		Collector: "http://" + lnAddr, AuthzRef: "LAB",
		OutDir: filepath.Join(dir, "out"), KeyPath: key, RegistryDB: reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	url, _ := beacon.HTTPSURL("http://"+lnAddr, res.TokenID)
	go func() {
		time.Sleep(100 * time.Millisecond)
		r, err := http.Get(url)
		if err == nil {
			r.Body.Close()
		}
	}()

	sc := bufio.NewScanner(resp.Body)
	deadline := time.Now().Add(5 * time.Second)
	saw := false
	for time.Now().Before(deadline) && sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, "beacon_fetch") {
			saw = true
			break
		}
	}
	sseCancel()
	if !saw {
		t.Fatal("expected SSE beacon_fetch event")
	}
}

func waitHealthzAPI(t *testing.T, lnAddr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := http.Get("http://" + lnAddr + "/healthz")
		if err == nil {
			var body struct {
				OK  bool `json:"ok"`
				API bool `json:"api"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&body)
			resp.Body.Close()
			if resp.StatusCode == 200 && body.OK && body.API {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("hub not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
