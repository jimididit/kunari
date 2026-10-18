package hub_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/collect"
	"github.com/jimididit/kunari/internal/forge"
	"github.com/jimididit/kunari/internal/hub"
)

func TestOperatorUIAndAPI(t *testing.T) {
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

	// Root redirects to /ui/
	resp, err := http.Get("http://" + lnAddr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / via redirect: status %d", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("Kunari")) || !bytes.Contains(body, []byte("app.js")) {
		t.Fatalf("ui html missing brand or script: %s", truncate(body, 200))
	}
	if csp := resp.Header.Get("Content-Security-Policy"); csp == "" {
		t.Fatal("expected CSP on UI response")
	}

	js, err := http.Get("http://" + lnAddr + "/ui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	js.Body.Close()
	if js.StatusCode != http.StatusOK {
		t.Fatalf("app.js status %d", js.StatusCode)
	}

	tokenHex, err := os.ReadFile(filepath.Join(data, "api.token"))
	if err != nil {
		t.Fatal(err)
	}
	token := string(bytes.TrimSpace(tokenHex))

	// Unauthorized status
	unauth, err := http.Get("http://" + lnAddr + "/api/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status want 401, got %d", unauth.StatusCode)
	}

	req, err := http.NewRequest(http.MethodGet, "http://"+lnAddr+"/api/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	stResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var status map[string]any
	if err := json.NewDecoder(stResp.Body).Decode(&status); err != nil {
		stResp.Body.Close()
		t.Fatal(err)
	}
	stResp.Body.Close()
	if stResp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", stResp.StatusCode)
	}
	if status["ok"] != true {
		t.Fatalf("status body: %#v", status)
	}
	q, ok := status["queue"].(map[string]any)
	if !ok {
		t.Fatalf("missing queue in status: %#v", status)
	}
	if _, ok := q["pending"]; !ok {
		t.Fatalf("queue.pending missing: %#v", q)
	}

	res, err := forge.Run(forge.Options{
		Type: "env", Name: "ui-tok", Detect: "beacon",
		Collector: "http://" + lnAddr, AuthzRef: "LAB-UI",
		OutDir: filepath.Join(dir, "out"), KeyPath: key, RegistryDB: reg,
	})
	if err != nil {
		t.Fatal(err)
	}

	listReq, _ := http.NewRequest(http.MethodGet, "http://"+lnAddr+"/api/v1/tokens", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Tokens []struct {
			TokenID string `json:"token_id"`
			Revoked bool   `json:"revoked"`
			Name    string `json:"name"`
		} `json:"tokens"`
		Count int `json:"count"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		listResp.Body.Close()
		t.Fatal(err)
	}
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("tokens status %d", listResp.StatusCode)
	}
	if list.Count < 1 {
		t.Fatal("expected at least one token")
	}
	found := false
	for _, tok := range list.Tokens {
		if tok.TokenID == res.TokenID {
			found = true
			if tok.Revoked {
				t.Fatal("new token should be active")
			}
		}
	}
	if !found {
		t.Fatalf("forged token %s not in list", res.TokenID)
	}

	revReq, _ := http.NewRequest(http.MethodPost, "http://"+lnAddr+"/api/v1/tokens/"+res.TokenID+"/revoke", nil)
	revReq.Header.Set("Authorization", "Bearer "+token)
	revResp, err := http.DefaultClient.Do(revReq)
	if err != nil {
		t.Fatal(err)
	}
	revBody, _ := io.ReadAll(revResp.Body)
	revResp.Body.Close()
	if revResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status %d: %s", revResp.StatusCode, revBody)
	}

	listReq2, _ := http.NewRequest(http.MethodGet, "http://"+lnAddr+"/api/v1/tokens", nil)
	listReq2.Header.Set("Authorization", "Bearer "+token)
	listResp2, err := http.DefaultClient.Do(listReq2)
	if err != nil {
		t.Fatal(err)
	}
	list = struct {
		Tokens []struct {
			TokenID string `json:"token_id"`
			Revoked bool   `json:"revoked"`
			Name    string `json:"name"`
		} `json:"tokens"`
		Count int `json:"count"`
	}{}
	if err := json.NewDecoder(listResp2.Body).Decode(&list); err != nil {
		listResp2.Body.Close()
		t.Fatal(err)
	}
	listResp2.Body.Close()
	for _, tok := range list.Tokens {
		if tok.TokenID == res.TokenID && !tok.Revoked {
			t.Fatal("token should be revoked")
		}
	}

	// Unknown token → 404
	miss, _ := http.NewRequest(http.MethodPost, "http://"+lnAddr+"/api/v1/tokens/ffffffffffffffffffffffffffffffff/revoke", nil)
	miss.Header.Set("Authorization", "Bearer "+token)
	missResp, err := http.DefaultClient.Do(miss)
	if err != nil {
		t.Fatal(err)
	}
	missResp.Body.Close()
	if missResp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing revoke want 404, got %d", missResp.StatusCode)
	}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
