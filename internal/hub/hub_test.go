package hub_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/beacon"
	"github.com/jimididit/kunari/internal/collect"
	"github.com/jimididit/kunari/internal/forge"
	"github.com/jimididit/kunari/internal/hub"
)

func TestHTTPSBeaconE2E(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg.db")
	key := filepath.Join(dir, "key")

	lnAddr := freeHTTPAddr(t)

	h, err := hub.New(hub.Config{
		HTTPListen: lnAddr,
		DataDir:    filepath.Join(dir, "data"),
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
		case <-time.After(3 * time.Second):
		}
		_ = h.Close()
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := http.Get("http://" + lnAddr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("hub did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}

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
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.Hits() >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected hit, got %d", h.Hits())
}

func freeHTTPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}
