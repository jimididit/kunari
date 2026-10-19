package hub_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/collect"
	"github.com/jimididit/kunari/internal/forge"
	"github.com/jimididit/kunari/internal/hub"
	"github.com/miekg/dns"
)

func TestDNSBeaconE2E(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "reg.db")
	key := filepath.Join(dir, "key")
	zone := "canary.example.invalid"
	httpAddr := freeHTTPAddr(t)
	dnsAddr := freeUDPAddr(t)

	h, err := hub.New(hub.Config{
		HTTPListen: httpAddr,
		DNSListen:  dnsAddr,
		DNSZone:    zone,
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
		case <-time.After(5 * time.Second):
			t.Error("hub.Run did not exit")
		}
		if err := h.Close(); err != nil {
			t.Errorf("hub.Close: %v", err)
		}
	})

	deadline := time.Now().Add(3 * time.Second)
	for {
		c := new(dns.Client)
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(zone), dns.TypeA)
		_, _, err := c.Exchange(m, dnsAddr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dns hub not ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	res, err := forge.Run(forge.Options{
		Type: "env", Name: "dns-lab", Detect: "beacon",
		CollectorDNS: zone, AuthzRef: "LAB-DNS",
		OutDir: filepath.Join(dir, "out"), KeyPath: key, RegistryDB: reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(res.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	gotName := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "METRICS_HOST=") {
			gotName = strings.TrimPrefix(line, "METRICS_HOST=")
			break
		}
	}
	if gotName == "" {
		t.Fatal("missing METRICS_HOST in forged env")
	}

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(gotName), dns.TypeA)
	resp, _, err := c.Exchange(m, dnsAddr)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected dns response %#v", resp)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.Hits() >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected dns beacon hit, got %d", h.Hits())
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	return addr
}
