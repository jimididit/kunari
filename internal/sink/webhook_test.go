package sink_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/sink"
)

func TestWebhookSSRFBlock(t *testing.T) {
	secret := []byte("0123456789abcdef")
	_, err := sink.NewWebhookSink("http://127.0.0.1:9/hook", secret)
	if err == nil {
		t.Fatal("expected loopback block")
	}
	_, err = sink.NewWebhookSink("http://169.254.169.254/latest", secret)
	if err == nil {
		t.Fatal("expected metadata block")
	}
	_, err = sink.NewWebhookSink("http://[::1]:9/hook", secret)
	if err == nil {
		t.Fatal("expected IPv6 loopback block")
	}
	_, err = sink.NewWebhookSink("https://example.com/hook", []byte("short"))
	if err == nil {
		t.Fatal("expected short secret rejection")
	}
	// Default allows RFC1918 for on-prem SIEM.
	if _, err := sink.NewWebhookSink("http://10.0.0.5/hook", secret); err != nil {
		t.Fatalf("RFC1918 should be allowed by default: %v", err)
	}
	// DenyPrivate blocks RFC1918 literals at construction.
	_, err = sink.NewWebhookSinkOpts("http://10.0.0.5/hook", secret, sink.WebhookOptions{DenyPrivate: true})
	if err == nil {
		t.Fatal("expected DenyPrivate to block RFC1918")
	}
	_, err = sink.NewWebhookSinkOpts("http://192.168.1.1/hook", secret, sink.WebhookOptions{DenyPrivate: true})
	if err == nil {
		t.Fatal("expected DenyPrivate to block 192.168/16")
	}
}

func TestWebhookHMAC(t *testing.T) {
	secret := []byte("0123456789abcdef")
	var gotSig, gotTS string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get(sink.HeaderSignature)
		gotTS = r.Header.Get(sink.HeaderTimestamp)
		body, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(gotTS))
		mac.Write([]byte("."))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if gotSig != want {
			t.Errorf("sig mismatch")
		}
		if _, err := strconv.ParseInt(gotTS, 10, 64); err != nil {
			t.Errorf("bad ts")
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	s, err := sink.NewWebhookSinkAllowLocal(srv.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("tok", "beacon", "beacon-https", "beacon_fetch")
	if err := s.Deliver(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("missing sig: %s", gotSig)
	}
}

func TestHubPushBlocksMetadataLiterals(t *testing.T) {
	secret := []byte("0123456789abcdef")
	blocked := []string{
		"http://169.254.169.254/latest",
		"http://[fe80::1]/latest",
		"http://[fe80::1%eth0]/latest",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://metadata.google.internal./computeMetadata/v1/",
	}
	for _, u := range blocked {
		if _, err := sink.NewHubPushSink(u, secret); err == nil {
			t.Fatalf("expected block for %s", u)
		}
	}
	// Loopback hub for lab is allowed at construction time.
	if _, err := sink.NewHubPushSink("http://127.0.0.1:8080/api/v1/ingest", secret); err != nil {
		t.Fatal(err)
	}
}

func TestThrottleSuppresses(t *testing.T) {
	th := sink.NewThrottle(time.Minute)
	ev := event.New("tok", "beacon", "beacon-https", "beacon_fetch")
	ev.Actor = &event.Actor{Exe: "/bin/cat"}
	ok, n := th.Allow(ev)
	if !ok || n != 0 {
		t.Fatalf("first should allow")
	}
	ok, n = th.Allow(ev)
	if ok || n < 1 {
		t.Fatalf("second should suppress, got allow=%v n=%d", ok, n)
	}
}
