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
	_, err := sink.NewWebhookSink("http://127.0.0.1:9/hook", []byte("secret"))
	if err == nil {
		t.Fatal("expected loopback block")
	}
	_, err = sink.NewWebhookSink("http://169.254.169.254/latest", []byte("secret"))
	if err == nil {
		t.Fatal("expected metadata block")
	}
}

func TestWebhookHMAC(t *testing.T) {
	secret := []byte("test-secret")
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
