package sink_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/sink"
)

func TestVerifySignatureOK(t *testing.T) {
	secret := []byte("0123456789abcdef")
	body := []byte(`{"ok":true}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := "sha256=" + sink.SignBody(secret, ts, body)
	if err := sink.VerifySignature(secret, ts, sig, body, time.Now(), sink.DefaultSkew); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySignatureSkew(t *testing.T) {
	secret := []byte("0123456789abcdef")
	body := []byte(`{"ok":true}`)
	old := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	sig := "sha256=" + sink.SignBody(secret, old, body)
	if err := sink.VerifySignature(secret, old, sig, body, time.Now(), sink.DefaultSkew); err == nil {
		t.Fatal("expected skew rejection")
	}
}

func TestVerifySignatureBadMAC(t *testing.T) {
	secret := []byte("0123456789abcdef")
	body := []byte(`{"ok":true}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	if err := sink.VerifySignature(secret, ts, "sha256=deadbeef", body, time.Now(), sink.DefaultSkew); err == nil {
		t.Fatal("expected mismatch")
	}
}
