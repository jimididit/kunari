package event_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
	"github.com/jimididit/kunari/internal/event"
)

func TestChainAppendAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	keys, err := kcrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := event.Open(path, keys)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		ev := event.New("tok", "beacon", "beacon-https", "beacon_fetch")
		ev.Memo = "test"
		if err := c.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	if err := event.VerifyFile(path, keys.Public); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestChainDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	keys, err := kcrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	c, err := event.Open(path, keys)
	if err != nil {
		t.Fatal(err)
	}
	ev := event.New("tok", "beacon", "beacon-https", "beacon_fetch")
	if err := c.Append(ev); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic tamper: alter a payload field while leaving integrity bytes intact.
	tampered := []byte(strings.Replace(string(raw), `"detector":"beacon"`, `"detector":"tampered"`, 1))
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := event.VerifyFile(path, keys.Public); err == nil {
		t.Fatal("expected verify failure after tamper")
	}
}
