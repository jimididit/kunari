package event_test

import (
	"path/filepath"
	"testing"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
	"github.com/jimididit/kunari/internal/event"
)

func TestReadAfter(t *testing.T) {
	dir := t.TempDir()
	keys, err := kcrypto.LoadOrCreate(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.jsonl")
	ch, err := event.Open(path, keys)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		ev := event.New("t", "beacon", "beacon-https", "beacon_fetch")
		if err := ch.Append(ev); err != nil {
			t.Fatal(err)
		}
	}
	got, next, err := event.ReadAfter(path, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || next != 3 {
		t.Fatalf("got len=%d next=%d", len(got), next)
	}
	if got[0].Integrity.Seq != 2 {
		t.Fatalf("seq %d", got[0].Integrity.Seq)
	}
}
