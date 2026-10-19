package sensor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateAgentIDStable(t *testing.T) {
	dir := t.TempDir()
	id1, err := loadOrCreateAgentID(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id1 == "" {
		t.Fatal("empty id")
	}
	id2, err := loadOrCreateAgentID(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("want stable id, got %q vs %q", id1, id2)
	}
	b, err := os.ReadFile(filepath.Join(dir, agentIDFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("agent.id empty")
	}
}
