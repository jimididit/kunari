package sensor

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
)

func TestVerifyJobAllowlistAndSig(t *testing.T) {
	keys, err := kcrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	r := &Runner{agentID: "a1", hubPubKey: keys.Public}
	args := json.RawMessage(`{}`)
	exp := time.Now().UTC().Add(time.Minute)
	j := controlJob{
		ID: "job-1", AgentID: "a1", Verb: verbStatusDump,
		Args: args, ExpiresAt: exp,
	}
	payload, err := jobSignPayload(j.ID, j.AgentID, j.Verb, string(args), exp)
	if err != nil {
		t.Fatal(err)
	}
	j.Sig = "ed25519=" + hex.EncodeToString(keys.Sign(payload))
	if err := r.verifyJob(&j); err != nil {
		t.Fatal(err)
	}
	j.Verb = "shell_exec"
	payload2, _ := jobSignPayload(j.ID, j.AgentID, j.Verb, string(args), exp)
	j.Sig = "ed25519=" + hex.EncodeToString(keys.Sign(payload2))
	if err := r.verifyJob(&j); err == nil {
		t.Fatal("expected reject for shell_exec")
	}
	// Wrong pubkey must fail even with a valid-looking sig from another key.
	other, _ := kcrypto.Generate()
	r.hubPubKey = other.Public
	j.Verb = verbStatusDump
	j.Sig = "ed25519=" + hex.EncodeToString(keys.Sign(payload))
	if err := r.verifyJob(&j); err == nil {
		t.Fatal("expected reject for wrong pubkey")
	}
	_ = ed25519.PublicKeySize
}
