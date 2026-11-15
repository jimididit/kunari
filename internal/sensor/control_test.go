package sensor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestVerifyJobAllowlistAndSig(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	r := &Runner{agentID: "a1", hubSecret: secret}
	args := json.RawMessage(`{}`)
	exp := time.Now().UTC().Add(time.Minute)
	j := controlJob{
		ID: "job-1", AgentID: "a1", Verb: verbStatusDump,
		Args: args, ExpiresAt: exp,
	}
	payload := "kunari.job/1\n" + j.ID + "\n" + j.AgentID + "\n" + j.Verb + "\n" + string(args) + "\n" + exp.Format(time.RFC3339Nano)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	j.Sig = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if err := r.verifyJob(&j); err != nil {
		t.Fatal(err)
	}
	j.Verb = "shell_exec"
	payload2 := "kunari.job/1\n" + j.ID + "\n" + j.AgentID + "\n" + j.Verb + "\n" + string(args) + "\n" + exp.Format(time.RFC3339Nano)
	mac2 := hmac.New(sha256.New, secret)
	mac2.Write([]byte(payload2))
	j.Sig = "sha256=" + hex.EncodeToString(mac2.Sum(nil))
	if err := r.verifyJob(&j); err == nil {
		t.Fatal("expected reject for shell_exec")
	}
}
