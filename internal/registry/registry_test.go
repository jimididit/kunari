package registry

import (
	"path/filepath"
	"testing"
	"time"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
)

func TestExistsActiveHonorsExpiry(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "reg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	keys, err := kcrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Hour)
	m := &Manifest{
		TokenID:   "0123456789abcdef0123456789abcdef",
		Name:      "expired",
		Type:      "env",
		Detect:    "beacon",
		AuthzRef:  "LAB",
		CreatedAt: time.Now().UTC().Add(-2 * time.Hour),
		ExpiresAt: &past,
	}
	if err := m.Sign(keys); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(m); err != nil {
		t.Fatal(err)
	}
	ok, err := st.ExistsActive(m.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expired token must not be active")
	}
}

func TestImportRequiresSignature(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "reg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := kcrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		TokenID:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Name:      "unsigned",
		Type:      "env",
		Detect:    "beacon",
		AuthzRef:  "LAB",
		CreatedAt: time.Now().UTC(),
		Revoked:   true,
	}
	if err := st.Import(m, keys.PublicHex()); err == nil {
		t.Fatal("expected failure for unsigned/revoked manifest")
	}
}

func TestImportRequiresTrustedKey(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "reg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := kcrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	other, err := kcrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		TokenID:   "cccccccccccccccccccccccccccccccc",
		Name:      "lab",
		Type:      "env",
		Detect:    "beacon",
		AuthzRef:  "LAB",
		CreatedAt: time.Now().UTC(),
	}
	if err := m.Sign(keys); err != nil {
		t.Fatal(err)
	}
	if err := st.Import(m, other.PublicHex()); err == nil {
		t.Fatal("expected untrusted key rejection")
	}
}

func TestImportRefusesRevoked(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "reg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	keys, err := kcrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		TokenID:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Name:      "lab",
		Type:      "env",
		Detect:    "beacon",
		AuthzRef:  "LAB",
		CreatedAt: time.Now().UTC(),
	}
	if err := m.Sign(keys); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(m); err != nil {
		t.Fatal(err)
	}
	if err := st.Revoke(m.TokenID); err != nil {
		t.Fatal(err)
	}
	again := *m
	again.Revoked = false
	if err := again.Sign(keys); err != nil {
		t.Fatal(err)
	}
	if err := st.Import(&again, keys.PublicHex()); err == nil {
		t.Fatal("expected import refused for revoked token")
	}
	got, err := st.Get(m.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked {
		t.Fatal("revoked token must stay revoked")
	}
}

func TestImportVerifyAndPut(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "reg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	keys, err := kcrypto.Generate()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		TokenID:    "fedcba9876543210fedcba9876543210",
		Name:       "lab",
		Type:       "env",
		Detect:     "both",
		AuthzRef:   "CASE-1",
		Engagement: "acme-q1",
		AgentLabel: "finance-laptop",
		CreatedAt:  time.Now().UTC(),
	}
	if err := m.Sign(keys); err != nil {
		t.Fatal(err)
	}
	if err := st.Import(m, keys.PublicHex()); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(m.TokenID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Engagement != "acme-q1" || got.AgentLabel != "finance-laptop" {
		t.Fatalf("import lost engagement fields: %#v", got)
	}
	if err := got.Verify(); err != nil {
		t.Fatalf("stored manifest must remain verifiable: %v", err)
	}
}
