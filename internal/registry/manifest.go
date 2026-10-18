package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
)

const ManifestSchema = "kunari.manifest/1"

// Manifest describes a forged tripwire for inventory and evidence.
type Manifest struct {
	Schema           string            `json:"schema"`
	TokenID          string            `json:"token_id"`
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	Platforms        []string          `json:"platforms"`
	Detect           string            `json:"detect"`
	Collect          string            `json:"collect"`
	Memo             string            `json:"memo"`
	AuthzRef         string            `json:"authorization_reference"`
	AuthorizedUse    string            `json:"authorized_use"`
	IntendedPath     string            `json:"intended_path,omitempty"`
	ArtifactSHA256   string            `json:"artifact_sha256"`
	BeaconHTTPS      string            `json:"beacon_https,omitempty"`
	BeaconDNS        string            `json:"beacon_dns,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	ExpiresAt        *time.Time        `json:"expires_at,omitempty"`
	Tags             map[string]string `json:"tags,omitempty"`
	Revoked          bool              `json:"revoked"`
	SigningPublicKey string            `json:"signing_public_key"`
	Signature        string            `json:"signature"`
}

const AuthorizedUseNotice = "Deploy only on systems you own or are authorized to monitor. Defensive use only."

func HashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (m *Manifest) Sign(keys *kcrypto.KeyPair) error {
	m.Schema = ManifestSchema
	m.AuthorizedUse = AuthorizedUseNotice
	m.SigningPublicKey = keys.PublicHex()
	m.Signature = ""
	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	m.Signature = hex.EncodeToString(keys.Sign(sum[:]))
	return nil
}

func (m *Manifest) Verify() error {
	if m.Schema != ManifestSchema {
		return fmt.Errorf("unsupported manifest schema")
	}
	sigHex := m.Signature
	pubHex := m.SigningPublicKey
	m.Signature = ""
	defer func() { m.Signature = sigHex }()

	payload, err := json.Marshal(m)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return err
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return err
	}
	if !kcrypto.Verify(pub, sum[:], sig) {
		return fmt.Errorf("manifest signature invalid")
	}
	return nil
}
