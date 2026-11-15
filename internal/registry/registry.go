package registry

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store is a local SQLite registry of forged tokens.
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS tokens (
  token_id TEXT PRIMARY KEY,
  manifest_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);`)
	return err
}

func (s *Store) Put(m *Manifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(m)
}

func (s *Store) putLocked(m *Manifest) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO tokens(token_id, manifest_json, created_at, revoked) VALUES(?,?,?,?)`,
		m.TokenID, string(b), m.CreatedAt.UTC().Format(time.RFC3339), boolToInt(m.Revoked),
	)
	return err
}

func (s *Store) Get(tokenID string) (*Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(tokenID)
}

func (s *Store) getLocked(tokenID string) (*Manifest, error) {
	var raw string
	err := s.db.QueryRow(`SELECT manifest_json FROM tokens WHERE token_id=?`, tokenID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) List() ([]Manifest, error) {
	rows, err := s.db.Query(`SELECT manifest_json FROM tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Manifest
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var m Manifest
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) Revoke(tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.getLocked(tokenID)
	if err != nil {
		return err
	}
	m.Revoked = true
	return s.putLocked(m)
}

func (s *Store) ExistsActive(tokenID string) (bool, error) {
	m, err := s.Get(tokenID)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if m.Revoked || m.Expired(time.Now().UTC()) {
		return false, nil
	}
	return true, nil
}

// Import verifies a signed manifest against trustedPubHex and upserts it.
// Tokens already revoked in this store are refused (re-import cannot restore them).
func (s *Store) Import(m *Manifest, trustedPubHex string) error {
	if m == nil || strings.TrimSpace(m.TokenID) == "" {
		return fmt.Errorf("manifest token_id required")
	}
	trustedPubHex = strings.TrimSpace(strings.ToLower(trustedPubHex))
	if trustedPubHex == "" {
		return fmt.Errorf("trusted signing public key required")
	}
	if m.Revoked {
		return fmt.Errorf("refusing to import revoked manifest")
	}
	if err := m.Verify(); err != nil {
		return fmt.Errorf("manifest verify: %w", err)
	}
	got := strings.ToLower(strings.TrimSpace(m.SigningPublicKey))
	a := sha256.Sum256([]byte(trustedPubHex))
	b := sha256.Sum256([]byte(got))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		return fmt.Errorf("manifest signing key is not trusted")
	}

	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var revoked int
	err = s.db.QueryRow(`SELECT revoked FROM tokens WHERE token_id=?`, m.TokenID).Scan(&revoked)
	if err == nil && revoked != 0 {
		return fmt.Errorf("token %s is revoked; import refused", m.TokenID)
	}
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	res, err := s.db.Exec(
		`INSERT INTO tokens(token_id, manifest_json, created_at, revoked) VALUES(?,?,?,0)
		 ON CONFLICT(token_id) DO UPDATE SET
		   manifest_json=excluded.manifest_json,
		   created_at=excluded.created_at,
		   revoked=0
		 WHERE tokens.revoked=0`,
		m.TokenID, string(raw), m.CreatedAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("token %s is revoked; import refused", m.TokenID)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func EnsureAuthz(ref string) error {
	if ref == "" {
		return fmt.Errorf("--authz-ref is required (ticket/case/authorization reference)")
	}
	return nil
}
