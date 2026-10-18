package registry

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is a local SQLite registry of forged tokens.
type Store struct {
	db *sql.DB
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
	m, err := s.Get(tokenID)
	if err != nil {
		return err
	}
	m.Revoked = true
	return s.Put(m)
}

func (s *Store) ExistsActive(tokenID string) (bool, error) {
	var revoked int
	err := s.db.QueryRow(`SELECT revoked FROM tokens WHERE token_id=?`, tokenID).Scan(&revoked)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return revoked == 0, nil
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
