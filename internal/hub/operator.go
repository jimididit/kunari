package hub

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jimididit/kunari/internal/registry"
)

// tokenView is a slim registry row for the operator UI (no signatures).
type tokenView struct {
	TokenID   string    `json:"token_id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Detect    string    `json:"detect"`
	AuthzRef  string    `json:"authorization_reference"`
	Memo      string    `json:"memo,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

func (h *Hub) handleOperatorStatus(w http.ResponseWriter, r *http.Request) {
	qs := h.queue.Stats()
	agents := h.agents.Snapshot()
	if agents == nil {
		agents = []agentView{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"hits":     h.Hits(),
		"last_seq": h.chain.LastSeq(),
		"ingest":   len(h.ingestSecret) > 0,
		"api":      len(h.apiToken) > 0,
		"queue":    qs,
		"agents":   agents,
		"ts":       time.Now().UTC(),
	})
}

func (h *Hub) handleListTokens(w http.ResponseWriter, r *http.Request) {
	items, err := h.reg.List()
	if err != nil {
		h.log.Error("list tokens", "err", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	out := make([]tokenView, 0, len(items))
	for _, m := range items {
		out = append(out, tokenViewFromManifest(m))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"tokens": out,
		"count":  len(out),
	})
}

func (h *Hub) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	tokenID := strings.TrimSpace(r.PathValue("token"))
	if tokenID == "" || len(tokenID) < 16 {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	if err := h.reg.Revoke(tokenID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		h.log.Error("revoke token", "token_id", tokenID, "err", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"token_id": tokenID,
		"revoked":  true,
	})
}

func tokenViewFromManifest(m registry.Manifest) tokenView {
	return tokenView{
		TokenID:   m.TokenID,
		Name:      m.Name,
		Type:      m.Type,
		Detect:    m.Detect,
		AuthzRef:  m.AuthzRef,
		Memo:      m.Memo,
		CreatedAt: m.CreatedAt,
		Revoked:   m.Revoked,
	}
}
