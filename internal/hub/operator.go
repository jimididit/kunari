package hub

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jimididit/kunari/internal/registry"
)

// tokenView is a slim registry row for the operator UI (no signatures).
type tokenView struct {
	TokenID      string            `json:"token_id"`
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	Detect       string            `json:"detect"`
	AuthzRef     string            `json:"authorization_reference"`
	Memo         string            `json:"memo,omitempty"`
	Engagement   string            `json:"engagement,omitempty"`
	AgentLabel   string            `json:"agent_label,omitempty"`
	IntendedPath string            `json:"intended_path,omitempty"`
	Platforms    []string          `json:"platforms,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    *time.Time        `json:"expires_at,omitempty"`
	Expired      bool              `json:"expired,omitempty"`
	Revoked      bool              `json:"revoked"`
}

func (h *Hub) handleOperatorStatus(w http.ResponseWriter, r *http.Request) {
	qs := h.queue.Stats()
	agents := h.agents.Snapshot()
	if agents == nil {
		agents = []agentView{}
	}
	persistErr := ""
	if h.agents != nil {
		persistErr = h.agents.PersistError()
	}
	w.Header().Set("Content-Type", "application/json")
	pendingJobs := 0
	if h.jobs != nil {
		pendingJobs = h.jobs.PendingCount()
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":                   true,
		"hits":                 h.Hits(),
		"alerts":               h.Alerts(),
		"last_seq":             h.chain.LastSeq(),
		"ingest":               len(h.ingestSecret) > 0,
		"api":                  len(h.apiToken) > 0,
		"queue":                qs,
		"agents":               agents,
		"agents_persist_error": persistErr,
		"pending_jobs":         pendingJobs,
		"ts":                   time.Now().UTC(),
	})
}

func (h *Hub) handleRetireAgent(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "invalid agent id", http.StatusBadRequest)
		return
	}
	if h.agents == nil || !h.agents.enabled() {
		http.Error(w, "agent watch disabled", http.StatusBadRequest)
		return
	}
	if err := h.agents.Retire(id); err != nil {
		if err.Error() == "not found" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		h.log.Error("retire agent", "agent_id", id, "err", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"agent_id":  id,
		"retired":   true,
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
		TokenID:      m.TokenID,
		Name:         m.Name,
		Type:         m.Type,
		Detect:       m.Detect,
		AuthzRef:     m.AuthzRef,
		Memo:         m.Memo,
		Engagement:   m.Engagement,
		AgentLabel:   m.AgentLabel,
		IntendedPath: m.IntendedPath,
		Platforms:    m.Platforms,
		Tags:         m.Tags,
		CreatedAt:    m.CreatedAt,
		ExpiresAt:    m.ExpiresAt,
		Expired:      m.Expired(time.Now().UTC()),
		Revoked:      m.Revoked,
	}
}

func (h *Hub) handleImportToken(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var m registry.Manifest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&m); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if h.keys == nil {
		http.Error(w, "signing key unavailable", http.StatusInternalServerError)
		return
	}
	if err := h.reg.Import(&m, h.keys.PublicHex()); err != nil {
		h.log.Error("import token", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"token_id": m.TokenID,
		"token":    tokenViewFromManifest(m),
	})
}
