package hub

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jimididit/kunari/internal/event"
)

func (h *Hub) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"hits":   h.Hits(),
			"ingest": len(h.ingestSecret) > 0,
			"ts":     time.Now().UTC(),
		})
	})
	mux.HandleFunc("GET /b/{token}", h.handleBeacon)
	mux.HandleFunc("HEAD /b/{token}", h.handleBeacon)
	mux.HandleFunc("POST /api/v1/ingest", h.handleIngest)
	mux.HandleFunc("GET /api/v1/events", h.handleListEventsStub)
	return mux
}

func (h *Hub) handleBeacon(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	token = strings.TrimSpace(token)
	if token == "" || len(token) < 16 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	netInfo := &event.Network{
		SrcIP: h.clientIP(r),
		UA:    r.UserAgent(),
	}
	if h.cfg.Collect.AllowsForensicNetwork() {
		netInfo.Headers = map[string]string{}
		for k, v := range r.Header {
			if len(v) > 0 {
				netInfo.Headers[k] = v[0]
			}
		}
	}
	if err := h.recordBeacon(token, "beacon-https", netInfo); err != nil {
		h.log.Error("record beacon", "err", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	// 1x1 transparent GIF
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
	})
}

func (h *Hub) handleListEventsStub(w http.ResponseWriter, r *http.Request) {
	// Authenticated pull API arrives with Phase 1 hardening; stub for now.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "auth pull API: use local events.jsonl / kunari verify for v0.1 lab",
	})
}

