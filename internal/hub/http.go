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
	mux.HandleFunc("GET /{$}", h.handleUIRedirect)
	mux.Handle("GET /ui/", uiStaticHandler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"hits":   h.Hits(),
			"ingest": len(h.ingestSecret) > 0,
			"api":    len(h.apiToken) > 0,
			"ts":     time.Now().UTC(),
		})
	})
	mux.HandleFunc("GET /b/{token}", h.handleBeacon)
	mux.HandleFunc("HEAD /b/{token}", h.handleBeacon)
	mux.HandleFunc("POST /api/v1/ingest", h.handleIngest)
	// Agent job transport: ingest HMAC (rate limit is per agent_id inside handlers).
	mux.HandleFunc("POST /api/v1/jobs/pull", h.requireIngestHMACAuth(h.handleJobPull))
	mux.HandleFunc("POST /api/v1/jobs/result", h.requireIngestHMACAuth(h.handleJobResult))
	mux.HandleFunc("GET /api/v1/events", h.requireAPIAuth(false, h.handleListEvents))
	mux.HandleFunc("GET /api/v1/events/stream", h.requireAPIAuth(true, h.handleEventStream))
	mux.HandleFunc("GET /api/v1/status", h.requireAPIAuth(false, h.handleOperatorStatus))
	mux.HandleFunc("POST /api/v1/agents/{id}/retire", h.requireAPIAuth(false, h.handleRetireAgent))
	mux.HandleFunc("POST /api/v1/agents/{id}/jobs", h.requireAPIAuth(false, h.handleEnqueueJob))
	mux.HandleFunc("GET /api/v1/agents/{id}/jobs", h.requireAPIAuth(false, h.handleListAgentJobs))
	mux.HandleFunc("GET /api/v1/jobs/audit", h.requireAPIAuth(false, h.handleJobsAudit))
	mux.HandleFunc("GET /api/v1/tokens", h.requireAPIAuth(false, h.handleListTokens))
	mux.HandleFunc("POST /api/v1/tokens/import", h.requireAPIAuth(false, h.handleImportToken))
	mux.HandleFunc("POST /api/v1/tokens/{token}/revoke", h.requireAPIAuth(false, h.handleRevokeToken))
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
	ip := h.clientIP(r)
	allowed := true
	var retry time.Duration
	if h.beaconLimit != nil {
		allowed, retry = h.beaconLimit.allow(ip)
	}
	// Under limit: always record. Over limit: record only if overflow budget
	// remains (keeps some detections without unbounded storage writes).
	shouldRecord := allowed || h.beaconLimit == nil || h.beaconLimit.allowOverflow(ip)
	if shouldRecord {
		if err := h.recordBeacon(token, "beacon-https", netInfo); err != nil {
			h.log.Error("record beacon", "err", err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	}
	if !allowed {
		writeTooManyRequests(w, retry)
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

