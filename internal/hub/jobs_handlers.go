package hub

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jimididit/kunari/internal/sink"
)

type ingestBodyCtxKey struct{}

const maxJobBody = 64 << 10 // 64 KiB

type jobPullRequest struct {
	AgentID string `json:"agent_id"`
	Limit   int    `json:"limit,omitempty"`
}

type jobResultRequest struct {
	AgentID string `json:"agent_id"`
	JobID   string `json:"job_id"`
	Result  string `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
}

type enqueueJobRequest struct {
	Verb string          `json:"verb"`
	Args json.RawMessage `json:"args,omitempty"`
}

// requireIngestHMACAuth verifies the shared ingest HMAC and attaches the body
// for agent job pull/result handlers (mirrors requireAPIAuth at the route layer).
func (h *Hub) requireIngestHMACAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := h.requireIngestHMAC(w, r)
		if !ok {
			return
		}
		ctx := context.WithValue(r.Context(), ingestBodyCtxKey{}, body)
		next(w, r.WithContext(ctx))
	}
}

func (h *Hub) requireIngestHMAC(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if len(h.ingestSecret) == 0 || h.jobs == nil {
		http.Error(w, "jobs disabled", http.StatusServiceUnavailable)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJobBody+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return nil, false
	}
	if len(body) > maxJobBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	if err := sink.VerifySignature(
		h.ingestSecret,
		r.Header.Get(sink.HeaderTimestamp),
		r.Header.Get(sink.HeaderSignature),
		body,
		time.Now(),
		sink.DefaultSkew,
	); err != nil {
		h.log.Info("job auth failed", "err", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	return body, true
}

func ingestBodyFromCtx(r *http.Request) ([]byte, bool) {
	body, ok := r.Context().Value(ingestBodyCtxKey{}).([]byte)
	return body, ok
}

func (h *Hub) agentMayPullJobs(agentID string) bool {
	// Fail closed when agent watch is off: otherwise any holder of the shared ingest
	// secret could pull jobs for arbitrary agent_ids with no heartbeat gate.
	// Residual risk remains across agents that share the secret and have heartbeated.
	if h.agents == nil || !h.agents.enabled() {
		return false
	}
	return h.agents.KnownRecently(agentID, 24*time.Hour)
}

func (h *Hub) handleJobPull(w http.ResponseWriter, r *http.Request) {
	body, ok := ingestBodyFromCtx(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req jobPullRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if ok, retry := h.allowIngestRateKey(r, req.AgentID); !ok {
		writeTooManyRequests(w, retry)
		return
	}
	if !h.agentMayPullJobs(req.AgentID) {
		http.Error(w, "unknown or stale agent", http.StatusForbidden)
		return
	}
	jobs, err := h.jobs.Pull(req.AgentID, req.Limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if jobs == nil {
		jobs = []Job{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (h *Hub) handleJobResult(w http.ResponseWriter, r *http.Request) {
	body, ok := ingestBodyFromCtx(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req jobResultRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if ok, retry := h.allowIngestRateKey(r, req.AgentID); !ok {
		writeTooManyRequests(w, retry)
		return
	}
	if !h.agentMayPullJobs(req.AgentID) {
		http.Error(w, "unknown or stale agent", http.StatusForbidden)
		return
	}
	j, err := h.jobs.Complete(req.AgentID, req.JobID, req.Result, req.Error)
	if err != nil {
		if err.Error() == "not found" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "job": j})
}

func (h *Hub) handleEnqueueJob(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		http.Error(w, "jobs disabled", http.StatusServiceUnavailable)
		return
	}
	agentID := strings.TrimSpace(r.PathValue("id"))
	if agentID == "" {
		http.Error(w, "invalid agent id", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	var req enqueueJobRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxJobBody)).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	actor := "operator"
	verb := strings.TrimSpace(req.Verb)
	if verb == VerbAckMissing {
		if h.agents == nil {
			http.Error(w, "agent watch disabled", http.StatusBadRequest)
			return
		}
		// Ack first, then persist a completed job in one shot (never hub_pending/queued).
		h.agentMu.Lock()
		ackErr := h.agents.AckMissing(agentID)
		h.agentMu.Unlock()
		if ackErr != nil {
			j, _ := h.jobs.EnqueueCompleted(agentID, verb, actor, req.Args, "", ackErr.Error(), actor)
			if j != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": ackErr.Error(), "job": j})
				return
			}
			http.Error(w, ackErr.Error(), http.StatusBadRequest)
			return
		}
		j, err := h.jobs.EnqueueCompleted(agentID, verb, actor, req.Args, "acked by operator", "", actor)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "job": j})
		return
	}
	j, err := h.jobs.Enqueue(agentID, verb, actor, req.Args)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "job": j})
}

func (h *Hub) handleListAgentJobs(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		http.Error(w, "jobs disabled", http.StatusServiceUnavailable)
		return
	}
	agentID := strings.TrimSpace(r.PathValue("id"))
	jobs := h.jobs.ListForAgent(agentID, 50)
	if jobs == nil {
		jobs = []Job{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs, "count": len(jobs)})
}

func (h *Hub) handleJobsAudit(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		http.Error(w, "jobs disabled", http.StatusServiceUnavailable)
		return
	}
	entries := h.jobs.Audit(50)
	if entries == nil {
		entries = []AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries, "count": len(entries)})
}
