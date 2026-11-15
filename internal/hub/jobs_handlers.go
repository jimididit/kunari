package hub

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jimididit/kunari/internal/sink"
)

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

func (h *Hub) agentMayPullJobs(agentID string) bool {
	// Shared ingest HMAC means any secret holder can claim any agent_id.
	// Require a recent heartbeat for that id so idle impersonation is harder.
	if h.agents == nil || !h.agents.enabled() {
		return true
	}
	return h.agents.KnownRecently(agentID, 24*time.Hour)
}

func (h *Hub) handleJobPull(w http.ResponseWriter, r *http.Request) {
	body, ok := h.requireIngestHMAC(w, r)
	if !ok {
		return
	}
	var req jobPullRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs})
}

func (h *Hub) handleJobResult(w http.ResponseWriter, r *http.Request) {
	body, ok := h.requireIngestHMAC(w, r)
	if !ok {
		return
	}
	var req jobResultRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
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
	// Hub-side side effects after successful agent completion.
	if j.Status == jobStatusDone && j.Verb == VerbAckMissing && h.agents != nil {
		h.agentMu.Lock()
		err := h.agents.AckMissing(j.AgentID)
		h.agentMu.Unlock()
		if err != nil {
			h.log.Info("ack_missing after result", "agent_id", j.AgentID, "err", err)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "job": j})
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
	j, err := h.jobs.Enqueue(agentID, req.Verb, actor, req.Args)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// ack_missing is hub-side: clear Missing immediately so operators need not wait for a pull.
	if j.Verb == VerbAckMissing && h.agents != nil {
		h.agentMu.Lock()
		err := h.agents.AckMissing(agentID)
		h.agentMu.Unlock()
		if err != nil {
			h.log.Info("ack_missing enqueue", "agent_id", agentID, "err", err)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "job": j})
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs, "count": len(jobs)})
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"audit": entries, "count": len(entries)})
}
