package hub

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/sink"
)

const maxIngestBody = 1 << 20 // 1 MiB

// seenIDs bounds replay/retry dedupe of successfully ingested event_ids.
type seenIDs struct {
	mu   sync.Mutex
	ids  map[string]struct{}
	order []string
	max  int
}

func newSeenIDs(max int) *seenIDs {
	if max < 64 {
		max = 4096
	}
	return &seenIDs{ids: make(map[string]struct{}, max), max: max}
}

// Reserve marks id as in-flight/seen. Returns true if it was already present.
func (s *seenIDs) Reserve(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ids[id]; ok {
		return true
	}
	if len(s.order) >= s.max {
		old := s.order[0]
		s.order = s.order[1:]
		delete(s.ids, old)
	}
	s.ids[id] = struct{}{}
	s.order = append(s.order, id)
	return false
}

// Forget drops a reserved id so a failed ingest can be retried.
func (s *seenIDs) Forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ids[id]; !ok {
		return
	}
	delete(s.ids, id)
	for i, v := range s.order {
		if v == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}

func (h *Hub) handleIngest(w http.ResponseWriter, r *http.Request) {
	if len(h.ingestSecret) == 0 {
		http.Error(w, "ingest disabled", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxIngestBody+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if len(body) > maxIngestBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := sink.VerifySignature(
		h.ingestSecret,
		r.Header.Get(sink.HeaderTimestamp),
		r.Header.Get(sink.HeaderSignature),
		body,
		time.Now(),
		sink.DefaultSkew,
	); err != nil {
		h.log.Info("ingest auth failed", "err", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Rate limit only after HMAC so unauthenticated floods cannot burn the bucket.
	if ok, retry := h.allowIngestRate(r); !ok {
		writeTooManyRequests(w, retry)
		return
	}

	var ev event.Event
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := ev.Validate(); err != nil {
		http.Error(w, "invalid event", http.StatusBadRequest)
		return
	}
	if ev.Detector != "sentinel" {
		http.Error(w, "detector must be sentinel", http.StatusBadRequest)
		return
	}
	headerID := r.Header.Get(sink.HeaderEventID)
	if headerID != "" && headerID != ev.EventID {
		http.Error(w, "event_id mismatch", http.StatusBadRequest)
		return
	}

	if h.seen.Reserve(ev.EventID) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := h.recordIngest(&ev); err != nil {
		h.seen.Forget(ev.EventID)
		h.log.Error("record ingest", "err", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Hub) recordIngest(ev *event.Event) error {
	// Only token_id identifies control-plane heartbeats. Do not trust action alone:
	// a signed ingest with action=heartbeat on a real token must still alert.
	if ev.TokenID == "heartbeat" {
		// Hold agentMu so missing/recovered emits cannot interleave with this heartbeat.
		// Append before NoteHeartbeat so a failed chain write does not clear Missing
		// and drop the recovery transition on retry.
		h.agentMu.Lock()
		defer h.agentMu.Unlock()
		if err := h.chain.Append(ev); err != nil {
			return err
		}
		recovered := h.agents.NoteHeartbeat(ev)
		// Heartbeats are control-plane: record + track, do not alert/SSE flood.
		h.mu.Lock()
		h.hits++
		h.mu.Unlock()
		if recovered {
			if err := h.emitAgentRecoveredLocked(ev); err != nil {
				// Re-arm so a later heartbeat retries agent_recovered.
				if id := agentKey(ev); id != "" {
					h.agents.MarkRecoverPending(id)
				}
			}
		}
		return nil
	}

	// Annotate unknown/revoked tokens like beacons (memo only).
	active, err := h.reg.ExistsActive(ev.TokenID)
	if err != nil {
		return err
	}
	if m, err := h.reg.Get(ev.TokenID); err == nil {
		if ev.Memo == "" {
			ev.Memo = m.Memo
		}
		if m.Name != "" && !strings.Contains(ev.Memo, m.Name) {
			if ev.Memo != "" {
				ev.Memo = m.Name + " | " + ev.Memo
			} else {
				ev.Memo = m.Name
			}
		}
		if m.Revoked {
			ev.Memo = ev.Memo + " [REVOKED]"
		} else if m.Expired(time.Now().UTC()) {
			ev.Memo = ev.Memo + " [EXPIRED]"
		}
	} else if !active && ev.TokenID != "unmapped" {
		if ev.Memo != "" {
			ev.Memo += " | "
		}
		ev.Memo += "unknown or unregistered token"
	}

	// Hub re-chains with its own keys (sentinel integrity replaced).
	allow, suppressed := h.throttle.Allow(ev)
	if !allow {
		h.log.Info("alert suppressed (still recorded)", "token_id", ev.TokenID, "suppressed", suppressed, "src", "ingest")
	}
	if err := h.chain.Append(ev); err != nil {
		return err
	}
	h.subs.Broadcast(ev)
	if allow {
		if err := h.queue.Enqueue(ev); err != nil {
			return err
		}
	}
	h.mu.Lock()
	h.hits++
	h.alerts++
	h.mu.Unlock()
	return nil
}

func (h *Hub) watchAgents(ctx context.Context) {
	interval := h.cfg.AgentStaleAfter / 6
	if interval < 50*time.Millisecond {
		interval = 50 * time.Millisecond
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.emitMissingAgents(time.Now().UTC())
		}
	}
}

func (h *Hub) emitMissingAgents(now time.Time) {
	h.agentMu.Lock()
	defer h.agentMu.Unlock()
	for _, rec := range h.agents.CheckMissing(now) {
		// Claim under tracker lock so AckMissing cannot win the race between check and mark.
		if !h.agents.ClaimMissingAlert(rec.ID) {
			continue
		}
		tier := rec.Tier
		if tier == "" {
			tier = "agent-watch"
		}
		// token_id stays a control-plane marker so the UI token column is not a decoy id.
		ev := event.New("agent_status", "hub", tier, "agent_missing")
		ev.Memo = "sentinel heartbeat overdue"
		ev.Host = &event.HostInfo{
			ID:           rec.ID,
			Hostname:     rec.Hostname,
			OS:           rec.OS,
			AgentVersion: rec.AgentVersion,
		}
		ev.Confidence.Action = "inferred"
		if err := h.chain.Append(ev); err != nil {
			h.log.Error("agent_missing chain", "agent_id", rec.ID, "err", err)
			h.agents.AbortMissingAlert(rec.ID)
			continue
		}
		// Persist alerted only after durable chain append so a crash mid-emit retries.
		h.agents.MarkMissingAlerted(rec.ID)
		h.subs.Broadcast(ev)
		if err := h.queue.Enqueue(ev); err != nil {
			h.log.Error("agent_missing enqueue", "agent_id", rec.ID, "err", err)
		}
		h.log.Info("agent missing", "agent_id", rec.ID, "hostname", rec.Hostname, "last_seen", rec.LastSeen)
		h.mu.Lock()
		h.hits++
		h.alerts++
		h.mu.Unlock()
	}
}

// emitAgentRecoveredLocked requires h.agentMu held by the caller.
// Returns an error only when the chain append fails (safe to retry).
// Enqueue failure is logged but not retried - the event is already chained/broadcast.
func (h *Hub) emitAgentRecoveredLocked(hb *event.Event) error {
	ev := event.New("agent_status", "hub", "agent-watch", "agent_recovered")
	ev.Memo = "sentinel heartbeat resumed"
	if hb != nil && hb.Host != nil {
		ev.Host = &event.HostInfo{
			ID:           hb.Host.ID,
			Hostname:     hb.Host.Hostname,
			OS:           hb.Host.OS,
			AgentVersion: hb.Host.AgentVersion,
		}
		if hb.DetectionTier != "" {
			ev.DetectionTier = hb.DetectionTier
		}
	}
	ev.Confidence.Action = "inferred"
	if err := h.chain.Append(ev); err != nil {
		h.log.Error("agent_recovered chain", "err", err)
		return err
	}
	h.subs.Broadcast(ev)
	if err := h.queue.Enqueue(ev); err != nil {
		h.log.Error("agent_recovered enqueue", "err", err)
	}
	h.mu.Lock()
	h.hits++
	h.alerts++
	h.mu.Unlock()
	return nil
}
