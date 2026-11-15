package hub

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/safepath"
)

// agentView is the operator-facing snapshot of a heartbeating sentinel.
type agentView struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname,omitempty"`
	OS           string    `json:"os,omitempty"`
	Tier         string    `json:"tier,omitempty"`
	Capabilities string    `json:"capabilities,omitempty"`
	WatchCount   int       `json:"watch_count"`
	AgentVersion string    `json:"agent_version,omitempty"`
	Engagement   string    `json:"engagement,omitempty"`
	AgentLabel   string    `json:"agent_label,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
	Missing      bool      `json:"missing"`
	Acked        bool      `json:"acked,omitempty"` // operator ack_missing while still stale
	Retired      bool      `json:"retired,omitempty"`
	StaleAfter   string    `json:"stale_after,omitempty"`
}

type agentRecord struct {
	ID              string    `json:"id"`
	Hostname        string    `json:"hostname,omitempty"`
	OS              string    `json:"os,omitempty"`
	Tier            string    `json:"tier,omitempty"`
	Capabilities    string    `json:"capabilities,omitempty"`
	WatchCount      int       `json:"watch_count,omitempty"`
	AgentVersion    string    `json:"agent_version,omitempty"`
	Engagement      string    `json:"engagement,omitempty"`
	AgentLabel      string    `json:"agent_label,omitempty"`
	LastSeen        time.Time `json:"last_seen"`
	Missing         bool      `json:"missing"`
	MissingAlerted  bool      `json:"missing_alerted"`
	OperatorAcked   bool      `json:"operator_acked,omitempty"`
	RecoverPending  bool      `json:"recover_pending,omitempty"`
	Retired         bool      `json:"retired,omitempty"`
}

type agentTracker struct {
	mu         sync.Mutex
	path       string
	staleAfter time.Duration
	byID       map[string]*agentRecord
	lastErr    string
}

func newAgentTracker(dataDir string, staleAfter time.Duration) (*agentTracker, error) {
	if staleAfter < 0 {
		staleAfter = 0
	}
	dataDir, err := safepath.Clean(dataDir)
	if err != nil {
		return nil, err
	}
	t := &agentTracker{
		path:       filepath.Join(dataDir, "agents.json"),
		staleAfter: staleAfter,
		byID:       map[string]*agentRecord{},
	}
	if err := t.load(); err != nil {
		t.lastErr = err.Error()
	}
	return t, nil
}

func (t *agentTracker) enabled() bool {
	return t != nil && t.staleAfter > 0
}

func (t *agentTracker) PersistError() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastErr
}

func agentKey(ev *event.Event) string {
	if ev == nil {
		return ""
	}
	if ev.Host != nil && ev.Host.ID != "" {
		return ev.Host.ID
	}
	if ev.Host != nil && ev.Host.Hostname != "" {
		osName := ev.Host.OS
		if osName == "" {
			osName = "unknown"
		}
		return ev.Host.Hostname + "|" + osName
	}
	return ""
}

// NoteHeartbeat updates last-seen. recovered is true when a previously missing
// (and not retired) agent returns.
func (t *agentTracker) NoteHeartbeat(ev *event.Event) (recovered bool) {
	if t == nil || !t.enabled() {
		return false
	}
	id := agentKey(ev)
	if id == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byID[id]
	if rec == nil {
		rec = &agentRecord{ID: id}
		t.byID[id] = rec
	}
	// Pair agent_recovered with a prior missing alert (or operator-acked missing), or retry a failed recover emit.
	// OperatorAcked alone is not enough - AckMissing only sets it when the agent was actually stale/missing.
	wasMissing := !rec.Retired && ((rec.Missing && rec.MissingAlerted) || rec.RecoverPending || (rec.OperatorAcked && rec.MissingAlerted))
	// Hub clock only - sender ObservedAt must not push last-seen into the future.
	rec.LastSeen = time.Now().UTC()
	rec.Missing = false
	rec.MissingAlerted = false
	rec.OperatorAcked = false
	rec.RecoverPending = false
	rec.Retired = false
	if ev.Host != nil {
		if ev.Host.Hostname != "" {
			rec.Hostname = ev.Host.Hostname
		}
		if ev.Host.OS != "" {
			rec.OS = ev.Host.OS
		}
		if ev.Host.AgentVersion != "" {
			rec.AgentVersion = ev.Host.AgentVersion
		}
		if ev.Host.Engagement != "" {
			rec.Engagement = ev.Host.Engagement
		}
		if ev.Host.AgentLabel != "" {
			rec.AgentLabel = ev.Host.AgentLabel
		}
	}
	if ev.DetectionTier != "" {
		rec.Tier = ev.DetectionTier
	}
	if meta, ok := parseHeartbeatMeta(ev.Memo); ok {
		if meta.Caps != "" {
			rec.Capabilities = meta.Caps
		}
		// Apply watches only when the key is present (including 0); caps-only must not clear it.
		if meta.HasWatches {
			rec.WatchCount = meta.Watches
		}
	}
	if err := t.persistLocked(); err != nil {
		t.lastErr = err.Error()
	} else {
		t.lastErr = ""
	}
	return wasMissing
}

// CheckMissing marks overdue agents and returns those still needing an alert.
// MissingAlerted is set only via MarkMissingAlerted after a successful emit.
func (t *agentTracker) CheckMissing(now time.Time) []*agentRecord {
	if t == nil || !t.enabled() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*agentRecord
	changed := false
	for _, rec := range t.byID {
		if rec.Retired || rec.LastSeen.IsZero() {
			continue
		}
		if now.Sub(rec.LastSeen) < t.staleAfter {
			if rec.Missing || rec.OperatorAcked {
				rec.Missing = false
				rec.MissingAlerted = false
				rec.OperatorAcked = false
				changed = true
			}
			continue
		}
		// Operator ack suppresses further missing alerts until heartbeat returns.
		if rec.OperatorAcked {
			continue
		}
		if !rec.Missing {
			rec.Missing = true
			changed = true
		}
		if !rec.MissingAlerted {
			cp := *rec
			out = append(out, &cp)
		}
	}
	if changed {
		if err := t.persistLocked(); err != nil {
			t.lastErr = err.Error()
		} else {
			t.lastErr = ""
		}
	}
	return out
}

// MarkRecoverPending arms a retry when agent_recovered failed to emit durably.
func (t *agentTracker) MarkRecoverPending(id string) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byID[id]
	if rec == nil || rec.Retired {
		return
	}
	rec.RecoverPending = true
	if err := t.persistLocked(); err != nil {
		t.lastErr = err.Error()
	} else {
		t.lastErr = ""
	}
}

// NeedsMissingAlert reports whether id is still missing and has not been alerted.
func (t *agentTracker) NeedsMissingAlert(id string) bool {
	if t == nil || id == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byID[id]
	return rec != nil && !rec.Retired && !rec.OperatorAcked && rec.Missing && !rec.MissingAlerted
}

// MarkMissingAlerted records that a missing-agent alert was durably emitted.
func (t *agentTracker) MarkMissingAlerted(id string) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byID[id]
	if rec == nil || !rec.Missing {
		return
	}
	rec.MissingAlerted = true
	if err := t.persistLocked(); err != nil {
		t.lastErr = err.Error()
	} else {
		t.lastErr = ""
	}
}

// AckMissing clears a missing-agent flag after operator acknowledgement.
// Does not retire the agent; a later heartbeat still updates LastSeen.
func (t *agentTracker) AckMissing(id string) error {
	if t == nil {
		return fmt.Errorf("agent tracker disabled")
	}
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, `/\`) {
		return fmt.Errorf("invalid agent id")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byID[id]
	if rec == nil {
		return fmt.Errorf("not found")
	}
	if rec.Retired {
		return fmt.Errorf("retired")
	}
	now := time.Now().UTC()
	stale := rec.Missing
	if t.staleAfter > 0 && !rec.LastSeen.IsZero() {
		stale = stale || now.Sub(rec.LastSeen) >= t.staleAfter
	}
	if !stale {
		return fmt.Errorf("agent not missing")
	}
	// Keep MissingAlerted as-is: only emit agent_recovered later if a missing
	// alert was actually raised. Fresh OperatorAck without a prior alert must not forge recovery.
	rec.Missing = false
	rec.OperatorAcked = true
	rec.RecoverPending = false
	if err := t.persistLocked(); err != nil {
		t.lastErr = err.Error()
		return err
	}
	t.lastErr = ""
	return nil
}

// KnownRecently reports whether id has heartbeated within within and is not retired.
func (t *agentTracker) KnownRecently(id string, within time.Duration) bool {
	if t == nil || id == "" || within <= 0 {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byID[id]
	if rec == nil || rec.Retired || rec.LastSeen.IsZero() {
		return false
	}
	return time.Since(rec.LastSeen) <= within
}

// Retire removes an agent from the active roster (reimaged / decommissioned hosts).
func (t *agentTracker) Retire(id string) error {
	if t == nil {
		return fmt.Errorf("agent tracker disabled")
	}
	id = strings.TrimSpace(id)
	if id == "" || strings.ContainsAny(id, `/\`) {
		return fmt.Errorf("invalid agent id")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byID[id]
	if rec == nil {
		return fmt.Errorf("not found")
	}
	rec.Retired = true
	rec.Missing = false
	rec.MissingAlerted = true
	rec.RecoverPending = false
	if err := t.persistLocked(); err != nil {
		t.lastErr = err.Error()
		return err
	}
	t.lastErr = ""
	return nil
}

func (t *agentTracker) Snapshot() []agentView {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().UTC()
	out := make([]agentView, 0, len(t.byID))
	stale := ""
	if t.staleAfter > 0 {
		stale = t.staleAfter.String()
	}
	for _, rec := range t.byID {
		if rec.Retired {
			continue
		}
		missing := rec.Missing
		if t.staleAfter > 0 && !rec.LastSeen.IsZero() {
			missing = now.Sub(rec.LastSeen) >= t.staleAfter
		}
		acked := rec.OperatorAcked
		if acked {
			missing = false
		}
		out = append(out, agentView{
			ID:           rec.ID,
			Hostname:     rec.Hostname,
			OS:           rec.OS,
			Tier:         rec.Tier,
			Capabilities: rec.Capabilities,
			WatchCount:   rec.WatchCount,
			AgentVersion: rec.AgentVersion,
			Engagement:   rec.Engagement,
			AgentLabel:   rec.AgentLabel,
			LastSeen:     rec.LastSeen,
			Missing:      missing,
			Acked:        acked,
			StaleAfter:   stale,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		ei, ej := out[i].Engagement, out[j].Engagement
		if ei != ej {
			return ei < ej
		}
		li, lj := out[i].AgentLabel, out[j].AgentLabel
		if li != lj {
			return li < lj
		}
		hi, hj := out[i].Hostname, out[j].Hostname
		if hi != hj {
			return hi < hj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (t *agentTracker) load() error {
	b, err := os.ReadFile(t.path) // #nosec G304 -- path under safepath-cleaned data_dir
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var items []agentRecord
	if err := json.Unmarshal(b, &items); err != nil {
		return err
	}
	for i := range items {
		rec := items[i]
		if rec.ID == "" {
			continue
		}
		cp := rec
		t.byID[rec.ID] = &cp
	}
	return nil
}

type heartbeatMeta struct {
	Caps       string
	Watches    int
	HasWatches bool
}

// parseHeartbeatMeta extracts watches=N and caps=... from a sentinel heartbeat memo.
// caps= is expected last so capability text may contain semicolons.
func parseHeartbeatMeta(memo string) (heartbeatMeta, bool) {
	var meta heartbeatMeta
	if memo == "" {
		return meta, false
	}
	found := false
	if i := strings.Index(memo, "watches="); i >= 0 {
		rest := memo[i+len("watches="):]
		n := 0
		digits := 0
		for _, r := range rest {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
			digits++
		}
		if digits > 0 {
			meta.Watches = n
			meta.HasWatches = true
			found = true
		}
	}
	if i := strings.Index(memo, "caps="); i >= 0 {
		meta.Caps = strings.TrimSpace(memo[i+len("caps="):])
		if meta.Caps != "" {
			found = true
		}
	}
	return meta, found
}

func (t *agentTracker) persistLocked() error {
	items := make([]agentRecord, 0, len(t.byID))
	for _, rec := range t.byID {
		items = append(items, *rec)
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, t.path)
}
