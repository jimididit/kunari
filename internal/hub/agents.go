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
	AgentVersion string    `json:"agent_version,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
	Missing      bool      `json:"missing"`
	Retired      bool      `json:"retired,omitempty"`
	StaleAfter   string    `json:"stale_after,omitempty"`
}

type agentRecord struct {
	ID             string    `json:"id"`
	Hostname       string    `json:"hostname,omitempty"`
	OS             string    `json:"os,omitempty"`
	Tier           string    `json:"tier,omitempty"`
	AgentVersion   string    `json:"agent_version,omitempty"`
	LastSeen       time.Time `json:"last_seen"`
	Missing        bool      `json:"missing"`
	MissingAlerted bool      `json:"missing_alerted"`
	Retired        bool      `json:"retired,omitempty"`
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
	wasMissing := rec.Missing && !rec.Retired
	// Hub clock only - sender ObservedAt must not push last-seen into the future.
	rec.LastSeen = time.Now().UTC()
	rec.Missing = false
	rec.MissingAlerted = false
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
	}
	if ev.DetectionTier != "" {
		rec.Tier = ev.DetectionTier
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
			if rec.Missing {
				rec.Missing = false
				rec.MissingAlerted = false
				changed = true
			}
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
		}
	}
	return out
}

// NeedsMissingAlert reports whether id is still missing and has not been alerted.
func (t *agentTracker) NeedsMissingAlert(id string) bool {
	if t == nil || id == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byID[id]
	return rec != nil && !rec.Retired && rec.Missing && !rec.MissingAlerted
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
	}
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
		out = append(out, agentView{
			ID:           rec.ID,
			Hostname:     rec.Hostname,
			OS:           rec.OS,
			Tier:         rec.Tier,
			AgentVersion: rec.AgentVersion,
			LastSeen:     rec.LastSeen,
			Missing:      missing,
			StaleAfter:   stale,
		})
	}
	sort.Slice(out, func(i, j int) bool {
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
