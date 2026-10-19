package hub

import (
	"encoding/json"
	"os"
	"path/filepath"
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
}

type agentTracker struct {
	mu         sync.Mutex
	path       string
	staleAfter time.Duration
	byID       map[string]*agentRecord
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
	_ = t.load()
	return t, nil
}

func (t *agentTracker) enabled() bool {
	return t != nil && t.staleAfter > 0
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

func (t *agentTracker) NoteHeartbeat(ev *event.Event) {
	if t == nil || !t.enabled() {
		return
	}
	id := agentKey(ev)
	if id == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.byID[id]
	if rec == nil {
		rec = &agentRecord{ID: id}
		t.byID[id] = rec
	}
	rec.LastSeen = ev.ObservedAt
	if rec.LastSeen.IsZero() {
		rec.LastSeen = time.Now().UTC()
	}
	rec.Missing = false
	rec.MissingAlerted = false
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
	_ = t.persistLocked()
}

// CheckMissing marks overdue agents and returns those that need a new alert.
func (t *agentTracker) CheckMissing(now time.Time) []*agentRecord {
	if t == nil || !t.enabled() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*agentRecord
	for _, rec := range t.byID {
		if rec.LastSeen.IsZero() {
			continue
		}
		if now.Sub(rec.LastSeen) < t.staleAfter {
			if rec.Missing {
				rec.Missing = false
				rec.MissingAlerted = false
			}
			continue
		}
		rec.Missing = true
		if !rec.MissingAlerted {
			rec.MissingAlerted = true
			cp := *rec
			out = append(out, &cp)
		}
	}
	if len(out) > 0 {
		_ = t.persistLocked()
	}
	return out
}

func (t *agentTracker) Snapshot() []agentView {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]agentView, 0, len(t.byID))
	stale := ""
	if t.staleAfter > 0 {
		stale = t.staleAfter.String()
	}
	for _, rec := range t.byID {
		out = append(out, agentView{
			ID:           rec.ID,
			Hostname:     rec.Hostname,
			OS:           rec.OS,
			Tier:         rec.Tier,
			AgentVersion: rec.AgentVersion,
			LastSeen:     rec.LastSeen,
			Missing:      rec.Missing,
			StaleAfter:   stale,
		})
	}
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
