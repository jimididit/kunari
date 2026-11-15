package hub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jimididit/kunari/internal/safepath"
)

// Allowlisted control-plane verbs. No shell, no arbitrary exec.
const (
	VerbReloadConfig   = "reload_config"
	VerbSetTargets     = "set_targets"
	VerbStatusDump     = "status_dump"
	VerbAckMissing     = "ack_missing"
	VerbRotateHubURL   = "rotate_hub_url_hint"
)

const (
	jobStatusQueued = "queued"
	jobStatusDone   = "done"
	jobStatusFailed = "failed"
	jobStatusExpired = "expired"
)

const defaultJobTTL = 30 * time.Minute
const maxJobsPersisted = 500

var allowedJobVerbs = map[string]struct{}{
	VerbReloadConfig: {},
	VerbSetTargets:   {},
	VerbStatusDump:   {},
	VerbAckMissing:   {},
	VerbRotateHubURL: {},
}

// Job is a bounded operator action for one agent to pull and execute.
type Job struct {
	ID        string          `json:"id"`
	AgentID   string          `json:"agent_id"`
	Verb      string          `json:"verb"`
	Args      json.RawMessage `json:"args,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	CreatedBy string          `json:"created_by,omitempty"`
	ExpiresAt time.Time       `json:"expires_at"`
	Status    string          `json:"status"`
	Result    string          `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	DoneAt    *time.Time      `json:"done_at,omitempty"`
	Sig       string          `json:"sig"` // HMAC over canonical job fields
}

// AuditEntry records who queued which verb.
type AuditEntry struct {
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	AgentID string    `json:"agent_id"`
	JobID   string    `json:"job_id"`
	Verb    string    `json:"verb"`
	Detail  string    `json:"detail,omitempty"`
}

type jobStore struct {
	mu     sync.Mutex
	path   string
	auditP string
	jobs   map[string]*Job
	audit  []AuditEntry
	secret []byte
}

func newJobStore(dataDir string, ingestSecret []byte) (*jobStore, error) {
	dataDir, err := safepath.Clean(dataDir)
	if err != nil {
		return nil, err
	}
	s := &jobStore{
		path:   filepath.Join(dataDir, "jobs.json"),
		auditP: filepath.Join(dataDir, "jobs-audit.json"),
		jobs:   map[string]*Job{},
		secret: append([]byte(nil), ingestSecret...),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func AllowedJobVerb(verb string) bool {
	_, ok := allowedJobVerbs[strings.TrimSpace(verb)]
	return ok
}

func (s *jobStore) Enqueue(agentID, verb, createdBy string, args json.RawMessage) (*Job, error) {
	agentID = strings.TrimSpace(agentID)
	verb = strings.TrimSpace(verb)
	if agentID == "" {
		return nil, fmt.Errorf("agent_id required")
	}
	if !AllowedJobVerb(verb) {
		return nil, fmt.Errorf("verb %q not allowlisted", verb)
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	if !json.Valid(args) {
		return nil, fmt.Errorf("args must be json")
	}
	now := time.Now().UTC()
	j := &Job{
		ID:        uuid.Must(uuid.NewV7()).String(),
		AgentID:   agentID,
		Verb:      verb,
		Args:      args,
		CreatedAt: now,
		CreatedBy: createdBy,
		ExpiresAt: now.Add(defaultJobTTL),
		Status:    jobStatusQueued,
	}
	sig, err := signJob(s.secret, j)
	if err != nil {
		return nil, err
	}
	j.Sig = sig

	s.mu.Lock()
	defer s.mu.Unlock()
	detail := "queued"
	// ack_missing is hub-side: never leave it queued for a possibly-offline agent.
	if verb == VerbAckMissing {
		j.Status = jobStatusDone
		j.Result = "acked by operator"
		j.DoneAt = &now
		detail = jobStatusDone
	}
	s.jobs[j.ID] = j
	s.audit = append(s.audit, AuditEntry{
		At:      now,
		Actor:   createdBy,
		AgentID: agentID,
		JobID:   j.ID,
		Verb:    verb,
		Detail:  detail,
	})
	s.trimLocked()
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	cp := *j
	return &cp, nil
}

func (s *jobStore) Pull(agentID string, limit int) ([]Job, error) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return nil, fmt.Errorf("agent_id required")
	}
	if limit <= 0 || limit > 20 {
		limit = 5
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Job
	changed := false
	for _, j := range s.jobs {
		if j.AgentID != agentID {
			continue
		}
		if j.Status != jobStatusQueued {
			continue
		}
		if !j.ExpiresAt.IsZero() && now.After(j.ExpiresAt) {
			j.Status = jobStatusExpired
			changed = true
			continue
		}
		out = append(out, *j)
	}
	sort.Slice(out, func(i, k int) bool {
		return out[i].CreatedAt.Before(out[k].CreatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	if changed {
		_ = s.persistLocked()
	}
	return out, nil
}

func (s *jobStore) Complete(agentID, jobID, result, errMsg string) (*Job, error) {
	agentID = strings.TrimSpace(agentID)
	jobID = strings.TrimSpace(jobID)
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[jobID]
	if j == nil || j.AgentID != agentID {
		return nil, fmt.Errorf("not found")
	}
	if j.Status != jobStatusQueued {
		cp := *j
		return &cp, nil
	}
	now := time.Now().UTC()
	j.DoneAt = &now
	if errMsg != "" {
		j.Status = jobStatusFailed
		j.Error = truncateRunes(errMsg, 500)
	} else {
		j.Status = jobStatusDone
		j.Result = truncateRunes(result, 4000)
	}
	s.audit = append(s.audit, AuditEntry{
		At:      now,
		Actor:   "agent:" + agentID,
		AgentID: agentID,
		JobID:   jobID,
		Verb:    j.Verb,
		Detail:  j.Status,
	})
	s.trimLocked()
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	cp := *j
	return &cp, nil
}

func (s *jobStore) ListForAgent(agentID string, limit int) []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	var out []Job
	for _, j := range s.jobs {
		if agentID != "" && j.AgentID != agentID {
			continue
		}
		out = append(out, *j)
	}
	sort.Slice(out, func(i, k int) bool {
		return out[i].CreatedAt.After(out[k].CreatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *jobStore) Audit(limit int) []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	n := len(s.audit)
	if n == 0 {
		return nil
	}
	start := 0
	if n > limit {
		start = n - limit
	}
	out := make([]AuditEntry, n-start)
	copy(out, s.audit[start:])
	// newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (s *jobStore) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := time.Now().UTC()
	for _, j := range s.jobs {
		if j.Status == jobStatusQueued && (j.ExpiresAt.IsZero() || now.Before(j.ExpiresAt)) {
			n++
		}
	}
	return n
}

func (s *jobStore) trimLocked() {
	if len(s.jobs) <= maxJobsPersisted {
		return
	}
	type pair struct {
		id string
		t  time.Time
	}
	var all []pair
	for id, j := range s.jobs {
		all = append(all, pair{id: id, t: j.CreatedAt})
	}
	sort.Slice(all, func(i, k int) bool { return all[i].t.Before(all[k].t) })
	drop := len(all) - maxJobsPersisted
	for i := 0; i < drop; i++ {
		delete(s.jobs, all[i].id)
	}
	if len(s.audit) > maxJobsPersisted {
		s.audit = s.audit[len(s.audit)-maxJobsPersisted:]
	}
}

func (s *jobStore) load() error {
	if b, err := os.ReadFile(s.path); err == nil { // #nosec G304 -- under data_dir
		var items []Job
		if err := json.Unmarshal(b, &items); err != nil {
			return err
		}
		for i := range items {
			cp := items[i]
			s.jobs[cp.ID] = &cp
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if b, err := os.ReadFile(s.auditP); err == nil { // #nosec G304 -- under data_dir
		var items []AuditEntry
		if err := json.Unmarshal(b, &items); err != nil {
			return err
		}
		s.audit = items
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *jobStore) persistLocked() error {
	items := make([]Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		items = append(items, *j)
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path, b, 0o600); err != nil {
		return err
	}
	ab, err := json.MarshalIndent(s.audit, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.auditP, ab, 0o600)
}

func signJob(secret []byte, j *Job) (string, error) {
	if len(secret) < 16 {
		return "", fmt.Errorf("ingest secret too short for job signing")
	}
	args := string(j.Args)
	if args == "" {
		args = "{}"
	}
	payload := j.ID + "\n" + j.AgentID + "\n" + j.Verb + "\n" + args + "\n" + j.ExpiresAt.UTC().Format(time.RFC3339Nano)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyJobSig checks the job HMAC using the shared ingest secret.
func VerifyJobSig(secret []byte, j *Job) error {
	want, err := signJob(secret, j)
	if err != nil {
		return err
	}
	got := strings.TrimSpace(j.Sig)
	wb, err := hex.DecodeString(strings.TrimPrefix(want, "sha256="))
	if err != nil {
		return err
	}
	gb, err := hex.DecodeString(strings.TrimPrefix(got, "sha256="))
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	if !hmac.Equal(wb, gb) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func truncateRunes(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}
