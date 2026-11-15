package hub

import (
	"bytes"
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
	"unicode/utf8"

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
	jobStatusQueued   = "queued"
	jobStatusInflight = "inflight"
	jobStatusDone     = "done"
	jobStatusFailed   = "failed"
	jobStatusExpired  = "expired"
)

const defaultJobTTL = 30 * time.Minute
const jobLease = 5 * time.Minute
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
	Status      string          `json:"status"`
	Result      string          `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	DeliveredAt *time.Time      `json:"delivered_at,omitempty"`
	DoneAt      *time.Time      `json:"done_at,omitempty"`
	Sig         string          `json:"sig"` // HMAC over canonical job fields
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

type jobStoreFile struct {
	Jobs  []Job        `json:"jobs"`
	Audit []AuditEntry `json:"audit"`
}

type jobStore struct {
	mu     sync.Mutex
	path   string // single atomic jobs-state.json (jobs + audit)
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
		path:   filepath.Join(dataDir, "jobs-state.json"),
		jobs:   map[string]*Job{},
		secret: append([]byte(nil), ingestSecret...),
	}
	if err := s.load(dataDir); err != nil {
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
	args, err := canonicalJSONArgs(args)
	if err != nil {
		return nil, err
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
	auditLen := len(s.audit)
	s.audit = append(s.audit, AuditEntry{
		At:      now,
		Actor:   createdBy,
		AgentID: agentID,
		JobID:   j.ID,
		Verb:    verb,
		Detail:  detail,
	})
	if err := s.persistLocked(); err != nil {
		delete(s.jobs, j.ID)
		s.audit = s.audit[:auditLen]
		return nil, err
	}
	s.trimLocked()
	_ = s.persistLocked() // best-effort trim persist; enqueue already durable
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
		if !j.ExpiresAt.IsZero() && now.After(j.ExpiresAt) {
			if j.Status == jobStatusQueued || j.Status == jobStatusInflight {
				j.Status = jobStatusExpired
				changed = true
			}
			continue
		}
		switch j.Status {
		case jobStatusQueued:
			// claim with lease so re-poll does not re-deliver until lease expires
		case jobStatusInflight:
			if j.DeliveredAt != nil && now.Sub(*j.DeliveredAt) < jobLease {
				continue // still leased to a prior pull
			}
		default:
			continue
		}
		del := now
		j.Status = jobStatusInflight
		j.DeliveredAt = &del
		changed = true
		out = append(out, *j)
	}
	sort.Slice(out, func(i, k int) bool {
		return out[i].CreatedAt.Before(out[k].CreatedAt)
	})
	if len(out) > limit {
		// un-claim overflow so they stay queued for the next pull
		for _, j := range out[limit:] {
			if stored := s.jobs[j.ID]; stored != nil && stored.Status == jobStatusInflight {
				stored.Status = jobStatusQueued
				stored.DeliveredAt = nil
			}
		}
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
	if j.Status != jobStatusQueued && j.Status != jobStatusInflight {
		cp := *j
		return &cp, nil
	}
	prevStatus := j.Status
	prevResult := j.Result
	prevError := j.Error
	prevDoneAt := j.DoneAt
	now := time.Now().UTC()
	j.DoneAt = &now
	if errMsg != "" {
		j.Status = jobStatusFailed
		j.Error = truncateRunes(errMsg, 500)
		j.Result = ""
	} else {
		j.Status = jobStatusDone
		j.Result = truncateRunes(result, 4000)
		j.Error = ""
	}
	auditLen := len(s.audit)
	s.audit = append(s.audit, AuditEntry{
		At:      now,
		Actor:   "agent:" + agentID,
		AgentID: agentID,
		JobID:   jobID,
		Verb:    j.Verb,
		Detail:  j.Status,
	})
	if err := s.persistLocked(); err != nil {
		j.Status = prevStatus
		j.Result = prevResult
		j.Error = prevError
		j.DoneAt = prevDoneAt
		s.audit = s.audit[:auditLen]
		return nil, err
	}
	s.trimLocked()
	_ = s.persistLocked() // best-effort trim persist; completion already durable
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
		if j.ExpiresAt.IsZero() || now.Before(j.ExpiresAt) {
			if j.Status == jobStatusQueued || j.Status == jobStatusInflight {
				n++
			}
		}
	}
	return n
}

func (s *jobStore) trimLocked() {
	if len(s.jobs) <= maxJobsPersisted {
		return
	}
	type pair struct {
		id     string
		t      time.Time
		active bool // queued/inflight - prefer keep
	}
	var all []pair
	for id, j := range s.jobs {
		active := j.Status == jobStatusQueued || j.Status == jobStatusInflight
		all = append(all, pair{id: id, t: j.CreatedAt, active: active})
	}
	// Drop finished/expired first (oldest), then active only if still over cap.
	sort.Slice(all, func(i, k int) bool {
		if all[i].active != all[k].active {
			return !all[i].active && all[k].active
		}
		return all[i].t.Before(all[k].t)
	})
	drop := len(all) - maxJobsPersisted
	for i := 0; i < drop; i++ {
		delete(s.jobs, all[i].id)
	}
	if len(s.audit) > maxJobsPersisted {
		s.audit = s.audit[len(s.audit)-maxJobsPersisted:]
	}
}

func (s *jobStore) load(dataDir string) error {
	b, err := os.ReadFile(s.path) // #nosec G304 -- path under safepath-cleaned data_dir
	if err == nil {
		var doc jobStoreFile
		if err := json.Unmarshal(b, &doc); err != nil {
			return err
		}
		for i := range doc.Jobs {
			cp := doc.Jobs[i]
			s.jobs[cp.ID] = &cp
		}
		s.audit = doc.Audit
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	// Migrate legacy split files from earlier Phase E builds (paths under safepath-cleaned dataDir).
	legacyJobs := filepath.Join(dataDir, "jobs.json")
	legacyAudit := filepath.Join(dataDir, "jobs-audit.json")
	b, err = os.ReadFile(legacyJobs) // #nosec G304 -- path under safepath-cleaned data_dir
	if err == nil {
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
	b, err = os.ReadFile(legacyAudit) // #nosec G304 -- path under safepath-cleaned data_dir
	if err == nil {
		var items []AuditEntry
		if err := json.Unmarshal(b, &items); err != nil {
			return err
		}
		s.audit = items
	} else if !os.IsNotExist(err) {
		return err
	}
	if len(s.jobs) > 0 || len(s.audit) > 0 {
		if err := s.persistLocked(); err != nil {
			return err
		}
	}
	return nil
}

func (s *jobStore) persistLocked() error {
	items := make([]Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		items = append(items, *j)
	}
	doc := jobStoreFile{Jobs: items, Audit: s.audit}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, b)
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func canonicalJSONArgs(args json.RawMessage) (json.RawMessage, error) {
	if len(args) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if !json.Valid(args) {
		return nil, fmt.Errorf("args must be json")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, args); err != nil {
		return nil, fmt.Errorf("args: %w", err)
	}
	return json.RawMessage(buf.Bytes()), nil
}

func signJob(secret []byte, j *Job) (string, error) {
	if len(secret) < 16 {
		return "", fmt.Errorf("ingest secret too short for job signing")
	}
	args, err := canonicalJSONArgs(j.Args)
	if err != nil {
		return "", err
	}
	// Domain-separated from ingest body HMAC (timestamp+"."+body).
	payload := "kunari.job/1\n" + j.ID + "\n" + j.AgentID + "\n" + j.Verb + "\n" + string(args) + "\n" + j.ExpiresAt.UTC().Format(time.RFC3339Nano)
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
	// n is a byte budget; cut on a rune boundary so multi-byte UTF-8 is not split.
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
