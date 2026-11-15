package hub

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	kcrypto "github.com/jimididit/kunari/internal/crypto"
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
	jobStatusQueued     = "queued"
	jobStatusInflight   = "inflight"
	jobStatusHubPending = "hub_pending" // hub-side verbs; never agent-pulled
	jobStatusDone       = "done"
	jobStatusFailed     = "failed"
	jobStatusExpired    = "expired"
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
	Args      json.RawMessage `json:"args"` // always {}; never null (signed as {})
	CreatedAt time.Time       `json:"created_at"`
	CreatedBy string          `json:"created_by,omitempty"`
	ExpiresAt time.Time       `json:"expires_at"`
	Status      string          `json:"status"`
	Result      string          `json:"result,omitempty"`
	Error       string          `json:"error,omitempty"`
	DeliveredAt *time.Time      `json:"delivered_at,omitempty"`
	DoneAt      *time.Time      `json:"done_at,omitempty"`
	Sig         string          `json:"sig"` // ed25519 hex over length-prefixed job fields
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
	mu   sync.Mutex
	path string // single atomic jobs-state.json (jobs + audit)
	jobs map[string]*Job
	audit []AuditEntry
	keys *kcrypto.KeyPair // hub Ed25519; agents verify with provisioned pubkey
}

func newJobStore(dataDir string, keys *kcrypto.KeyPair) (*jobStore, error) {
	if keys == nil || len(keys.Private) == 0 {
		return nil, fmt.Errorf("hub signing key required for job store")
	}
	dataDir, err := safepath.Clean(dataDir)
	if err != nil {
		return nil, err
	}
	s := &jobStore{
		path: filepath.Join(dataDir, "jobs-state.json"),
		jobs: map[string]*Job{},
		keys: keys,
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
	if verb == VerbAckMissing {
		return nil, fmt.Errorf("ack_missing is hub-side; use EnqueueCompleted")
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
	sig, err := signJob(s.keys, j)
	if err != nil {
		return nil, err
	}
	j.Sig = sig

	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[j.ID] = j
	auditLen := len(s.audit)
	s.audit = append(s.audit, AuditEntry{
		At:      now,
		Actor:   createdBy,
		AgentID: agentID,
		JobID:   j.ID,
		Verb:    verb,
		Detail:  "queued",
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

// EnqueueCompleted records a hub-side verb as already finished in one persist
// (never queued/hub_pending, so agents cannot pull or race it).
func (s *jobStore) EnqueueCompleted(agentID, verb, createdBy string, args json.RawMessage, result, errMsg, actor string) (*Job, error) {
	agentID = strings.TrimSpace(agentID)
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
		DoneAt:    &now,
	}
	if errMsg != "" {
		j.Status = jobStatusFailed
		j.Error = truncateRunes(errMsg, 500)
	} else {
		j.Status = jobStatusDone
		j.Result = truncateRunes(result, 4000)
	}
	sig, err := signJob(s.keys, j)
	if err != nil {
		return nil, err
	}
	j.Sig = sig
	auditActor := strings.TrimSpace(actor)
	if auditActor == "" {
		auditActor = "hub"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[j.ID] = j
	auditLen := len(s.audit)
	s.audit = append(s.audit, AuditEntry{
		At:      now,
		Actor:   auditActor,
		AgentID: agentID,
		JobID:   j.ID,
		Verb:    verb,
		Detail:  j.Status,
	})
	if err := s.persistLocked(); err != nil {
		delete(s.jobs, j.ID)
		s.audit = s.audit[:auditLen]
		return nil, err
	}
	s.trimLocked()
	_ = s.persistLocked()
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
	type claim struct {
		prevStatus    string
		prevDelivered *time.Time
	}
	claims := map[string]claim{}
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
			// hub_pending / done / failed / expired are never pulled
			continue
		}
		prevDel := j.DeliveredAt
		claims[j.ID] = claim{prevStatus: j.Status, prevDelivered: prevDel}
		del := now
		j.Status = jobStatusInflight
		j.DeliveredAt = &del
		changed = true
		out = append(out, *j)
	}
	sort.Slice(out, func(i, k int) bool {
		return out[i].CreatedAt.Before(out[k].CreatedAt)
	})
	restoreClaim := func(id string) {
		stored := s.jobs[id]
		c, ok := claims[id]
		if stored == nil || !ok {
			return
		}
		stored.Status = c.prevStatus
		stored.DeliveredAt = c.prevDelivered
	}
	if len(out) > limit {
		// Restore overflow to prior state (queued stays queued; prior inflight keeps lease).
		for _, j := range out[limit:] {
			restoreClaim(j.ID)
		}
		out = out[:limit]
	}
	if changed {
		if err := s.persistLocked(); err != nil {
			for i := range out {
				restoreClaim(out[i].ID)
			}
			return nil, err
		}
	}
	return out, nil
}

func (s *jobStore) Complete(agentID, jobID, result, errMsg string) (*Job, error) {
	return s.completeJob(agentID, jobID, result, errMsg, false, "")
}

// CompleteHub finalizes hub-side jobs (hub_pending); agents cannot call this path.
func (s *jobStore) CompleteHub(agentID, jobID, result, errMsg, actor string) (*Job, error) {
	return s.completeJob(agentID, jobID, result, errMsg, true, actor)
}

func (s *jobStore) completeJob(agentID, jobID, result, errMsg string, hubSide bool, actor string) (*Job, error) {
	agentID = strings.TrimSpace(agentID)
	jobID = strings.TrimSpace(jobID)
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[jobID]
	if j == nil || j.AgentID != agentID {
		return nil, fmt.Errorf("not found")
	}
	if hubSide {
		if j.Status != jobStatusHubPending {
			cp := *j
			return &cp, nil
		}
	} else if j.Status != jobStatusInflight {
		// Agents may only complete jobs they pulled (inflight), not queued/hub_pending.
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
	auditActor := "agent:" + agentID
	if hubSide {
		auditActor = strings.TrimSpace(actor)
		if auditActor == "" {
			auditActor = "hub"
		}
	}
	auditLen := len(s.audit)
	s.audit = append(s.audit, AuditEntry{
		At:      now,
		Actor:   auditActor,
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
			if j.Status == jobStatusQueued || j.Status == jobStatusInflight || j.Status == jobStatusHubPending {
				n++
			}
		}
	}
	return n
}

func (s *jobStore) trimLocked() {
	if len(s.audit) > maxJobsPersisted {
		s.audit = s.audit[len(s.audit)-maxJobsPersisted:]
	}
	if len(s.jobs) <= maxJobsPersisted {
		return
	}
	type pair struct {
		id     string
		t      time.Time
		active bool // queued/inflight/hub_pending - prefer keep
	}
	var all []pair
	for id, j := range s.jobs {
		active := j.Status == jobStatusQueued || j.Status == jobStatusInflight || j.Status == jobStatusHubPending
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
	// Unique temp name avoids clobbering concurrent writers to the same path.
	tmp := fmt.Sprintf("%s.%d.%d.tmp", path, os.Getpid(), time.Now().UnixNano())
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
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
	// Compact HTML-escapes <>&; undo those. Force U+2028/U+2029 to \uXXXX so the
	// sha256 digest matches after JSON transport (which always escapes them).
	b := unescapeJSONHTML(buf.Bytes())
	b = bytes.ReplaceAll(b, []byte("\u2028"), []byte(`\u2028`))
	b = bytes.ReplaceAll(b, []byte("\u2029"), []byte(`\u2029`))
	return json.RawMessage(b), nil
}

// unescapeJSONHTML reverses encoding/json's EscapeHTML substitutions.
// Only rewrites \u003c/\u003e/\u0026 that are not preceded by an odd number of
// backslashes, so a literal "\u0026" in args (encoded as \\u0026) stays intact.
func unescapeJSONHTML(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\u00`)) {
		return b
	}
	s := string(b)
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); {
		if i+6 <= len(s) && s[i] == '\\' && s[i+1] == 'u' && !oddBackslashesBefore(s, i) {
			switch s[i : i+6] {
			case `\u003c`:
				out.WriteByte('<')
				i += 6
				continue
			case `\u003e`:
				out.WriteByte('>')
				i += 6
				continue
			case `\u0026`:
				out.WriteByte('&')
				i += 6
				continue
			}
		}
		out.WriteByte(s[i])
		i++
	}
	return []byte(out.String())
}

func oddBackslashesBefore(s string, i int) bool {
	n := 0
	for i > 0 && s[i-1] == '\\' {
		n++
		i--
	}
	return n%2 == 1
}

// jobSignPayload builds a length-prefixed, unambiguous message for Ed25519.
// Field order: domain, id, agent_id, verb, sha256hex(canonical args), expires_unix_micro.
// Args are hashed and expiry is unix-micro so JSON time/string transport cannot break verify.
func jobSignPayload(j *Job) ([]byte, error) {
	args, err := canonicalJSONArgs(j.Args)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(args)
	argsDigest := hex.EncodeToString(sum[:])
	exp := strconv.FormatInt(j.ExpiresAt.UTC().UnixMicro(), 10)
	var buf bytes.Buffer
	writeLP := func(s string) error {
		n := uint64(len(s))
		if n > math.MaxUint32 {
			return fmt.Errorf("sign field too large")
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(n)) // #nosec G115 -- bounded by MaxUint32 check
		buf.Write(lenBuf[:])
		buf.WriteString(s)
		return nil
	}
	for _, s := range []string{"kunari.job/3", j.ID, j.AgentID, j.Verb, argsDigest, exp} {
		if err := writeLP(s); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func signJob(keys *kcrypto.KeyPair, j *Job) (string, error) {
	if keys == nil {
		return "", fmt.Errorf("hub signing key required")
	}
	payload, err := jobSignPayload(j)
	if err != nil {
		return "", err
	}
	sig := keys.Sign(payload)
	return "ed25519=" + hex.EncodeToString(sig), nil
}

// VerifyJobSig checks the job Ed25519 signature with the hub public key.
func VerifyJobSig(pub ed25519.PublicKey, j *Job) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid hub public key")
	}
	payload, err := jobSignPayload(j)
	if err != nil {
		return err
	}
	got := strings.TrimSpace(j.Sig)
	got = strings.TrimPrefix(got, "ed25519=")
	sig, err := hex.DecodeString(got)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	if !kcrypto.Verify(pub, payload, sig) {
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
