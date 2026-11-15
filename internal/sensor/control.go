package sensor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
	"github.com/jimididit/kunari/internal/safepath"
	"github.com/jimididit/kunari/internal/sink"
)

const (
	verbReloadConfig = "reload_config"
	verbSetTargets   = "set_targets"
	verbStatusDump   = "status_dump"
	verbAckMissing   = "ack_missing"
	verbRotateHubURL = "rotate_hub_url_hint"
)

// controlJob is the hub-signed job envelope (fields mirror hub.Job).
type controlJob struct {
	ID        string          `json:"id"`
	AgentID   string          `json:"agent_id"`
	Verb      string          `json:"verb"`
	Args      json.RawMessage `json:"args"`
	ExpiresAt time.Time       `json:"expires_at"`
	Sig       string          `json:"sig"`
}

type setTargetsArgs struct {
	Targets []Target `json:"targets"`
}

type rotateHubURLArgs struct {
	HubURL string `json:"hub_url"`
}

func (r *Runner) jobPollInterval() time.Duration {
	d := r.Cfg.HeartbeatDuration() / 2
	if d < 15*time.Second {
		d = 15 * time.Second
	}
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	return d
}

func (r *Runner) pollJobs(ctx context.Context) {
	if r.hubSecret == nil || r.Cfg.HubURL == "" || len(r.hubPubKey) == 0 {
		return
	}
	jobs, err := r.pullJobs(ctx)
	if err != nil {
		r.Log.Debug("job pull", "err", err)
		return
	}
	for _, j := range jobs {
		if err := r.verifyJob(&j); err != nil {
			r.Log.Info("job reject", "job_id", j.ID, "err", err)
			_ = r.reportJob(ctx, j.ID, "", err.Error())
			continue
		}
		result, err := r.executeJob(ctx, &j)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
			r.Log.Info("job failed", "job_id", j.ID, "verb", j.Verb, "err", err)
		} else {
			r.Log.Info("job done", "job_id", j.ID, "verb", j.Verb)
		}
		if reportErr := r.reportJob(ctx, j.ID, result, errMsg); reportErr != nil {
			r.Log.Debug("job result report", "err", reportErr)
		}
	}
}

func (r *Runner) pullJobs(ctx context.Context) ([]controlJob, error) {
	body, err := json.Marshal(map[string]any{"agent_id": r.agentID, "limit": 5})
	if err != nil {
		return nil, err
	}
	respBody, err := r.hubHMACPost(ctx, "/api/v1/jobs/pull", body)
	if err != nil {
		return nil, err
	}
	var out struct {
		Jobs []controlJob `json:"jobs"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return out.Jobs, nil
}

func (r *Runner) reportJob(ctx context.Context, jobID, result, errMsg string) error {
	body, err := json.Marshal(map[string]any{
		"agent_id": r.agentID,
		"job_id":   jobID,
		"result":   result,
		"error":    errMsg,
	})
	if err != nil {
		return err
	}
	_, err = r.hubHMACPost(ctx, "/api/v1/jobs/result", body)
	return err
}

func (r *Runner) hubHMACPost(ctx context.Context, path string, body []byte) ([]byte, error) {
	base := strings.TrimRight(r.Cfg.HubURL, "/")
	url := base + path
	ts := fmt.Sprintf("%d", time.Now().Unix())
	sig := "sha256=" + sink.SignBody(r.hubSecret, ts, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(sink.HeaderTimestamp, ts)
	req.Header.Set(sink.HeaderSignature, sig)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req) // #nosec G107 -- hub_url from operator config
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hub %s: %s", resp.Status, truncateStr(string(respBody), 200))
	}
	return respBody, nil
}

func (r *Runner) verifyJob(j *controlJob) error {
	if j.AgentID != r.agentID {
		return fmt.Errorf("agent_id mismatch")
	}
	if time.Now().UTC().After(j.ExpiresAt) {
		return fmt.Errorf("expired")
	}
	switch j.Verb {
	case verbReloadConfig, verbSetTargets, verbStatusDump, verbAckMissing, verbRotateHubURL:
	default:
		return fmt.Errorf("verb not allowlisted")
	}
	if len(r.hubPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("hub pubkey not configured")
	}
	args := j.Args
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	compacted, err := canonicalJobArgs(args)
	if err != nil {
		return err
	}
	payload, err := jobSignPayload(j.ID, j.AgentID, j.Verb, string(compacted), j.ExpiresAt)
	if err != nil {
		return err
	}
	gotHex := strings.TrimPrefix(strings.TrimSpace(j.Sig), "ed25519=")
	sig, err := hex.DecodeString(gotHex)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	if !kcrypto.Verify(r.hubPubKey, payload, sig) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func canonicalJobArgs(args json.RawMessage) (json.RawMessage, error) {
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
	return json.RawMessage(unescapeJobJSONHTML(buf.Bytes())), nil
}

func unescapeJobJSONHTML(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\u00`)) {
		return b
	}
	s := string(b)
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); {
		if i+6 <= len(s) && s[i] == '\\' && s[i+1] == 'u' {
			n := 0
			for j := i; j > 0 && s[j-1] == '\\'; {
				n++
				j--
			}
			if n%2 == 0 {
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
		}
		out.WriteByte(s[i])
		i++
	}
	return []byte(out.String())
}

func jobSignPayload(id, agentID, verb, args string, exp time.Time) ([]byte, error) {
	var buf bytes.Buffer
	writeLP := func(s string) error {
		n := len(s)
		if n > math.MaxUint32 {
			return fmt.Errorf("sign field too large")
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(n)) // #nosec G115 -- bounded by MaxUint32 check
		buf.Write(lenBuf[:])
		buf.WriteString(s)
		return nil
	}
	for _, s := range []string{"kunari.job/1", id, agentID, verb, args, exp.UTC().Format(time.RFC3339Nano)} {
		if err := writeLP(s); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (r *Runner) executeJob(ctx context.Context, j *controlJob) (string, error) {
	switch j.Verb {
	case verbStatusDump:
		return r.statusDumpJSON(), nil
	case verbAckMissing:
		return `{"acked":true}`, nil
	case verbReloadConfig:
		return r.reloadFromDisk(ctx)
	case verbSetTargets:
		var args setTargetsArgs
		if err := json.Unmarshal(nonzeroArgs(j.Args), &args); err != nil {
			return "", fmt.Errorf("args: %w", err)
		}
		return r.applyTargets(ctx, args.Targets)
	case verbRotateHubURL:
		var args rotateHubURLArgs
		if err := json.Unmarshal(nonzeroArgs(j.Args), &args); err != nil {
			return "", fmt.Errorf("args: %w", err)
		}
		return r.rotateHubURL(args.HubURL)
	default:
		return "", fmt.Errorf("verb not allowlisted")
	}
}

func nonzeroArgs(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return raw
}

func (r *Runner) statusDumpJSON() string {
	r.watchMu.Lock()
	defer r.watchMu.Unlock()
	type dump struct {
		AgentID      string   `json:"agent_id"`
		Tier         string   `json:"tier"`
		Capabilities string   `json:"capabilities"`
		ConfigHash   string   `json:"config_hash"`
		WatcherHash  string   `json:"watcher_hash"`
		WatchCount   int      `json:"watch_count"`
		HubURL       string   `json:"hub_url,omitempty"`
		Targets      []string `json:"targets"`
	}
	paths := make([]string, 0, len(r.Cfg.Targets))
	for _, t := range r.Cfg.Targets {
		paths = append(paths, t.Path)
	}
	d := dump{
		AgentID:      r.agentID,
		Tier:         string(r.Watcher.Tier()),
		Capabilities: r.Watcher.Capabilities(),
		ConfigHash:   r.Cfg.Hash(),
		WatcherHash:  r.Watcher.ConfigHash(),
		WatchCount:   len(r.Cfg.Targets),
		HubURL:       r.Cfg.HubURL,
		Targets:      paths,
	}
	b, _ := json.Marshal(d)
	return string(b)
}

func (r *Runner) reloadFromDisk(ctx context.Context) (string, error) {
	if r.ConfigPath == "" {
		return "", fmt.Errorf("config path unknown")
	}
	cfg, err := LoadConfig(r.ConfigPath)
	if err != nil {
		return "", err
	}
	// Preserve runtime data_dir / keys if file omitted them (LoadConfig already has them).
	if err := r.applyConfig(ctx, cfg); err != nil {
		return "", err
	}
	return r.statusDumpJSON(), nil
}

func (r *Runner) applyTargets(ctx context.Context, targets []Target) (string, error) {
	if len(targets) == 0 {
		return "", fmt.Errorf("targets required")
	}
	for i := range targets {
		p, err := safepath.Clean(targets[i].Path)
		if err != nil {
			return "", fmt.Errorf("target %d: %w", i, err)
		}
		targets[i].Path = p
		if targets[i].TokenID == "" {
			return "", fmt.Errorf("target %d: token_id required", i)
		}
	}
	cfgCopy := *r.Cfg
	cfgCopy.Targets = targets
	if r.ConfigPath != "" {
		if err := SaveConfig(r.ConfigPath, &cfgCopy); err != nil {
			return "", err
		}
	}
	if err := r.applyConfig(ctx, &cfgCopy); err != nil {
		return "", err
	}
	return r.statusDumpJSON(), nil
}

func (r *Runner) rotateHubURL(hubURL string) (string, error) {
	hubURL = strings.TrimSpace(hubURL)
	if hubURL == "" {
		return "", fmt.Errorf("hub_url required")
	}
	if !strings.HasPrefix(hubURL, "https://") && !strings.HasPrefix(hubURL, "http://") {
		return "", fmt.Errorf("hub_url must be http(s)")
	}
	r.Cfg.HubURL = strings.TrimRight(hubURL, "/")
	if r.ConfigPath != "" {
		if err := SaveConfig(r.ConfigPath, r.Cfg); err != nil {
			return "", err
		}
	}
	// Rebuild hub push sink with new URL.
	if r.hubSecret != nil {
		hubSink, err := sink.NewHubPushSink(r.Cfg.HubURL+"/api/v1/ingest", r.hubSecret)
		if err != nil {
			return "", err
		}
		r.hubPush = hubSink
	}
	b, _ := json.Marshal(map[string]string{"hub_url": r.Cfg.HubURL})
	return string(b), nil
}

func (r *Runner) applyConfig(ctx context.Context, cfg *Config) error {
	select {
	case r.reloadReq <- cfg:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-r.reloadAck:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(30 * time.Second):
		return fmt.Errorf("reload timed out")
	}
}

func truncateStr(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}
