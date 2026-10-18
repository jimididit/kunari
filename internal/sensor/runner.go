package sensor

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/safepath"
	"github.com/jimididit/kunari/internal/sink"
)

// Runner wires a Watcher to the evidence chain, sinks, allowlist, and heartbeat.
type Runner struct {
	Cfg     *Config
	Log     *slog.Logger
	Watcher Watcher
	keys    *kcrypto.KeyPair
	chain   *event.Chain
	queue   *sink.Queue
	byPath   map[string]Target
	copyCorr *copyCorrelator
}

func NewRunner(cfg *Config, log *slog.Logger) (*Runner, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	keyPath := cfg.KeyPath
	if keyPath == "" {
		keyPath = filepath.Join(cfg.DataDir, "signing.key")
	}
	keys, err := kcrypto.LoadOrCreate(keyPath)
	if err != nil {
		return nil, err
	}
	chain, err := event.Open(filepath.Join(cfg.DataDir, "events.jsonl"), keys)
	if err != nil {
		return nil, err
	}
	fileSink, err := sink.NewFileSink(filepath.Join(cfg.DataDir, "alerts.jsonl"))
	if err != nil {
		return nil, err
	}
	sinks := []sink.Sink{fileSink, sink.NewStdoutSink()}
	if cfg.HubURL != "" || cfg.HubSecretFile != "" {
		hubSink, err := newHubPushSink(cfg)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, hubSink)
		log.Info("sentinel hub push enabled", "url", strings.TrimRight(cfg.HubURL, "/")+"/api/v1/ingest")
	}
	q, err := sink.NewQueue(filepath.Join(cfg.DataDir, "queue"), log, sinks...)
	if err != nil {
		return nil, err
	}
	w, err := OpenBest(cfg.Targets)
	if err != nil {
		return nil, err
	}
	byPath := map[string]Target{}
	for _, t := range cfg.Targets {
		byPath[filepath.Clean(t.Path)] = t
	}
	return &Runner{
		Cfg: cfg, Log: log, Watcher: w, keys: keys, chain: chain, queue: q, byPath: byPath,
		copyCorr: newCopyCorrelator(defaultCopyWindow),
	}, nil
}

func (r *Runner) Close() error {
	_ = r.Watcher.Close()
	r.queue.Close()
	return nil
}

func (r *Runner) Run(ctx context.Context) error {
	r.Log.Info("sentinel armed",
		"tier", r.Watcher.Tier(),
		"capabilities", r.Watcher.Capabilities(),
		"config_hash", r.Cfg.Hash(),
		"watcher_hash", r.Watcher.ConfigHash(),
		"targets", len(r.Cfg.Targets),
	)

	go r.queue.Run(ctx)

	touches := make(chan Touch, 64)
	errCh := make(chan error, 1)
	go func() {
		errCh <- r.Watcher.Run(ctx, touches)
	}()

	hb := time.NewTicker(r.Cfg.HeartbeatDuration())
	defer hb.Stop()

	// Initial heartbeat
	r.emitHeartbeat(ctx, false)

	lastWatcherHash := r.Watcher.ConfigHash()
	lastCfgHash := r.Cfg.Hash()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			if err != nil && ctx.Err() == nil {
				return err
			}
			return nil
		case <-hb.C:
			drift := r.Watcher.ConfigHash() != lastWatcherHash || r.Cfg.Hash() != lastCfgHash
			if drift {
				r.Log.Error("config drift detected",
					"watcher_hash", r.Watcher.ConfigHash(),
					"cfg_hash", r.Cfg.Hash(),
				)
			}
			r.emitHeartbeat(ctx, drift)
			lastWatcherHash = r.Watcher.ConfigHash()
			lastCfgHash = r.Cfg.Hash()
		case t := <-touches:
			r.handleTouch(ctx, t)
		}
	}
}

func (r *Runner) handleTouch(ctx context.Context, t Touch) {
	tokenID := ""
	memo := ""
	if tgt, ok := r.byPath[filepath.Clean(t.Path)]; ok {
		tokenID = tgt.TokenID
		memo = tgt.Memo
	}
	if tokenID == "" {
		// Path may be reported differently; try basename match.
		for p, tgt := range r.byPath {
			if filepath.Base(p) == filepath.Base(t.Path) {
				tokenID = tgt.TokenID
				memo = tgt.Memo
				break
			}
		}
	}
	if tokenID == "" {
		tokenID = "unmapped"
	}

	exe := ""
	cmdline := ""
	quality := "none"
	if t.PID > 0 {
		exe, cmdline, quality = resolveExe(t.PID)
	}
	if exe == "" && t.Extra != nil {
		exe = t.Extra["process_name"]
		if exe != "" {
			quality = "partial"
		}
	}

	matched, reason := MatchAllowlist(exe, r.Cfg.Allowlist)
	ev := event.New(tokenID, "sentinel", string(r.Watcher.Tier()), t.Action)
	ev.Memo = memo
	ev.ObservedAt = t.Occurred
	if !t.Proven {
		ev.Confidence.Action = "inferred"
	}
	if r.copyCorr != nil && r.copyCorr.Suspect(t, exe) {
		ev.Confidence.CopySuspected = true
	}
	ev.File = &event.FileInfo{Path: t.Path}
	hn, _ := os.Hostname()
	ev.Host = &event.HostInfo{
		Hostname:     hn,
		OS:           runtime.GOOS,
		AgentVersion: r.Cfg.AgentVersion,
	}
	ev.Actor = &event.Actor{
		PID:                t.PID,
		Exe:                exe,
		Cmdline:            cmdline,
		AttributionQuality: quality,
	}
	ev.Context = &event.Context{AllowlistMatched: matched}
	if matched {
		r.Log.Info("touch allowlisted (still recorded)", "exe", exe, "reason", reason, "path", t.Path)
		if ev.Memo != "" {
			ev.Memo += " | "
		}
		ev.Memo += "allowlist:" + reason
	}

	if err := r.chain.Append(ev); err != nil {
		r.Log.Error("chain append", "err", err)
		return
	}
	if matched {
		return // recorded, not alerted
	}
	if err := r.queue.Enqueue(ev); err != nil {
		r.Log.Error("enqueue", "err", err)
	}
}

func (r *Runner) emitHeartbeat(ctx context.Context, drift bool) {
	action := "attrib"
	if drift {
		action = "perm_change"
	}
	ev := event.New("heartbeat", "sentinel", string(r.Watcher.Tier()), action)
	ev.Memo = "heartbeat"
	if drift {
		ev.Memo = "config_drift"
	}
	hn, _ := os.Hostname()
	ev.Host = &event.HostInfo{
		Hostname:     hn,
		OS:           runtime.GOOS,
		AgentVersion: r.Cfg.AgentVersion,
	}
	ev.File = &event.FileInfo{Path: "watcher:" + r.Watcher.ConfigHash()}
	ev.Confidence.Action = "proven"
	if err := r.chain.Append(ev); err != nil {
		r.Log.Error("heartbeat chain", "err", err)
		return
	}
	if drift {
		_ = r.queue.Enqueue(ev)
	}
	_ = ctx
}

func newHubPushSink(cfg *Config) (*sink.WebhookSink, error) {
	if cfg.HubURL == "" {
		return nil, fmt.Errorf("hub_secret_file set but hub_url is empty")
	}
	if cfg.HubSecretFile == "" {
		return nil, fmt.Errorf("hub_url set but hub_secret_file is empty")
	}
	path, err := safepath.Clean(cfg.HubSecretFile)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path cleaned by safepath.Clean
	if err != nil {
		return nil, fmt.Errorf("hub_secret_file: %w", err)
	}
	secret := trimSecret(raw)
	if decoded, err := hex.DecodeString(string(secret)); err == nil && len(decoded) >= 16 {
		secret = decoded
	}
	if len(secret) < 16 {
		return nil, fmt.Errorf("hub_secret_file must contain at least 16 bytes")
	}
	base := strings.TrimRight(cfg.HubURL, "/")
	return sink.NewHubPushSink(base+"/api/v1/ingest", secret)
}

func trimSecret(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\n' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}
