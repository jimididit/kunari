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
	"sync"
	"sync/atomic"
	"time"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/safepath"
	"github.com/jimididit/kunari/internal/sink"
)

// Runner wires a Watcher to the evidence chain, sinks, allowlist, and heartbeat.
type Runner struct {
	Cfg        *Config
	ConfigPath string // on-disk sentinel.json for reload_config / set_targets persistence
	Log        *slog.Logger
	Watcher    Watcher
	keys       *kcrypto.KeyPair
	chain      *event.Chain
	queue      *sink.Queue
	hubPush    sink.Sink // optional; heartbeats Deliver here without alert-queue spam
	hubSecret  []byte
	agentID    string
	byPath     map[string]Target
	copyCorr   *copyCorrelator
	watchMu    sync.Mutex
	reloadReq  chan *Config
	reloadAck  chan error
	reloading  atomic.Bool
}

func NewRunner(cfg *Config, log *slog.Logger) (*Runner, error) {
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	if err := hardenPrivateDir(cfg.DataDir); err != nil {
		return nil, fmt.Errorf("sentinel data_dir: %w", err)
	}
	agentID, err := loadOrCreateAgentID(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("agent id: %w", err)
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
	var hubPush sink.Sink
	var hubSecret []byte
	if cfg.HubURL != "" || cfg.HubSecretFile != "" {
		hubSink, secret, err := newHubPushSinkWithSecret(cfg)
		if err != nil {
			return nil, err
		}
		hubPush = hubSink
		hubSecret = secret
		sinks = append(sinks, hubSink)
		// Log host only - full ingest URL and paths help local enumerators.
		log.Info("sentinel hub push enabled", "hub", hubPushLogHost(cfg.HubURL))
	}
	q, err := sink.NewQueue(filepath.Join(cfg.DataDir, "queue"), log, sinks...)
	if err != nil {
		return nil, err
	}
	w, err := OpenBest(cfg.Targets, cfg.PreferTier)
	if err != nil {
		return nil, err
	}
	if restorer, ok := w.(interface{ RestoreSeen(string) error }); ok {
		if err := restorer.RestoreSeen(cfg.DataDir); err != nil {
			log.Debug("watcher seen-state restore", "err", err)
		}
	}
	byPath := map[string]Target{}
	for _, t := range cfg.Targets {
		byPath[filepath.Clean(t.Path)] = t
	}
	return &Runner{
		Cfg: cfg, Log: log, Watcher: w, keys: keys, chain: chain, queue: q,
		hubPush: hubPush, hubSecret: hubSecret, agentID: agentID, byPath: byPath,
		copyCorr:  newCopyCorrelator(defaultCopyWindow),
		reloadReq: make(chan *Config, 1),
		reloadAck: make(chan error, 1),
	}, nil
}

func (r *Runner) Close() error {
	_ = r.Watcher.Close()
	r.queue.Close()
	return nil
}

func (r *Runner) Run(ctx context.Context) error {
	// One-line info for operators/journals; hashes/caps at debug (hostile-local OPSEC).
	r.Log.Info("sentinel armed", "tier", r.Watcher.Tier(), "targets", len(r.Cfg.Targets))
	r.Log.Debug("sentinel armed detail",
		"capabilities", r.Watcher.Capabilities(),
		"config_hash", r.Cfg.Hash(),
		"watcher_hash", r.Watcher.ConfigHash(),
	)

	go r.queue.Run(ctx)

	touches := make(chan Touch, 64)
	watchCtx, watchCancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- r.Watcher.Run(watchCtx, touches)
	}()

	hb := time.NewTicker(r.Cfg.HeartbeatDuration())
	defer hb.Stop()

	// Initial heartbeat; job poll runs on its own goroutine so reload can use reloadReq.
	r.emitHeartbeat(ctx, false)
	go r.jobPollLoop(ctx)

	lastWatcherHash := r.Watcher.ConfigHash()
	lastCfgHash := r.Cfg.Hash()

	for {
		select {
		case <-ctx.Done():
			watchCancel()
			return nil
		case err := <-errCh:
			if ctx.Err() != nil {
				return nil
			}
			if r.reloading.Load() {
				continue
			}
			if err != nil {
				return err
			}
			return nil
		case cfg := <-r.reloadReq:
			err := r.swapWatcher(ctx, &watchCancel, errCh, touches, cfg)
			select {
			case r.reloadAck <- err:
			default:
			}
			if err == nil {
				lastWatcherHash = r.Watcher.ConfigHash()
				lastCfgHash = r.Cfg.Hash()
				r.emitHeartbeat(ctx, false)
			}
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

func (r *Runner) jobPollLoop(ctx context.Context) {
	if r.hubSecret == nil || r.Cfg.HubURL == "" {
		return
	}
	r.pollJobs(ctx)
	t := time.NewTicker(r.jobPollInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.pollJobs(ctx)
		}
	}
}

func (r *Runner) swapWatcher(ctx context.Context, watchCancel *context.CancelFunc, errCh chan error, touches chan Touch, cfg *Config) error {
	r.watchMu.Lock()
	defer r.watchMu.Unlock()
	r.reloading.Store(true)
	defer r.reloading.Store(false)
	(*watchCancel)()
	// Drain watcher exit
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		r.Log.Info("watcher stop slow during reload")
	}
	_ = r.Watcher.Close()
	w, err := OpenBest(cfg.Targets, cfg.PreferTier)
	if err != nil {
		// Best-effort restore previous watcher
		old, restoreErr := OpenBest(r.Cfg.Targets, r.Cfg.PreferTier)
		if restoreErr != nil {
			return fmt.Errorf("open new watcher: %v; restore: %w", err, restoreErr)
		}
		r.Watcher = old
		cctx, c := context.WithCancel(ctx)
		*watchCancel = c
		go func() { errCh <- r.Watcher.Run(cctx, touches) }()
		return err
	}
	if restorer, ok := w.(interface{ RestoreSeen(string) error }); ok {
		_ = restorer.RestoreSeen(cfg.DataDir)
	}
	byPath := map[string]Target{}
	for _, t := range cfg.Targets {
		byPath[filepath.Clean(t.Path)] = t
	}
	r.Cfg = cfg
	r.Watcher = w
	r.byPath = byPath
	cctx, c := context.WithCancel(ctx)
	*watchCancel = c
	go func() { errCh <- r.Watcher.Run(cctx, touches) }()
	r.Log.Info("sentinel reloaded", "tier", w.Tier(), "targets", len(cfg.Targets))
	return nil
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
	if t.Extra != nil && t.Extra["access_mask"] != "" {
		if ev.Memo != "" {
			ev.Memo += " "
		}
		ev.Memo += "mask=" + t.Extra["access_mask"]
	}
	ev.ObservedAt = t.Occurred
	if !t.Proven {
		ev.Confidence.Action = "inferred"
	}
	if r.copyCorr != nil && r.copyCorr.Suspect(t, exe) {
		ev.Confidence.CopySuspected = true
	}
	ev.File = &event.FileInfo{Path: t.Path}
	ev.Host = r.hostInfo()
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
	ev := event.New("heartbeat", "sentinel", string(r.Watcher.Tier()), "heartbeat")
	prefix := "heartbeat"
	if drift {
		prefix = "config_drift"
	}
	// caps= is last so capability text may contain semicolons without breaking watches=.
	ev.Memo = fmt.Sprintf("%s;every=%s;watches=%d;caps=%s",
		prefix, r.Cfg.HeartbeatEvery, len(r.Cfg.Targets), r.Watcher.Capabilities())
	ev.Host = r.hostInfo()
	ev.File = &event.FileInfo{Path: "watcher:" + r.Watcher.ConfigHash()}
	ev.Confidence.Action = "proven"
	if err := r.chain.Append(ev); err != nil {
		r.Log.Error("heartbeat chain", "err", err)
		return
	}
	// Heartbeats go straight to hub (control plane). On config drift, use the
	// alert queue once (includes hub) so the hub is not delivered twice.
	if drift {
		_ = r.queue.Enqueue(ev)
	} else if r.hubPush != nil {
		if err := r.hubPush.Deliver(ctx, ev); err != nil {
			r.Log.Debug("heartbeat hub push", "err", err)
		}
	}
}

func (r *Runner) hostInfo() *event.HostInfo {
	hn, _ := os.Hostname()
	return &event.HostInfo{
		ID:           r.agentID,
		Hostname:     hn,
		OS:           runtime.GOOS,
		OSVersion:    runtime.GOOS + "/" + runtime.GOARCH,
		AgentVersion: r.Cfg.AgentVersion,
		Engagement:   r.Cfg.Engagement,
		AgentLabel:   r.Cfg.AgentLabel,
	}
}

func newHubPushSink(cfg *Config) (*sink.WebhookSink, error) {
	s, _, err := newHubPushSinkWithSecret(cfg)
	return s, err
}

func newHubPushSinkWithSecret(cfg *Config) (*sink.WebhookSink, []byte, error) {
	if cfg.HubURL == "" {
		return nil, nil, fmt.Errorf("hub_secret_file set but hub_url is empty")
	}
	if cfg.HubSecretFile == "" {
		return nil, nil, fmt.Errorf("hub_url set but hub_secret_file is empty")
	}
	path, err := safepath.Clean(cfg.HubSecretFile)
	if err != nil {
		return nil, nil, err
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path cleaned by safepath.Clean
	if err != nil {
		return nil, nil, fmt.Errorf("hub_secret_file: %w", err)
	}
	secret := trimSecret(raw)
	if decoded, err := hex.DecodeString(string(secret)); err == nil && len(decoded) >= 16 {
		secret = decoded
	}
	if len(secret) < 16 {
		return nil, nil, fmt.Errorf("hub_secret_file must contain at least 16 bytes")
	}
	base := strings.TrimRight(cfg.HubURL, "/")
	sinkClient, err := sink.NewHubPushSink(base+"/api/v1/ingest", secret)
	if err != nil {
		return nil, nil, err
	}
	return sinkClient, append([]byte(nil), secret...), nil
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
