package hub

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jimididit/kunari/internal/collect"
	kcrypto "github.com/jimididit/kunari/internal/crypto"
	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/registry"
	"github.com/jimididit/kunari/internal/sink"
)

type Config struct {
	HTTPListen       string
	DNSListen        string
	DNSZone          string
	DataDir          string
	RegistryDB       string
	KeyPath          string
	IngestSecretPath string // default: <data>/ingest.secret
	APITokenPath     string // default: <data>/api.token (Bearer for pull/SSE)
	// TrustedProxies are CIDRs (or bare IPs) allowed to set ClientIPHeader.
	// Empty (default): always use RemoteAddr; never trust X-Forwarded-For.
	TrustedProxies []string
	ClientIPHeader string // default X-Forwarded-For when TrustedProxies is set
	// AgentStaleAfter is how long after the last sentinel heartbeat before the
	// hub emits an agent_missing alert. Zero disables missing-agent watch.
	// Default (when unset via CLI): 3m.
	AgentStaleAfter time.Duration
	Collect         collect.Level
	Logger          *slog.Logger
}

type Hub struct {
	cfg            Config
	log            *slog.Logger
	keys           *kcrypto.KeyPair
	reg            *registry.Store
	chain          *event.Chain
	queue          *sink.Queue
	throttle       *sink.Throttle
	ingestSecret   []byte
	apiToken       []byte
	seen           *seenIDs
	subs           *apiSubs
	agents         *agentTracker
	trustedProxies []*net.IPNet
	mu             sync.Mutex
	hits           int
}

func New(cfg Config) (*Hub, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	keys, err := kcrypto.LoadOrCreate(cfg.KeyPath)
	if err != nil {
		return nil, err
	}
	regPath := cfg.RegistryDB
	if regPath == "" {
		regPath = filepath.Join(cfg.DataDir, "registry.db")
	}
	reg, err := registry.Open(regPath)
	if err != nil {
		return nil, err
	}
	chain, err := event.Open(filepath.Join(cfg.DataDir, "events.jsonl"), keys)
	if err != nil {
		_ = reg.Close()
		return nil, err
	}
	fileSink, err := sink.NewFileSink(filepath.Join(cfg.DataDir, "alerts.jsonl"))
	if err != nil {
		_ = reg.Close()
		return nil, err
	}
	q, err := sink.NewQueue(filepath.Join(cfg.DataDir, "queue"), cfg.Logger, fileSink, sink.NewStdoutSink())
	if err != nil {
		_ = reg.Close()
		return nil, err
	}
	if cfg.Collect == "" {
		cfg.Collect = collect.Standard
	}
	secretPath := cfg.IngestSecretPath
	if secretPath == "" {
		secretPath = filepath.Join(cfg.DataDir, "ingest.secret")
	}
	ingestSecret, err := loadOrCreateIngestSecret(secretPath)
	if err != nil {
		_ = reg.Close()
		return nil, err
	}
	cfg.Logger.Info("hub ingest enabled", "secret_path", secretPath)
	apiPath := cfg.APITokenPath
	if apiPath == "" {
		apiPath = filepath.Join(cfg.DataDir, "api.token")
	}
	apiToken, err := loadOrCreateAPIToken(apiPath)
	if err != nil {
		_ = reg.Close()
		return nil, err
	}
	cfg.Logger.Info("hub API token enabled", "token_path", apiPath)
	trusted, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		_ = reg.Close()
		return nil, err
	}
	if len(trusted) > 0 {
		hdr := cfg.ClientIPHeader
		if hdr == "" {
			hdr = "X-Forwarded-For"
		}
		cfg.Logger.Info("hub trusted-proxy client IP enabled", "proxies", len(trusted), "header", hdr)
	}
	agents, err := newAgentTracker(cfg.DataDir, cfg.AgentStaleAfter)
	if err != nil {
		_ = reg.Close()
		return nil, err
	}
	if agents.enabled() {
		cfg.Logger.Info("hub agent watch enabled", "stale_after", cfg.AgentStaleAfter.String())
	}
	return &Hub{
		cfg:            cfg,
		log:            cfg.Logger,
		keys:           keys,
		reg:            reg,
		chain:          chain,
		queue:          q,
		throttle:       sink.NewThrottle(time.Minute),
		ingestSecret:   ingestSecret,
		apiToken:       apiToken,
		seen:           newSeenIDs(8192),
		subs:           newAPISubs(),
		agents:         agents,
		trustedProxies: trusted,
	}, nil
}

func (h *Hub) Close() error {
	h.queue.Close()
	return h.reg.Close()
}

func (h *Hub) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.queue.Run(ctx)
	}()
	if h.agents != nil && h.agents.enabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.watchAgents(ctx)
		}()
	}

	httpSrv := &http.Server{
		Addr:              h.cfg.HTTPListen,
		Handler:           h.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		h.log.Info("hub https/http listening", "addr", h.cfg.HTTPListen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	if h.cfg.DNSListen != "" && h.cfg.DNSZone != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.log.Info("hub dns listening", "addr", h.cfg.DNSListen, "zone", h.cfg.DNSZone)
			if err := h.serveDNS(ctx); err != nil && ctx.Err() == nil {
				errCh <- err
			}
		}()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = httpSrv.Shutdown(shutdownCtx)
		wg.Wait()
		return nil
	case err := <-errCh:
		cancel()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		_ = httpSrv.Shutdown(shutdownCtx)
		stop()
		wg.Wait()
		return err
	}
}

func (h *Hub) recordBeacon(tokenID, tier string, netInfo *event.Network) error {
	// Unknown tokens still record (possible probe) but mark memo.
	active, err := h.reg.ExistsActive(tokenID)
	if err != nil {
		return err
	}
	memo := ""
	if m, err := h.reg.Get(tokenID); err == nil {
		memo = m.Memo
		if m.Revoked {
			memo = memo + " [REVOKED]"
		}
	} else if !active {
		memo = "unknown or unregistered token"
	}

	ev := event.New(tokenID, "beacon", tier, "beacon_fetch")
	ev.Memo = memo
	ev.Network = netInfo
	if !h.cfg.Collect.AllowsForensicNetwork() && ev.Network != nil {
		ev.Network.Headers = nil
		ev.Network.TLSFP = ""
	}

	allow, suppressed := h.throttle.Allow(ev)
	if !allow {
		h.log.Info("alert suppressed (still recorded)", "token_id", tokenID, "suppressed", suppressed)
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
	h.mu.Unlock()
	return nil
}

func (h *Hub) Hits() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits
}
