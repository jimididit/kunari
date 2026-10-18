package hub

import (
	"context"
	"log/slog"
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
	HTTPListen string
	DNSListen  string
	DNSZone    string
	DataDir    string
	RegistryDB string
	KeyPath    string
	Collect    collect.Level
	Logger     *slog.Logger
}

type Hub struct {
	cfg      Config
	log      *slog.Logger
	keys     *kcrypto.KeyPair
	reg      *registry.Store
	chain    *event.Chain
	queue    *sink.Queue
	throttle *sink.Throttle
	mu       sync.Mutex
	hits     int
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
	fileSink := sink.NewFileSink(filepath.Join(cfg.DataDir, "alerts.jsonl"))
	q, err := sink.NewQueue(filepath.Join(cfg.DataDir, "queue"), cfg.Logger, fileSink, sink.NewStdoutSink())
	if err != nil {
		_ = reg.Close()
		return nil, err
	}
	if cfg.Collect == "" {
		cfg.Collect = collect.Standard
	}
	return &Hub{
		cfg:      cfg,
		log:      cfg.Logger,
		keys:     keys,
		reg:      reg,
		chain:    chain,
		queue:    q,
		throttle: sink.NewThrottle(time.Minute),
	}, nil
}

func (h *Hub) Close() error {
	h.queue.Close()
	return h.reg.Close()
}

func (h *Hub) Run(ctx context.Context) error {
	go h.queue.Run(ctx)

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
		go func() {
			h.log.Info("hub dns listening", "addr", h.cfg.DNSListen, "zone", h.cfg.DNSZone)
			if err := h.serveDNS(ctx); err != nil && ctx.Err() == nil {
				errCh <- err
			}
		}()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
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
