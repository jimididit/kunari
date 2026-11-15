package hub

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ipRateLimiter is a per-key token bucket. ratePerMin <= 0 disables limiting.
type ipRateLimiter struct {
	mu         sync.Mutex
	ratePerSec float64
	burst      float64
	buckets    map[string]*tokenBucket
	// overflow: rarer secondary budget so over-limit beacon hits can still
	// record a few detections without unbounded storage writes.
	overflowRatePerSec float64
	overflowBurst      float64
	overflow           map[string]*tokenBucket
	now                func() time.Time
	maxKeys            int
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newIPRateLimiter(ratePerMin int) *ipRateLimiter {
	if ratePerMin <= 0 {
		return nil
	}
	burst := float64(ratePerMin)
	if burst < 1 {
		burst = 1
	}
	overflowPerMin := ratePerMin / 12
	if overflowPerMin < 5 {
		overflowPerMin = 5
	}
	return &ipRateLimiter{
		ratePerSec:         float64(ratePerMin) / 60.0,
		burst:              burst,
		buckets:            make(map[string]*tokenBucket),
		overflowRatePerSec: float64(overflowPerMin) / 60.0,
		overflowBurst:      float64(overflowPerMin),
		overflow:           make(map[string]*tokenBucket),
		now:                time.Now,
		maxKeys:            10000,
	}
}

// allow reports whether key may proceed under the primary budget.
func (l *ipRateLimiter) allow(key string) (ok bool, retryAfter time.Duration) {
	if l == nil {
		return true, 0
	}
	return l.take(key, false)
}

// allowOverflow spends the secondary budget (beacon over-limit recording).
func (l *ipRateLimiter) allowOverflow(key string) bool {
	if l == nil {
		return true
	}
	ok, _ := l.take(key, true)
	return ok
}

func (l *ipRateLimiter) take(key string, overflow bool) (ok bool, retryAfter time.Duration) {
	if key == "" {
		key = "unknown"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	rate := l.ratePerSec
	burst := l.burst
	store := l.buckets
	if overflow {
		rate = l.overflowRatePerSec
		burst = l.overflowBurst
		store = l.overflow
	}
	b := store[key]
	if b == nil {
		if len(store) >= l.maxKeys {
			evictOne(store)
		}
		b = &tokenBucket{tokens: burst, last: now}
		store[key] = b
	}
	refill(b, rate, burst, now)
	if b.tokens < 1 {
		return false, retryFor(1-b.tokens, rate)
	}
	b.tokens--
	return true, 0
}

func refill(b *tokenBucket, ratePerSec, burst float64, now time.Time) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * ratePerSec
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	} else if b.last.IsZero() {
		b.last = now
	}
}

func retryFor(need, ratePerSec float64) time.Duration {
	if ratePerSec <= 0 {
		return time.Second
	}
	sec := need / ratePerSec
	if sec < 1 {
		sec = 1
	}
	return time.Duration(sec * float64(time.Second))
}

func evictOne(store map[string]*tokenBucket) {
	for k := range store {
		delete(store, k)
		return
	}
}

func writeTooManyRequests(w http.ResponseWriter, retry time.Duration) {
	if retry < time.Second {
		retry = time.Second
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
	http.Error(w, "too many requests", http.StatusTooManyRequests)
}

// limitPublic rate-limits before the handler by client IP.
func (h *Hub) limitPublic(lim *ipRateLimiter, next http.HandlerFunc) http.HandlerFunc {
	if lim == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ok, retry := lim.allow(h.clientIP(r))
		if !ok {
			writeTooManyRequests(w, retry)
			return
		}
		next(w, r)
	}
}

// allowIngestRateKey limits authenticated ingest/jobs by agent id (falls back to IP).
// Avoids one NAT IP throttling every agent behind it.
func (h *Hub) allowIngestRateKey(r *http.Request, agentID string) (bool, time.Duration) {
	if h.ingestLimit == nil {
		return true, 0
	}
	key := strings.TrimSpace(agentID)
	if key == "" {
		key = h.clientIP(r)
	}
	return h.ingestLimit.allow(key)
}
