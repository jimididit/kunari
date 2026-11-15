package hub

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ipRateLimiter is a per-key token bucket with a coarser global backstop.
// ratePerMin <= 0 disables limiting.
type ipRateLimiter struct {
	mu              sync.Mutex
	ratePerSec      float64
	burst           float64
	buckets         map[string]*tokenBucket
	global          *tokenBucket
	globalRatePerSec float64
	globalBurst     float64
	now             func() time.Time
	maxKeys         int
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
	// Global cap ~10 saturated client IPs - bounds IP-rotation amplification.
	globalBurst := burst * 10
	return &ipRateLimiter{
		ratePerSec:       float64(ratePerMin) / 60.0,
		burst:            burst,
		buckets:          make(map[string]*tokenBucket),
		global:           &tokenBucket{tokens: globalBurst},
		globalRatePerSec: float64(ratePerMin) * 10 / 60.0,
		globalBurst:      globalBurst,
		now:              time.Now,
		maxKeys:          10000,
	}
}

// allow reports whether key may proceed. retryAfter is set when denied.
func (l *ipRateLimiter) allow(key string) (ok bool, retryAfter time.Duration) {
	if l == nil {
		return true, 0
	}
	if key == "" {
		key = "unknown"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	refill(l.global, l.globalRatePerSec, l.globalBurst, now)
	if l.global.tokens < 1 {
		return false, retryFor(1-l.global.tokens, l.globalRatePerSec)
	}

	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.maxKeys {
			l.evictOneLocked()
		}
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	refill(b, l.ratePerSec, l.burst, now)
	if b.tokens < 1 {
		return false, retryFor(1-b.tokens, l.ratePerSec)
	}
	b.tokens--
	l.global.tokens--
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

// evictOneLocked drops one map entry (O(1); Go map walk order is randomized).
func (l *ipRateLimiter) evictOneLocked() {
	for k := range l.buckets {
		delete(l.buckets, k)
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

// limitPublic rate-limits before the handler. Prefer auth-then-limit for HMAC routes.
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

// allowIngestRate is used after HMAC verification so unauthenticated floods
// cannot burn the shared agent/job bucket.
func (h *Hub) allowIngestRate(r *http.Request) (bool, time.Duration) {
	if h.ingestLimit == nil {
		return true, 0
	}
	return h.ingestLimit.allow(h.clientIP(r))
}
