package hub

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ipRateLimiter is a per-key token bucket. ratePerMin <= 0 disables limiting.
// At capacity, idle buckets (fully refilled and quiet) are evicted; if none are
// idle, new keys are denied (fail closed) so active throttle state is not reset.
type ipRateLimiter struct {
	mu         sync.Mutex
	ratePerSec float64
	burst      float64
	buckets    map[string]*tokenBucket
	now        func() time.Time
	maxKeys    int
	idleAfter  time.Duration
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
	return &ipRateLimiter{
		ratePerSec: float64(ratePerMin) / 60.0,
		burst:      burst,
		buckets:    make(map[string]*tokenBucket),
		now:        time.Now,
		maxKeys:    10000,
		idleAfter:  2 * time.Minute,
	}
}

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
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.maxKeys {
			if !l.evictIdleLocked(now) {
				return false, time.Second
			}
		}
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.ratePerSec
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		need := 1 - b.tokens
		sec := need / l.ratePerSec
		if sec < 1 {
			sec = 1
		}
		return false, time.Duration(sec * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// evictIdleLocked removes one fully-refilled bucket that has been quiet.
// Returns false if no idle victim exists.
func (l *ipRateLimiter) evictIdleLocked(now time.Time) bool {
	var victim string
	var victimLast time.Time
	found := false
	for k, b := range l.buckets {
		refillUnlocked(b, l.ratePerSec, l.burst, now)
		if b.tokens < l.burst {
			continue // still throttled / recently active
		}
		if now.Sub(b.last) < l.idleAfter {
			continue
		}
		if !found || b.last.Before(victimLast) {
			victim = k
			victimLast = b.last
			found = true
		}
	}
	if !found {
		return false
	}
	delete(l.buckets, victim)
	return true
}

func refillUnlocked(b *tokenBucket, ratePerSec, burst float64, now time.Time) {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed <= 0 {
		return
	}
	b.tokens += elapsed * ratePerSec
	if b.tokens > burst {
		b.tokens = burst
	}
	// Do not advance last here - idle detection uses last activity time.
}

func writeTooManyRequests(w http.ResponseWriter, retry time.Duration) {
	if retry < time.Second {
		retry = time.Second
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
	http.Error(w, "too many requests", http.StatusTooManyRequests)
}

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

func (h *Hub) allowIngestRate(r *http.Request) (bool, time.Duration) {
	if h.ingestLimit == nil {
		return true, 0
	}
	return h.ingestLimit.allow("ingest:" + h.clientIP(r))
}

func (h *Hub) allowJobsRate(r *http.Request) (bool, time.Duration) {
	if h.ingestLimit == nil {
		return true, 0
	}
	return h.ingestLimit.allow("jobs:" + h.clientIP(r))
}

func (h *Hub) rateLimitTrustedProxyHint() {
	if h == nil || h.log == nil {
		return
	}
	if (h.beaconLimit == nil && h.ingestLimit == nil) || len(h.trustedProxies) > 0 {
		return
	}
	h.log.Info("hub rate limits active without --trusted-proxy; all clients behind a TLS terminator share one IP bucket until trusted-proxy is set")
}
