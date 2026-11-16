package hub

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ipRateLimiter is a per-key token bucket. ratePerMin <= 0 disables limiting.
// Idle buckets are reaped when the map grows past maxKeys; actively throttled
// buckets are never deleted (that would reset Deny into Allow). Soft memory
 // growth under a sustained many-IP flood is an accepted residual of opt-in limits.
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
			l.reapIdleLocked(now)
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
		return false, time.Duration(math.Ceil(sec) * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// reapIdleLocked deletes quiet, full buckets only (estimate; no token mutation).
func (l *ipRateLimiter) reapIdleLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) < l.idleAfter {
			continue
		}
		est := b.tokens + now.Sub(b.last).Seconds()*l.ratePerSec
		if est > l.burst {
			est = l.burst
		}
		if est < l.burst {
			continue
		}
		delete(l.buckets, k)
	}
}

func writeTooManyRequests(w http.ResponseWriter, retry time.Duration) {
	sec := int(math.Ceil(retry.Seconds()))
	if sec < 1 {
		sec = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(sec))
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
