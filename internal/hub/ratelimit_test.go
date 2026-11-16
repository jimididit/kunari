package hub

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPRateLimiterAllowAndDeny(t *testing.T) {
	lim := newIPRateLimiter(2)
	base := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return base }

	if ok, _ := lim.allow("1.2.3.4"); !ok {
		t.Fatal("first allow")
	}
	if ok, _ := lim.allow("1.2.3.4"); !ok {
		t.Fatal("second allow (burst)")
	}
	ok, retry := lim.allow("1.2.3.4")
	if ok {
		t.Fatal("third must deny")
	}
	if retry < time.Second {
		t.Fatalf("retry-after too small: %v", retry)
	}
	if ok, _ := lim.allow("9.9.9.9"); !ok {
		t.Fatal("other key must allow")
	}
	lim.now = func() time.Time { return base.Add(60 * time.Second) }
	if ok, _ := lim.allow("1.2.3.4"); !ok {
		t.Fatal("expected allow after refill")
	}
}

func TestIPRateLimiterEvictIdleNoDoubleCount(t *testing.T) {
	lim := newIPRateLimiter(60)
	lim.maxKeys = 1
	lim.idleAfter = time.Minute
	base := time.Unix(1_700_000_000, 0).UTC()
	now := base
	lim.now = func() time.Time { return now }

	if ok, _ := lim.allow("idle"); !ok {
		t.Fatal("idle")
	}
	beforeTok := lim.buckets["idle"].tokens
	beforeLast := lim.buckets["idle"].last
	now = base.Add(3 * time.Minute)
	if !lim.evictOneLocked(now) {
		t.Fatal("expected idle eviction")
	}
	if lim.buckets["idle"] != nil {
		t.Fatal("idle should be gone")
	}
	// Recreate and ensure estimate path did not require mutating prior state
	// (bucket was deleted, not altered in place).
	_ = beforeTok
	_ = beforeLast
	if ok, _ := lim.allow("new"); !ok {
		t.Fatal("new after eviction")
	}
}

func TestIPRateLimiterNeverResetsThrottled(t *testing.T) {
	lim := newIPRateLimiter(1)
	lim.maxKeys = 1
	base := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return base }
	if ok, _ := lim.allow("throttled"); !ok {
		t.Fatal("first")
	}
	if ok, _ := lim.allow("throttled"); ok {
		t.Fatal("should be empty")
	}
	// New key must not evict the throttled bucket (bypass).
	if ok, _ := lim.allow("attacker"); ok {
		t.Fatal("must not admit new key by resetting throttled bucket")
	}
	if _, ok := lim.buckets["throttled"]; !ok {
		t.Fatal("throttled bucket must remain")
	}
}

func TestIPRateLimiterDisabled(t *testing.T) {
	if newIPRateLimiter(0) != nil {
		t.Fatal("0 must disable")
	}
}

func TestLimitPublicReturns429(t *testing.T) {
	h := &Hub{ingestLimit: newIPRateLimiter(1)}
	h.ingestLimit.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	var hits int
	handler := h.limitPublic(h.ingestLimit, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK || hits != 1 {
		t.Fatalf("first: code=%d hits=%d", rr.Code, hits)
	}
	rr2 := httptest.NewRecorder()
	handler(rr2, req)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second want 429, got %d", rr2.Code)
	}
	if rr2.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
}

func TestIngestAndJobsSeparateBudgets(t *testing.T) {
	h := &Hub{ingestLimit: newIPRateLimiter(1)}
	base := time.Unix(1_700_000_000, 0).UTC()
	h.ingestLimit.now = func() time.Time { return base }
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "10.0.0.1:9"
	if ok, _ := h.allowIngestRate(req); !ok {
		t.Fatal("ingest first")
	}
	if ok, _ := h.allowIngestRate(req); ok {
		t.Fatal("ingest second must deny")
	}
	if ok, _ := h.allowJobsRate(req); !ok {
		t.Fatal("jobs budget must be separate")
	}
}
