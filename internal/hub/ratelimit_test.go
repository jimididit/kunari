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

func TestIPRateLimiterEvictsIdleOnly(t *testing.T) {
	lim := newIPRateLimiter(60)
	lim.maxKeys = 2
	lim.idleAfter = time.Minute
	base := time.Unix(1_700_000_000, 0).UTC()
	now := base
	lim.now = func() time.Time { return now }

	if ok, _ := lim.allow("idle"); !ok {
		t.Fatal("idle")
	}
	if ok, _ := lim.allow("hot"); !ok {
		t.Fatal("hot")
	}
	// Exhaust hot so it is not idle/full.
	for i := 0; i < 60; i++ {
		lim.allow("hot")
	}
	// Advance past idleAfter; idle is full+quiet, hot is depleted.
	now = base.Add(3 * time.Minute)
	if ok, _ := lim.allow("new"); !ok {
		t.Fatal("should evict idle and admit new")
	}
	if _, ok := lim.buckets["idle"]; ok {
		t.Fatal("idle should have been evicted")
	}
	if _, ok := lim.buckets["hot"]; !ok {
		t.Fatal("hot must not be evicted while active")
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
