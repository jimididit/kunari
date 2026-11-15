package hub

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPRateLimiterAllowAndDeny(t *testing.T) {
	lim := newIPRateLimiter(2) // 2/min burst 2
	if lim == nil {
		t.Fatal("expected limiter")
	}
	base := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return base }
	lim.global.last = base
	lim.global.tokens = lim.globalBurst

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
	// Other IP unaffected (per-IP), still under global.
	if ok, _ := lim.allow("9.9.9.9"); !ok {
		t.Fatal("other IP must allow")
	}
	// Refill after 60s at 2/min -> +2 tokens.
	lim.now = func() time.Time { return base.Add(60 * time.Second) }
	if ok, _ := lim.allow("1.2.3.4"); !ok {
		t.Fatal("expected allow after refill")
	}
}

func TestIPRateLimiterGlobalBackstop(t *testing.T) {
	lim := newIPRateLimiter(1)
	base := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return base }
	lim.global.last = base
	lim.global.tokens = 2 // tiny global for test
	lim.globalBurst = 2
	lim.globalRatePerSec = 0
	for i := 0; i < 2; i++ {
		if ok, _ := lim.allow(fmt.Sprintf("ip-%d", i)); !ok {
			t.Fatalf("allow %d", i)
		}
	}
	if ok, _ := lim.allow("ip-z"); ok {
		t.Fatal("global backstop must deny")
	}
}

func TestIPRateLimiterDisabled(t *testing.T) {
	if newIPRateLimiter(0) != nil {
		t.Fatal("0 must disable")
	}
	if newIPRateLimiter(-1) != nil {
		t.Fatal("negative must disable")
	}
}

func TestLimitPublicReturns429(t *testing.T) {
	h := &Hub{ingestLimit: newIPRateLimiter(1)}
	h.ingestLimit.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	h.ingestLimit.global.last = h.ingestLimit.now()
	h.ingestLimit.global.tokens = h.ingestLimit.globalBurst
	var hits int
	handler := h.limitPublic(h.ingestLimit, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/pull", nil)
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
	if hits != 1 {
		t.Fatalf("handler must not run on 429: hits=%d", hits)
	}
}

func TestEvictOneIsBounded(t *testing.T) {
	lim := newIPRateLimiter(60)
	lim.maxKeys = 3
	base := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return base }
	lim.global.last = base
	lim.global.tokens = lim.globalBurst
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("k%d", i)
		if ok, _ := lim.allow(key); !ok {
			t.Fatalf("allow %s", key)
		}
	}
	if len(lim.buckets) > lim.maxKeys {
		t.Fatalf("buckets grew past max: %d", len(lim.buckets))
	}
}
