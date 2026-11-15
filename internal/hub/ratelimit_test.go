package hub

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPRateLimiterAllowAndDeny(t *testing.T) {
	lim := newIPRateLimiter(2)
	if lim == nil {
		t.Fatal("expected limiter")
	}
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

func TestIPRateLimiterOverflow(t *testing.T) {
	lim := newIPRateLimiter(1)
	base := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return base }
	if ok, _ := lim.allow("1.1.1.1"); !ok {
		t.Fatal("primary")
	}
	if ok, _ := lim.allow("1.1.1.1"); ok {
		t.Fatal("primary exhausted")
	}
	if !lim.allowOverflow("1.1.1.1") {
		t.Fatal("overflow should still allow recording")
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
}

func TestEvictOneIsBounded(t *testing.T) {
	lim := newIPRateLimiter(60)
	lim.maxKeys = 3
	base := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return base }
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

func TestAllowIngestRateKeyUsesAgent(t *testing.T) {
	h := &Hub{ingestLimit: newIPRateLimiter(1)}
	base := time.Unix(1_700_000_000, 0).UTC()
	h.ingestLimit.now = func() time.Time { return base }
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "10.0.0.1:9"
	if ok, _ := h.allowIngestRateKey(req, "agent-a"); !ok {
		t.Fatal("agent-a first")
	}
	if ok, _ := h.allowIngestRateKey(req, "agent-a"); ok {
		t.Fatal("agent-a second must deny")
	}
	// Different agent behind same IP still allowed.
	if ok, _ := h.allowIngestRateKey(req, "agent-b"); !ok {
		t.Fatal("agent-b must not share agent-a bucket")
	}
}
