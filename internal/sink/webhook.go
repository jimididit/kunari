package sink

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jimididit/kunari/internal/event"
)

const (
	HeaderSignature = "X-Kunari-Signature"
	HeaderTimestamp = "X-Kunari-Timestamp"
	HeaderEventID   = "X-Kunari-Event-Id"
)

type WebhookSink struct {
	url    string
	secret []byte
	client *http.Client
}

func NewWebhookSink(rawURL string, secret []byte) (*WebhookSink, error) {
	if err := validateWebhookURL(rawURL); err != nil {
		return nil, err
	}
	return &WebhookSink{
		url:    rawURL,
		secret: secret,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (w *WebhookSink) Name() string { return "webhook" }

func (w *WebhookSink) Deliver(ctx context.Context, ev *event.Event) error {
	body, err := MarshalEvent(ev)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, w.secret)
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderTimestamp, ts)
	req.Header.Set(HeaderSignature, "sha256="+sig)
	req.Header.Set(HeaderEventID, ev.EventID)

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("webhook scheme must be http(s)")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("webhook host required")
	}
	if isBlockedHost(host) {
		return fmt.Errorf("webhook host %q blocked (link-local/metadata)", host)
	}
	return nil
}

func isBlockedHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || h == "metadata.google.internal" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	// Block loopback/link-local/metadata by default (SSRF). RFC1918 private
	// ranges are allowed so operators can reach on-prem SIEMs; tighten via
	// allowlists in a later release if needed.
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || h == "169.254.169.254"
}

// AllowLocalWebhook is for tests only — production NewWebhookSink blocks loopback.
func NewWebhookSinkAllowLocal(rawURL string, secret []byte) (*WebhookSink, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("webhook scheme must be http(s)")
	}
	return &WebhookSink{
		url:    rawURL,
		secret: secret,
		client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}
