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
	minSecretLen    = 16
)

type WebhookSink struct {
	url    string
	secret []byte
	client *http.Client
}

func NewWebhookSink(rawURL string, secret []byte) (*WebhookSink, error) {
	if len(secret) < minSecretLen {
		return nil, fmt.Errorf("webhook secret must be at least %d bytes", minSecretLen)
	}
	if err := validateWebhookURL(rawURL); err != nil {
		return nil, err
	}
	return &WebhookSink{
		url:    rawURL,
		secret: append([]byte(nil), secret...),
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           safeDialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          4,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
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
	if isBlockedHostLiteral(host) {
		return fmt.Errorf("webhook host %q blocked (loopback/link-local/metadata)", host)
	}
	return nil
}

func isBlockedHostLiteral(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || h == "metadata.google.internal" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return isBlockedIP(ip)
}

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Loopback/link-local/metadata/multicast. RFC1918 remains allowed for on-prem SIEM.
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

// safeDialContext resolves the host and refuses destinations that land on blocked IPs
// (DNS rebinding / metadata SSRF). Only dials a non-blocked address.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if isBlockedHostLiteral(host) {
		return nil, fmt.Errorf("webhook host %q blocked", host)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	d := &net.Dialer{Timeout: 10 * time.Second}
	for _, ipa := range ips {
		if isBlockedIP(ipa.IP) {
			last = fmt.Errorf("webhook resolved to blocked address %s", ipa.IP)
			continue
		}
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("webhook host %q has no usable addresses", host)
	}
	return nil, last
}

// NewWebhookSinkAllowLocal is for tests only - skips destination IP guards.
func NewWebhookSinkAllowLocal(rawURL string, secret []byte) (*WebhookSink, error) {
	if len(secret) < minSecretLen {
		return nil, fmt.Errorf("webhook secret must be at least %d bytes", minSecretLen)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("webhook scheme must be http(s)")
	}
	return &WebhookSink{
		url:    rawURL,
		secret: append([]byte(nil), secret...),
		client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}, nil
}
