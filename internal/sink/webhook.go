package sink

import (
	"bytes"
	"context"
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

// WebhookOptions tunes SSRF egress policy for SIEM / alert webhooks.
type WebhookOptions struct {
	// DenyPrivate blocks RFC1918, RFC4193 ULA, and other net.IP.IsPrivate()
	// destinations in addition to loopback/link-local. Use for cloud-only sinks
	// that must never reach on-prem addresses.
	DenyPrivate bool
}

func NewWebhookSink(rawURL string, secret []byte) (*WebhookSink, error) {
	return NewWebhookSinkOpts(rawURL, secret, WebhookOptions{})
}

func NewWebhookSinkOpts(rawURL string, secret []byte, opts WebhookOptions) (*WebhookSink, error) {
	if len(secret) < minSecretLen {
		return nil, fmt.Errorf("webhook secret must be at least %d bytes", minSecretLen)
	}
	if err := validateWebhookURL(rawURL, opts.DenyPrivate); err != nil {
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
				// No env proxy: HTTP(S)_PROXY would dial the proxy instead of the
				// destination, skipping safeDialContext's DNS-rebinding / SSRF checks.
				Proxy:                 nil,
				DialContext:           makeSafeDial(opts.DenyPrivate),
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
	sig := SignBody(w.secret, ts, body)

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

func validateWebhookURL(raw string, denyPrivate bool) error {
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
	if isBlockedHostLiteral(host, denyPrivate) {
		return fmt.Errorf("webhook host %q blocked (loopback/link-local/metadata/private)", host)
	}
	return nil
}

func isBlockedHostLiteral(host string, denyPrivate bool) bool {
	h := normalizeHost(host)
	if h == "localhost" || h == "metadata.google.internal" ||
		strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".metadata.google.internal") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return isBlockedIP(ip, denyPrivate)
}

func isBlockedIP(ip net.IP, denyPrivate bool) bool {
	if ip == nil {
		return true
	}
	// Loopback/link-local/metadata/multicast. RFC1918 allowed unless DenyPrivate.
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if denyPrivate && ip.IsPrivate() {
		return true
	}
	return false
}

func makeSafeDial(denyPrivate bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return safeDialContext(ctx, network, addr, denyPrivate)
	}
}

// safeDialContext resolves the host and refuses destinations that land on blocked IPs
// (DNS rebinding / metadata SSRF). Only dials a non-blocked address.
func safeDialContext(ctx context.Context, network, addr string, denyPrivate bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	host = normalizeHost(host)
	if isBlockedHostLiteral(host, denyPrivate) {
		return nil, fmt.Errorf("webhook host %q blocked", host)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	d := &net.Dialer{Timeout: 10 * time.Second}
	for _, ipa := range ips {
		if isBlockedIP(ipa.IP, denyPrivate) {
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
	return newWebhook(rawURL, secret, true)
}

// NewHubPushSink builds an operator-configured hub ingest client.
// Loopback and RFC1918 are allowed (lab / on-prem hubs); link-local metadata stays blocked.
func NewHubPushSink(rawURL string, secret []byte) (*WebhookSink, error) {
	return newWebhook(rawURL, secret, true)
}

func newWebhook(rawURL string, secret []byte, allowPrivate bool) (*WebhookSink, error) {
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
	if u.Hostname() == "" {
		return nil, fmt.Errorf("webhook host required")
	}
	host := normalizeHost(u.Hostname())
	if !allowPrivate {
		if err := validateWebhookURL(rawURL, false); err != nil {
			return nil, err
		}
	} else if isMetadataHost(host) {
		return nil, fmt.Errorf("webhook host %q blocked (metadata)", u.Hostname())
	}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if allowPrivate {
		// Lab/on-prem hubs may be loopback or RFC1918; still refuse link-local metadata
		// even when the URL hostname is a DNS name that resolves there.
		transport.DialContext = hubDialContext
	} else {
		transport.DialContext = makeSafeDial(false)
	}
	return &WebhookSink{
		url:    rawURL,
		secret: append([]byte(nil), secret...),
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: transport,
		},
	}, nil
}

func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	return h
}

func isMetadataHost(host string) bool {
	h := normalizeHost(host)
	if h == "metadata.google.internal" || strings.HasSuffix(h, ".metadata.google.internal") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	// AWS/GCP/Azure link-local metadata (and scoped IPv6 after zone strip)
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// hubDialContext allows loopback/RFC1918 hub destinations but refuses link-local
// metadata, multicast, and unspecified addresses (including via DNS rebinding).
func hubDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	host = normalizeHost(host)
	if isMetadataHost(host) {
		return nil, fmt.Errorf("hub host %q blocked (metadata)", host)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	d := &net.Dialer{Timeout: 10 * time.Second}
	for _, ipa := range ips {
		if isHubBlockedIP(ipa.IP) {
			last = fmt.Errorf("hub resolved to blocked address %s", ipa.IP)
			continue
		}
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("hub host %q has no usable addresses", host)
	}
	return nil, last
}

func isHubBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}
