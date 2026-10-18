package sink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DefaultSkew is the max clock skew accepted for HMAC timestamps.
const DefaultSkew = 5 * time.Minute

// SignBody returns the hex HMAC-SHA256 of timestamp + "." + body.
func SignBody(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks X-Kunari-* style HMAC headers.
// sigHeader may be "sha256=<hex>" or bare hex. skew is Max(|now-ts|).
func VerifySignature(secret []byte, timestampHeader, sigHeader string, body []byte, now time.Time, skew time.Duration) error {
	if len(secret) < minSecretLen {
		return fmt.Errorf("secret too short")
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(timestampHeader), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp")
	}
	if skew <= 0 {
		skew = DefaultSkew
	}
	delta := now.UTC().Sub(time.Unix(ts, 0).UTC())
	if delta < 0 {
		delta = -delta
	}
	if delta > skew {
		return fmt.Errorf("timestamp outside skew window")
	}
	want := SignBody(secret, strconv.FormatInt(ts, 10), body)
	got := strings.TrimSpace(sigHeader)
	got = strings.TrimPrefix(got, "sha256=")
	gotBytes, err := hex.DecodeString(got)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	wantBytes, err := hex.DecodeString(want)
	if err != nil {
		return fmt.Errorf("internal signature encoding")
	}
	if !hmac.Equal(gotBytes, wantBytes) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
