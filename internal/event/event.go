package event

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const Schema = "kunari.event/1"

type Confidence struct {
	Action        string `json:"action"` // proven|inferred
	CopySuspected bool   `json:"copy_suspected"`
}

type FileInfo struct {
	Path           string `json:"path,omitempty"`
	SHA256AtDeploy string `json:"sha256_at_deploy,omitempty"`
	SHA256Now      string `json:"sha256_now,omitempty"`
	Size           int64  `json:"size,omitempty"`
	Mtime          string `json:"mtime,omitempty"`
}

type HostInfo struct {
	ID           string `json:"id,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	OS           string `json:"os,omitempty"`
	OSVersion    string `json:"os_version,omitempty"`
	BootID       string `json:"boot_id,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
}

type Actor struct {
	PID                int      `json:"pid,omitempty"`
	PPID               int      `json:"ppid,omitempty"`
	Exe                string   `json:"exe,omitempty"`
	Cmdline            string   `json:"cmdline,omitempty"`
	Cwd                string   `json:"cwd,omitempty"`
	UIDOrSID           string   `json:"uid_or_sid,omitempty"`
	Username           string   `json:"username,omitempty"`
	LogonID            string   `json:"logon_id,omitempty"`
	Session            string   `json:"session,omitempty"`
	Signer             string   `json:"signer,omitempty"`
	ParentChain        []string `json:"parent_chain,omitempty"`
	StartTime          string   `json:"start_time,omitempty"`
	AttributionQuality string   `json:"attribution_quality,omitempty"`
}

type Network struct {
	SrcIP         string            `json:"src_ip,omitempty"`
	UA            string            `json:"ua,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	TLSFP         string            `json:"tls_fp,omitempty"`
	RDNS          string            `json:"rdns,omitempty"`
	GeoASN        string            `json:"geo_asn,omitempty"`
	DNSResolverIP string            `json:"dns_resolver_ip,omitempty"`
}

type Context struct {
	LogonSourceIP     string   `json:"logon_source_ip,omitempty"`
	ActiveSessions    []string `json:"active_sessions,omitempty"`
	AllowlistMatched  bool     `json:"allowlist_matched,omitempty"`
}

type Integrity struct {
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	Sig      string `json:"sig"`
}

// Event is the stable kunari.event/1 envelope.
type Event struct {
	Schema        string     `json:"schema"`
	EventID       string     `json:"event_id"`
	TokenID       string     `json:"token_id"`
	Memo          string     `json:"memo,omitempty"`
	ObservedAt    time.Time  `json:"observed_at"`
	Detector      string     `json:"detector"`
	DetectionTier string     `json:"detection_tier"`
	Action        string     `json:"action"`
	Confidence    Confidence `json:"confidence"`
	File          *FileInfo  `json:"file,omitempty"`
	Host          *HostInfo  `json:"host,omitempty"`
	Actor         *Actor     `json:"actor,omitempty"`
	Network       *Network   `json:"network,omitempty"`
	Context       *Context   `json:"context,omitempty"`
	Integrity     Integrity  `json:"integrity"`
}

func New(tokenID, detector, tier, action string) *Event {
	return &Event{
		Schema:        Schema,
		EventID:       uuid.Must(uuid.NewV7()).String(),
		TokenID:       tokenID,
		ObservedAt:    time.Now().UTC(),
		Detector:      detector,
		DetectionTier: tier,
		Action:        action,
		Confidence:    Confidence{Action: "proven"},
	}
}

func (e *Event) Validate() error {
	if e.Schema != Schema {
		return fmt.Errorf("unsupported schema %q", e.Schema)
	}
	if e.EventID == "" || e.TokenID == "" {
		return fmt.Errorf("event_id and token_id are required")
	}
	if e.Detector == "" || e.DetectionTier == "" || e.Action == "" {
		return fmt.Errorf("detector, detection_tier, and action are required")
	}
	return nil
}

// CanonicalPayload returns JSON used for hashing (integrity fields zeroed).
func (e *Event) CanonicalPayload() ([]byte, error) {
	cp := *e
	cp.Integrity = Integrity{}
	return json.Marshal(cp)
}
