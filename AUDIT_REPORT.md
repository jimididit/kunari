# Kunari Audit Report (v0.1 / Phase 5)

**Date:** 2026-10-17  
**Scope:** `github.com/jimididit/kunari` at Phase 4 merge tip plus Phase 5 hardening fixes in this PR.  
**Method:** Threat-model driven review (STRIDE), code inspection of hub/sinks/sentinel/forge/crypto, CI security gates (`govulncheck`, `gosec`, Semgrep, fuzz), and prior Graphify advisory triage.  
**Use case:** Authorized defensive DFIR / tripwire only.

This report is an engineering self-audit, not a third-party certification.

---

## Executive summary

Kunari's v0.1 surface is appropriate for lab and controlled authorized deployments: opaque tokens, DNS/HTTPS-only beacons, signed hash-chained evidence, store-and-forward sinks, and honest detection-tier reporting.

**Critical findings open at audit start:** none that enable remote code execution or credential theft via forbidden beacon channels.

**High findings addressed in Phase 5:**

| ID | Finding | Status |
|---|---|---|
| H1 | Webhook SSRF via DNS rebinding to loopback/metadata | **Fixed** - dial-time IP deny + literal host checks |
| H2 | Empty / short webhook HMAC secrets accepted | **Fixed** - minimum 16-byte secret |
| H3 | Hub trusted spoofable `X-Forwarded-For` | **Fixed** - use `RemoteAddr` only |

Residual risk is dominated by host-level sensor privilege gaps (documented as NEEDS VERIFICATION) and operational TLS termination, not by artifact beacon design.

---

## Assets reviewed

| Asset | Notes |
|---|---|
| Sink credentials / webhook URLs | Must never appear in forged artifacts (`kunari lint`) |
| Hub / sentinel signing keys | Ed25519; `0600` files via `safepath.Clean` |
| Event log (`kunari.event/1`) | Hash-chained + signed; `kunari verify` |
| Registry SQLite + manifests | Authz-ref required; revoke supported |
| Tripwire artifacts | Decoys only; Apache-2.0; no UNC/WebDAV beacons |

---

## Findings detail

### Fixed this phase

#### H1 - Webhook DNS-rebinding SSRF (High)

**Where:** `internal/sink/webhook.go`  
**Issue:** Destination validation only inspected literal hostnames/IPs. A DNS name that later resolved to `127.0.0.1` or `169.254.169.254` could bypass checks.  
**Fix:** Custom `DialContext` resolves addresses and refuses loopback / link-local / multicast / unspecified IPs before connect. Redirects still rejected.  
**Residual:** RFC1918 destinations remain allowed for on-prem SIEM (intentional). Operators who need a full public-only allowlist should terminate sinks behind their own egress policy.

#### H2 - Weak webhook HMAC secret (High)

**Where:** `internal/sink/webhook.go`  
**Issue:** Empty or short secrets produced forgeable signatures.  
**Fix:** Reject secrets shorter than 16 bytes at sink construction.

#### H3 - Spoofable client IP via XFF (High)

**Where:** `internal/hub/http.go` `clientIP`  
**Issue:** First `X-Forwarded-For` hop was trusted unconditionally, so any client could plant false `network.src_ip` in beacon events.  
**Fix:** Record `RemoteAddr` only. Document that TLS terminators should stamp trusted identity separately in a later release.

### Accepted / residual (not Critical)

| ID | Severity | Topic | Disposition |
|---|---|---|---|
| M1 | Medium | Hub HTTP has no built-in TLS | Documented; use reverse proxy (`--listen` help text) |
| M2 | Medium | Authenticated event pull API is a stub | Intentional v0.1; use local `events.jsonl` + `verify` |
| M3 | Medium | DNS beacon answers `A 127.0.0.1` | Lab simplicity; does not leak secrets |
| M4 | Medium | Allowlist silences alerts (still records) | By design; default entries require path hints |
| M5 | Medium | Sentinel→hub HMAC channel not fully wired in CLI | Queue + file/stdout sinks first; hub push hardening on roadmap |
| M6 | Medium | Live elevated fanotify / SACL-4663 / mac-eslogger | **NV** - needs privileged labs |
| L1 | Low | Graphify formal verification abstains (`GOPROXY`) | CI informational only |
| L2 | Low | gosec G304 residuals after `safepath.Clean` | Accepted with `#nosec` + Clean |

### Explicit non-findings (design constraints)

- No UNC / SMB / WebDAV beacons (NTLM leak class) - enforced by product guardrails.
- No fanotify permission / blocking modes (`FAN_OPEN_PERM`) - availability risk avoided.
- Detection tiers report the armed mechanism only (`mac-fsevents` cannot claim open/PID).
- `copy_suspected` is always inferred, never a proven OS action.

---

## Component notes

### Forge

Install notes use POSIX single-quoting for `--memo` / path / token (shell metacharacters). Lint catches common fingerprint / webhook URL embeds. Artifact files are owner-restricted (`0600`); operators may chmod for multi-user labs.

### Sentinel

OpenBest tiers: Linux fanotify→inotify; Windows SACL-4663→RDC; macOS eslogger (root)→FSEvents. Allowlist matches are auditable on the event. Evidence chain + disk queue survive sink outages without silent disable.

### Hub

HTTPS path `/b/{token}` and optional DNS zone collector. Unknown tokens still record as probes. Throttle suppresses alert fan-out but keeps chain appends.

### Supply chain

Go 1.26.9+ toolchain (stdlib HTTP/2 HPACK fix). Release workflow: GoReleaser archives, Syft SBOM, cosign keyless checksum signatures. `main` protected by ruleset requiring PR + CI/security checks.

---

## Verification performed

- `go test ./...`
- `kunari self-test`
- CI: unit matrix (linux/windows/macos), `govulncheck`, `gosec`, Semgrep `p/golang`, short fuzz
- Prior Graphify advisories on Phase 3 (memo quoting, allowlist path hints, eslogger schema, root probe) closed before Phase 4 merge

---

## Recommendations before production use

1. Terminate hub TLS at a reverse proxy; do not expose plain `--listen` to the internet.
2. Generate ≥16-byte webhook secrets; prefer HTTPS sink URLs.
3. Treat elevated sensor tiers as optional until lab-proved on your OS images.
4. Retain signing keys and `events.jsonl` offline for evidence continuity.
5. Keep `authz-ref` populated and revoke tokens after operations.

---

## Sign-off

Phase 5 engineering audit complete for v0.1 scope. Critical open issues: **none**. High issues from this pass: **closed in-tree**. Remaining items tracked in [ROADMAP.md](ROADMAP.md).
