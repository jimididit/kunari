# Kunari Roadmap (post v0.1)

Living list after Phase 5. Ordered by defensive value, not calendar commitment.

---

## Near term

| Item | Why |
|---|---|
| Wire sentinel→hub authenticated push (HMAC + optional mTLS) | Close M5; reduce reliance on local file sinks alone |
| Trusted-proxy client IP mode for hub | Restore accurate `src_ip` behind TLS terminators without raw XFF trust |
| Webhook egress allowlist (optional deny-RFC1918) | Operators who never call on-prem SIEM |
| Privileged lab proofs: fanotify, win-sacl-4663, mac-eslogger+FDA | Clear **NV** cells in the capability matrix |
| First tagged release `v0.1.0` | Exercise GoReleaser + SBOM + cosign in anger |

## Medium term

| Item | Why |
|---|---|
| Authenticated `/api/v1/events` pull + SSE | Replace stub; retention / pagination |
| Built-in TLS options or documented Caddy/nginx recipes | Reduce foot-guns for hub exposure |
| Windows ETW Kernel-File tier (evaluate) | Stronger than RDC when SACL unavailable |
| richer allowlist (signer / Authenticode / path prefix DSL) | Cut noise without basename games |
| Hub token rate limits / proof-of-work | Abuse resistance on public collectors |

## Later / research

| Item | Why |
|---|---|
| Notarized Endpoint Security system extension | Replace `eslogger` CLI for production macOS |
| WebDAV canary filesystem (evaluate only) | Prior-art idea; watch for NTLM / auth pitfalls |
| Additional forge types (docx/xlsx/pdf hardening) | Broader decoy coverage with lint + fuzz |
| Independent external audit | Beyond engineering self-review |

---

## Explicit non-goals

- Offensive payloads, persistence, credential stealing, hack-back
- UNC / SMB / WebDAV beacons that can coerce NTLM
- Fanotify permission (blocking) modes
- Claiming unproven detection tiers in README or heartbeats

---

## Tracking

Internal planning notes remain private (`docs/`, `PLAN.md`). Public status lives in README + this file. Capability honesty rules stay: every marketed claim maps to a test ID or **NEEDS VERIFICATION**.
