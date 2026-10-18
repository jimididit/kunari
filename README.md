# Kunari

Cross-platform canary / tripwire toolkit for **DFIR and defensive** use.

> **Authorized use only.** Deploy Kunari only on systems you own or have written authorization to monitor. Do not use Kunari for unauthorized access, harassment, stalking, or offensive operations. Generated manifests include an authorization-reference field for operational accountability.

**License:** [Apache-2.0](LICENSE)

## Status

Phase 5 closes the v0.1 engineering audit (webhook SSRF hardening, hub client-IP handling). Packaging, security CI, and honest detection-tier reporting remain in place.

## Components

| Command | Role |
|---|---|
| `kunari forge` | Generate tripwire artifacts + signed manifests + install/uninstall notes |
| `kunari lint` | Scan generated artifacts for static fingerprint tells |
| `kunari verify` | Verify hash-chained, signed local event logs |
| `kunari hub` | Self-hosted HTTPS (+ DNS) beacon collector and alert fan-out |
| `kunari sentinel` | On-host sensor (Linux fanotify/inotify, Windows SACL-4663/RDC, macOS eslogger/FSEvents) |
| `kunari self-test` | Offline forge + lint + evidence-chain smoke check |

## Guardrails

- Beacons are **DNS or HTTPS only** - no UNC/SMB/WebDAV paths that can leak NTLM credentials.
- Artifacts carry an opaque token ID and collector host - **never** sink secrets (webhooks, API keys).
- Collection levels: `minimal` \| `standard` (default) \| `forensic`. Forensic network fields are opt-in.
- Alert sinks use a disk-backed queue with retries; sink failure is **surfaced**, never silently disabled.

## Quick start (development)

```bash
go build -o bin/kunari ./cmd/kunari
./bin/kunari self-test
./bin/kunari --help
```

Requires Go 1.26.9+ (patched stdlib; see `go.mod` toolchain).

```bash
# Forge a decoy (example)
kunari forge --type env --name app-secrets --detect both \
  --collector https://beacon.example.com \
  --memo "lab only" --authz-ref "LAB-001" --out ./dist

# Run a local hub (creates data/ingest.secret for sentinel HMAC push)
kunari hub --listen :8443 --data ./data

# Behind Caddy/nginx: only trust the terminator for client IP
kunari hub --listen 127.0.0.1:8080 --data ./data \
  --trusted-proxy 127.0.0.1/32 --client-ip-header X-Forwarded-For

# Watch a deployed path and push alerts to the hub
kunari sentinel init-config --path ./dist/app-secrets.env --token <token_id> \
  --hub-url http://127.0.0.1:8443 --hub-secret-file ./data/ingest.secret \
  --out sentinel.json
kunari sentinel install-hints --config sentinel.json
kunari sentinel run --config sentinel.json
```

Hub accepts `POST /api/v1/ingest` (HMAC-SHA256, same headers as webhook sinks). Share `ingest.secret` with sentinels; never embed it in forged artifacts. Webhook sinks allow RFC1918 by default (on-prem SIEM); use `sink.WebhookOptions{DenyPrivate: true}` for cloud-only egress.

Lab walkthroughs: [examples/lab-hub](examples/lab-hub/README.md), [examples/docker](examples/docker/README.md).

## Releases

Push a `v*` tag to run [.github/workflows/release.yml](.github/workflows/release.yml): GoReleaser builds multi-OS archives, Syft SBOMs, and cosign keyless signatures on `checksums.txt`.

## Contributing

Use feature branches and pull requests against `main`. Keep secrets and local research notes out of git (see `.gitignore`). Do not contribute exploit payloads, persistence mechanisms, or credential-stealing beacons.

## Security

CI runs `govulncheck`, `gosec`, and Semgrep (`p/golang`) on every PR. Report vulnerabilities privately to the maintainer. Do not open public issues that include working exploit details against Kunari itself.
