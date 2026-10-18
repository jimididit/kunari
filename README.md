# Kunari

Cross-platform canary / tripwire toolkit for **DFIR and defensive** use.

> **Authorized use only.** Deploy Kunari only on systems you own or have written authorization to monitor. Do not use Kunari for unauthorized access, harassment, stalking, or offensive operations. Generated manifests include an authorization-reference field for operational accountability.

**License:** [Apache-2.0](LICENSE)

## Status

Phase 1 (core + beacons) is in review. Host sensors (`sentinel`) land in Phase 2+. Detection tiers are reported honestly — Kunari will not claim capabilities it has not armed.

## Components

| Command | Role |
|---|---|
| `kunari forge` | Generate tripwire artifacts + signed manifests + install/uninstall notes |
| `kunari lint` | Scan generated artifacts for static fingerprint tells |
| `kunari verify` | Verify hash-chained, signed local event logs |
| `kunari hub` | Self-hosted HTTPS (+ DNS) beacon collector and alert fan-out |
| `kunari sentinel` | On-host sensor (Phase 2+) |

## Guardrails

- Beacons are **DNS or HTTPS only** — no UNC/SMB/WebDAV paths that can leak NTLM credentials.
- Artifacts carry an opaque token ID and collector host — **never** sink secrets (webhooks, API keys).
- Collection levels: `minimal` \| `standard` (default) \| `forensic`. Forensic network fields are opt-in.
- Alert sinks use a disk-backed queue with retries; sink failure is **surfaced**, never silently disabled.

## Quick start (development)

```bash
go build -o bin/kunari ./cmd/kunari
./bin/kunari --help
```

Requires Go 1.24+.

```bash
# Forge a decoy (example)
kunari forge --type env --name app-secrets --detect both \
  --collector https://beacon.example.com \
  --memo "lab only" --authz-ref "LAB-001" --out ./dist

# Run a local hub
kunari hub --listen :8443 --data ./data
```

## Contributing

Use feature branches and pull requests against `main`. Keep secrets and local research notes out of git (see `.gitignore`). Do not contribute exploit payloads, persistence mechanisms, or credential-stealing beacons.

## Security

Report vulnerabilities privately to the maintainer. Do not open public issues that include working exploit details against Kunari itself.
