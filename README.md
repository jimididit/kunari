# Kunari

[![CI](https://github.com/jimididit/kunari/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jimididit/kunari/actions/workflows/ci.yml)
[![Security](https://github.com/jimididit/kunari/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/jimididit/kunari/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/jimididit/kunari)](https://github.com/jimididit/kunari/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/jimididit/kunari)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Cross-platform **canary / tripwire toolkit** for DFIR and defensive monitoring.

Kunari helps you plant decoy files, watch them for unauthorized touch, collect signed evidence, and alert through a self-hosted hub - using DNS or HTTPS beacons only (no NTLM-leaking UNC/SMB paths).

> **Authorized use only.** Deploy Kunari only on systems you own or have written authorization to monitor. Do not use it for unauthorized access, harassment, stalking, or offensive operations. Generated manifests include an authorization-reference field for operational accountability.

## Features

- **Forge** decoy artifacts with signed manifests and install notes
- **Sentinel** on-host sensors with honest detection tiers (Linux / Windows / macOS)
- **Hub** HTTPS (+ optional DNS) collector with HMAC ingest from sentinels
- **Evidence** hash-chained, Ed25519-signed event logs (`kunari verify`)
- **Alerts** disk-backed queue - sink failures are surfaced, never silently disabled
- **Operator API** authenticated event pull + live SSE stream

## Install

**Release binaries** (recommended): download the archive for your OS from [Releases](https://github.com/jimididit/kunari/releases). Checksums are published with Syft SBOMs and cosign signatures on `checksums.txt`.

**From source** (Go 1.26.9+):

```bash
git clone https://github.com/jimididit/kunari.git
cd kunari
go build -o bin/kunari ./cmd/kunari
./bin/kunari self-test
```

## Quick start

```bash
# 1) Forge a decoy (beacon + sentinel)
mkdir -p dist data
./bin/kunari forge --type env --name app-secrets --detect both \
  --collector http://127.0.0.1:8080 \
  --memo "lab only" --authz-ref "LAB-001" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db

# 2) Run the hub (creates ingest.secret + api.token under ./data)
./bin/kunari hub --listen 127.0.0.1:8080 --data ./data

# 3) Arm a sentinel (share the hub ingest secret; never put it in the decoy)
./bin/kunari sentinel init-config \
  --path ./dist/app-secrets.env \
  --token "$(jq -r .token_id ./dist/app-secrets.manifest.json)" \
  --hub-url http://127.0.0.1:8080 \
  --hub-secret-file ./data/ingest.secret \
  --out ./sentinel.json
./bin/kunari sentinel run --config ./sentinel.json
```

Touch the decoy (`cat ./dist/app-secrets.env`). Watch hub health and events:

```bash
curl -s http://127.0.0.1:8080/healthz

curl -s -H "Authorization: Bearer $(tr -d '\n' < ./data/api.token)" \
  'http://127.0.0.1:8080/api/v1/events?after_seq=0&limit=50'
```

More detail: [examples/lab-hub](examples/lab-hub/README.md), [examples/docker](examples/docker/README.md).

## Commands

| Command | Role |
|---|---|
| `kunari forge` | Generate tripwire artifacts + signed manifests |
| `kunari lint` | Scan artifacts for static fingerprint tells |
| `kunari verify` | Verify hash-chained, signed event logs |
| `kunari hub` | Beacon collector, ingest, operator API |
| `kunari sentinel` | On-host sensor (best available OS tier) |
| `kunari self-test` | Offline forge + lint + evidence-chain smoke check |

## Hub API (operator)

Secrets live under the hub `--data` directory (`ingest.secret`, `api.token`). Never embed them in forged artifacts.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | Liveness + hit counters |
| `GET\|HEAD /b/{token}` | none | HTTPS beacon |
| `POST /api/v1/ingest` | HMAC (`X-Kunari-*`) | Sentinel event push |
| `GET /api/v1/events` | Bearer / `X-Kunari-API-Key` | Paginated pull (`after_seq`, `limit`) |
| `GET /api/v1/events/stream` | Bearer or `?token=` | Live SSE |

Behind a TLS terminator:

```bash
kunari hub --listen 127.0.0.1:8080 --data ./data \
  --trusted-proxy 127.0.0.1/32 --client-ip-header X-Forwarded-For
```

## Guardrails

- Beacons are **DNS or HTTPS only**
- Collection levels: `minimal` \| `standard` (default) \| `forensic` (network fields opt-in)
- Webhook sinks allow RFC1918 by default (on-prem SIEM); use `DenyPrivate` for cloud-only egress
- SSE `?token=` may appear in proxy logs - prefer `Authorization: Bearer` when possible

## Status

v0.1 is released. Current `main` adds sentinel→hub HMAC ingest, trusted-proxy client IP, webhook `DenyPrivate`, and an authenticated events API + SSE. A thin hub UI and privileged lab proofs (fanotify / Windows SACL / macOS Endpoint Security) are on the roadmap.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Use feature branches and pull requests against `main`. Do not contribute exploit payloads, persistence mechanisms, or credential-stealing beacons.

## Security

See [SECURITY.md](SECURITY.md) for supported versions and how to report vulnerabilities privately.

## License

[Apache-2.0](LICENSE)
