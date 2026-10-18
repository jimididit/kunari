# Lab: local hub + forged decoy

Authorized lab use only. No production secrets.

## 1. Build

```bash
go build -o bin/kunari ./cmd/kunari
./bin/kunari self-test
```

## 2. Forge a decoy (beacon + sentinel)

```bash
mkdir -p dist data
./bin/kunari forge --type env --name lab-secrets --detect both \
  --collector https://127.0.0.1:8443 \
  --memo "lab only" --authz-ref "LAB-001" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db
```

## 3. Hub (TLS terminator or plain listen for lab)

```bash
./bin/kunari hub --listen 127.0.0.1:8443 --data ./data/hub
```

Hub writes `./data/hub/ingest.secret` (hex, mode 0600) for sentinel HMAC push.
Point a reverse proxy with TLS at the hub for realistic HTTPS beacons, or use DNS collector separately.

## 4. Sentinel against the forged file (local + hub push)

```bash
./bin/kunari sentinel init-config \
  --path ./dist/lab-secrets.env \
  --token "$(jq -r .token_id ./dist/lab-secrets.manifest.json)" \
  --hub-url http://127.0.0.1:8443 \
  --hub-secret-file ./data/hub/ingest.secret \
  --out ./data/sentinel.json
# init-config writes mode 0600; keep data_dir 0700 and secrets private.
# Ensure data_dir in sentinel.json is writable; then:
./bin/kunari sentinel install-hints --config ./data/sentinel.json
./bin/kunari sentinel run --config ./data/sentinel.json
```

Touch the decoy (`cat ./dist/lab-secrets.env`). Sentinel records locally and HMAC-POSTs to
`POST /api/v1/ingest`. Watch hub hits via `curl -s http://127.0.0.1:8443/healthz` or
`tail -f ./data/hub/events.jsonl`.

On Linux without `CAP_SYS_ADMIN`, expect tier `inotify`. On macOS without root, expect `mac-fsevents`.
