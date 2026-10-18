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

Point a reverse proxy with TLS at the hub for realistic HTTPS beacons, or use DNS collector separately.

## 4. Sentinel against the forged file

```bash
./bin/kunari sentinel init-config \
  --path ./dist/lab-secrets.env \
  --token "$(jq -r .token_id ./dist/lab-secrets.manifest.json)" \
  --out ./data/sentinel.json
./bin/kunari sentinel install-hints --config ./data/sentinel.json
./bin/kunari sentinel run --config ./data/sentinel.json
```

On Linux without `CAP_SYS_ADMIN`, expect tier `inotify`. On macOS without root, expect `mac-fsevents`.
