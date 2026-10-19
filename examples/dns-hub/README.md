# DNS beacon collector (lab)

Authorized use only. The hub can answer UDP DNS queries for a zone you control and record a `beacon-dns` hit when the left-most label encodes a forged token.

DNS beacons are a second channel next to HTTPS. They do **not** watch the filesystem. Something still has to resolve the embedded name (or fetch a PDF URI that falls back to `https://<dns-name>/`).

You must control the zone (or a delegated subdomain) so queries reach this hub. Pointing `--collector-dns` at a zone you do not operate is not a supported deploy.

## Lab hub

```bash
mkdir -p data
kunari hub --listen 127.0.0.1:8080 --data ./data \
  --dns-listen 127.0.0.1:5353 \
  --dns-zone canary.example.invalid
```

Privileged port 53 is optional. Lab on `5353` is enough to prove the collector without binding system DNS.

## Forge

`env` and `pdf` embed DNS names. Other types (`svg`, `html`, `docx`, `xlsx`) need `--collector` HTTPS today.

DNS-only (`env` or `pdf`):

```bash
kunari forge --type env --name dns-secrets --detect beacon \
  --collector-dns canary.example.invalid \
  --memo "authorized dns lab" --authz-ref "LAB-DNS-001" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db
```

Dual channel (HTTPS + DNS):

```bash
kunari forge --type pdf --name budget-notes --detect beacon \
  --collector https://beacon.example.com \
  --collector-dns canary.example.invalid \
  --memo "authorized dual-channel lab" --authz-ref "LAB-DNS-002" \
  --out ./dist --key ./data/signing.key --registry ./data/registry.db
```

Read the DNS name from the manifest (`beacon_dns`) or from the artifact (`METRICS_HOST=` in `.env`).

## Smoke

```bash
# Replace NAME with beacon_dns from the manifest (no trailing dot required for dig).
dig @127.0.0.1 -p 5353 NAME. A +short

curl -sS http://127.0.0.1:8080/healthz
# hits should increase after a successful query
```

Operator events (Bearer token under `./data/api.token`):

```bash
curl -sS -H "Authorization: Bearer $(tr -d '\n' < ./data/api.token)" \
  'http://127.0.0.1:8080/api/v1/events?after_seq=0&limit=20'
```

Expect `detection_tier` `beacon-dns` and `action` `beacon_fetch`.

## Production notes

- Delegate a subdomain (for example `canary.example.com`) to the host that runs `--dns-listen` on UDP/53, or put a DNS forwarder in front.
- Keep the hub HTTP listener on loopback and terminate HTTPS separately ([../tls-hub](../tls-hub/README.md)).
- Do not put `ingest.secret`, `api.token`, or signing keys in forged artifacts.
- Opening a decoy does not guarantee a DNS query. Clients and resolvers decide whether the embedded name is resolved.

## What this example is not

- Not a recursive DNS server for the LAN.
- Not UNC / SMB / WebDAV (those stay out of scope).
- Not a substitute for `kunari package agent` / sentinel filesystem tiers.
