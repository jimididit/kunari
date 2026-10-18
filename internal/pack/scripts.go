package pack

import (
	"fmt"
	"strings"
)

func linuxInstall(prefix, binName string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
# Kunari agent install (Linux). Authorized use only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX="%s"
BIN_SRC="$ROOT/bin/%s"
if [[ ! -x "$BIN_SRC" && ! -f "$BIN_SRC" ]]; then
  echo "error: place %s in $ROOT/bin/ first" >&2
  exit 1
fi
if [[ ! -s "$ROOT/etc/ingest.secret" ]] || grep -q '^#' "$ROOT/etc/ingest.secret"; then
  echo "error: etc/ingest.secret missing or still a placeholder" >&2
  exit 1
fi
id -u kunari >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin kunari
install -d -m 0700 -o kunari -g kunari "$PREFIX" "$PREFIX/decoys" "$PREFIX/etc" "$PREFIX/data" "$PREFIX/bin"
install -m 0755 -o root -g root "$BIN_SRC" "$PREFIX/bin/%s"
install -m 0600 -o kunari -g kunari "$ROOT/etc/sentinel.json" "$PREFIX/etc/sentinel.json"
install -m 0600 -o kunari -g kunari "$ROOT/etc/ingest.secret" "$PREFIX/etc/ingest.secret"
install -m 0600 -o kunari -g kunari "$ROOT/decoys/"* "$PREFIX/decoys/"
install -m 0644 "$ROOT/kunari-sentinel.service" /etc/systemd/system/kunari-sentinel.service
systemctl daemon-reload
systemctl enable --now kunari-sentinel.service
echo "installed under $PREFIX; service kunari-sentinel started"
`, prefix, binName, binName, binName)
}

func linuxUnit(prefix, binName string) string {
	cfg := targetJoin("linux", prefix, "etc", "sentinel.json")
	bin := targetJoin("linux", prefix, "bin", binName)
	return fmt.Sprintf(`[Unit]
Description=Kunari sentinel tripwire sensor
After=network.target

[Service]
Type=simple
User=kunari
Group=kunari
UMask=0077
ExecStart=%s sentinel run --config %s
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`, bin, cfg)
}

func darwinInstall(prefix, binName string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
# Kunari agent install (macOS). Authorized use only. Prefer a dedicated operator account.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX="%s"
BIN_SRC="$ROOT/bin/%s"
if [[ ! -f "$BIN_SRC" ]]; then
  echo "error: place %s in $ROOT/bin/ first" >&2
  exit 1
fi
if [[ ! -s "$ROOT/etc/ingest.secret" ]] || grep -q '^#' "$ROOT/etc/ingest.secret"; then
  echo "error: etc/ingest.secret missing or still a placeholder" >&2
  exit 1
fi
install -d -m 0700 "$PREFIX" "$PREFIX/decoys" "$PREFIX/etc" "$PREFIX/data" "$PREFIX/bin"
install -m 0755 "$BIN_SRC" "$PREFIX/bin/%s"
install -m 0600 "$ROOT/etc/sentinel.json" "$PREFIX/etc/sentinel.json"
install -m 0600 "$ROOT/etc/ingest.secret" "$PREFIX/etc/ingest.secret"
install -m 0600 "$ROOT/decoys/"* "$PREFIX/decoys/"
PLIST_DST="/Library/LaunchDaemons/com.jimididit.kunari-sentinel.plist"
install -m 0644 "$ROOT/com.jimididit.kunari-sentinel.plist" "$PLIST_DST"
launchctl bootout system/com.jimididit.kunari-sentinel 2>/dev/null || true
launchctl bootstrap system "$PLIST_DST"
launchctl enable system/com.jimididit.kunari-sentinel
launchctl kickstart -k system/com.jimididit.kunari-sentinel
echo "installed under $PREFIX; launchd job started"
echo "Note: Full Disk Access may be required for stronger macOS tiers."
`, prefix, binName, binName, binName)
}

func darwinPlist(prefix, binName string) string {
	bin := targetJoin("darwin", prefix, "bin", binName)
	cfg := targetJoin("darwin", prefix, "etc", "sentinel.json")
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.jimididit.kunari-sentinel</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>sentinel</string>
    <string>run</string>
    <string>--config</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
`, bin, cfg)
}

func windowsInstall(prefix, binName string) string {
	// PowerShell: copy tree, create service via sc.exe.
	// Avoid backticks in this template - Go raw strings cannot contain them.
	p := strings.ReplaceAll(prefix, `'`, `''`)
	return fmt.Sprintf(`# Kunari agent install (Windows). Run elevated. Authorized use only.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Prefix = '%s'
$BinSrc = Join-Path $Root 'bin\%s'
if (-not (Test-Path -LiteralPath $BinSrc)) {
  throw "Place %s in $Root\bin\ first"
}
$Secret = Join-Path $Root 'etc\ingest.secret'
$secText = Get-Content -LiteralPath $Secret -Raw
if ($secText -match '^\s*#' -or [string]::IsNullOrWhiteSpace($secText)) {
  throw 'etc\ingest.secret missing or still a placeholder'
}
New-Item -ItemType Directory -Force -Path $Prefix, (Join-Path $Prefix 'decoys'), (Join-Path $Prefix 'etc'), (Join-Path $Prefix 'data'), (Join-Path $Prefix 'bin') | Out-Null
Copy-Item -LiteralPath $BinSrc -Destination (Join-Path $Prefix 'bin\%s') -Force
Copy-Item -LiteralPath (Join-Path $Root 'etc\sentinel.json') -Destination (Join-Path $Prefix 'etc\sentinel.json') -Force
Copy-Item -LiteralPath $Secret -Destination (Join-Path $Prefix 'etc\ingest.secret') -Force
Copy-Item -Path (Join-Path $Root 'decoys\*') -Destination (Join-Path $Prefix 'decoys') -Force
$Bin = Join-Path $Prefix 'bin\%s'
$Cfg = Join-Path $Prefix 'etc\sentinel.json'
$svc = Get-Service -Name KunariSentinel -ErrorAction SilentlyContinue
if ($svc) {
  Stop-Service KunariSentinel -Force -ErrorAction SilentlyContinue
  sc.exe delete KunariSentinel | Out-Null
}
$BinPath = '"' + $Bin + '" sentinel run --config "' + $Cfg + '"'
sc.exe create KunariSentinel binPath= $BinPath start= auto | Out-Null
sc.exe description KunariSentinel "Kunari defensive tripwire sensor" | Out-Null
Start-Service KunariSentinel
Write-Host "installed under $Prefix; service KunariSentinel started"
`, p, binName, binName, binName, binName)
}
