package pack

import (
	"fmt"
	"strings"
)

func linuxInstall(prefix, binName, unitName string) string {
	pq := shQuote(prefix)
	bq := shQuote(binName)
	uq := shQuote(unitName)
	return fmt.Sprintf(`#!/usr/bin/env bash
# Endpoint helper install (Linux).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX=%s
BIN_NAME=%s
UNIT_NAME=%s
UNIT_FILE="$UNIT_NAME.service"
BIN_SRC="$ROOT/bin/$BIN_NAME"
if [[ ! -f "$BIN_SRC" ]]; then
  echo "error: place $BIN_NAME in $ROOT/bin/ first" >&2
  exit 1
fi
if [[ ! -f "$ROOT/$UNIT_FILE" ]]; then
  echo "error: missing $UNIT_FILE in package root" >&2
  exit 1
fi
if [[ ! -s "$ROOT/etc/ingest.secret" ]] || grep -q '^#' "$ROOT/etc/ingest.secret"; then
  echo "error: etc/ingest.secret missing or still a placeholder" >&2
  exit 1
fi
case "$PREFIX" in
  /home|/home/*|/root|/root/*)
    echo "error: PREFIX=$PREFIX is under a home directory; the kunari service user cannot traverse typical 0700 homes. Use /opt/kunari-agent" >&2
    exit 1
    ;;
esac
id -u kunari >/dev/null 2>&1 || useradd --system --home "$PREFIX" --shell /usr/sbin/nologin kunari
install -d -m 0700 -o kunari -g kunari "$PREFIX" "$PREFIX/decoys" "$PREFIX/etc" "$PREFIX/data" "$PREFIX/bin"
install -m 0755 -o root -g root "$BIN_SRC" "$PREFIX/bin/$BIN_NAME"
install -m 0600 -o kunari -g kunari "$ROOT/etc/sentinel.json" "$PREFIX/etc/sentinel.json"
install -m 0600 -o kunari -g kunari "$ROOT/etc/ingest.secret" "$PREFIX/etc/ingest.secret"
install -m 0600 -o kunari -g kunari "$ROOT/decoys/"* "$PREFIX/decoys/"
# Remove legacy default unit when operators rename persistence.
if [[ "$UNIT_NAME" != "kunari-sentinel" ]] && [[ -f /etc/systemd/system/kunari-sentinel.service ]]; then
  systemctl disable --now kunari-sentinel.service 2>/dev/null || true
  rm -f /etc/systemd/system/kunari-sentinel.service
fi
install -m 0644 "$ROOT/$UNIT_FILE" "/etc/systemd/system/$UNIT_FILE"
systemctl daemon-reload
systemctl enable --now "$UNIT_FILE"
echo "installed under $PREFIX; service $UNIT_NAME started"
`, pq, bq, uq)
}

func linuxUnit(prefix, binName string) string {
	cfg := targetJoin("linux", prefix, "etc", "sentinel.json")
	bin := targetJoin("linux", prefix, "bin", binName)
	return fmt.Sprintf(`[Unit]
Description=Endpoint file helper
After=network.target

[Service]
Type=simple
User=kunari
Group=kunari
UMask=0077
Environment=KUNARI_SENTINEL_CONFIG=%s
ExecStart=%s sentinel run
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`, cfg, bin)
}

func darwinInstall(prefix, binName, unitName string) string {
	pq := shQuote(prefix)
	bq := shQuote(binName)
	uq := shQuote(unitName)
	return fmt.Sprintf(`#!/usr/bin/env bash
# Endpoint helper install (macOS).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX=%s
BIN_NAME=%s
UNIT_NAME=%s
PLIST_SRC="$ROOT/$UNIT_NAME.plist"
BIN_SRC="$ROOT/bin/$BIN_NAME"
if [[ ! -f "$BIN_SRC" ]]; then
  echo "error: place $BIN_NAME in $ROOT/bin/ first" >&2
  exit 1
fi
if [[ ! -f "$PLIST_SRC" ]]; then
  echo "error: missing $UNIT_NAME.plist in package root" >&2
  exit 1
fi
if [[ ! -s "$ROOT/etc/ingest.secret" ]] || grep -q '^#' "$ROOT/etc/ingest.secret"; then
  echo "error: etc/ingest.secret missing or still a placeholder" >&2
  exit 1
fi
install -d -m 0700 "$PREFIX" "$PREFIX/decoys" "$PREFIX/etc" "$PREFIX/data" "$PREFIX/bin"
install -m 0755 "$BIN_SRC" "$PREFIX/bin/$BIN_NAME"
install -m 0600 "$ROOT/etc/sentinel.json" "$PREFIX/etc/sentinel.json"
install -m 0600 "$ROOT/etc/ingest.secret" "$PREFIX/etc/ingest.secret"
install -m 0600 "$ROOT/decoys/"* "$PREFIX/decoys/"
PLIST_DST="/Library/LaunchDaemons/$UNIT_NAME.plist"
if [[ "$UNIT_NAME" != "com.jimididit.kunari-sentinel" ]]; then
  launchctl bootout system/com.jimididit.kunari-sentinel 2>/dev/null || true
  rm -f /Library/LaunchDaemons/com.jimididit.kunari-sentinel.plist
fi
install -m 0644 "$PLIST_SRC" "$PLIST_DST"
launchctl bootout "system/$UNIT_NAME" 2>/dev/null || true
launchctl bootstrap system "$PLIST_DST"
launchctl enable "system/$UNIT_NAME"
launchctl kickstart -k "system/$UNIT_NAME"
echo "installed under $PREFIX; launchd job $UNIT_NAME started"
echo "Note: Full Disk Access may be required for stronger macOS tiers."
`, pq, bq, uq)
}

func darwinPlist(prefix, binName, unitName string) string {
	bin := targetJoin("darwin", prefix, "bin", binName)
	cfg := targetJoin("darwin", prefix, "etc", "sentinel.json")
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>KUNARI_SENTINEL_CONFIG</key>
    <string>%s</string>
  </dict>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>sentinel</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
`, unitName, cfg, bin)
}

func windowsInstall(prefix, binName, unitName string) string {
	p := strings.ReplaceAll(prefix, `'`, `''`)
	b := strings.ReplaceAll(binName, `'`, `''`)
	u := strings.ReplaceAll(unitName, `'`, `''`)
	return fmt.Sprintf(`# Endpoint helper install (Windows). Run elevated.
# Not a Windows Service binary; install uses a SYSTEM scheduled task.
# Prefer ScheduledTasks cmdlets over schtasks.exe under $ErrorActionPreference=Stop.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Prefix = '%s'
$BinName = '%s'
$TaskName = '%s'
$ProcName = [System.IO.Path]::GetFileNameWithoutExtension($BinName)
$BinSrc = Join-Path $Root ('bin\' + $BinName)
if (-not (Test-Path -LiteralPath $BinSrc)) {
  throw ("Place {0} in {1}\bin\ first" -f $BinName, $Root)
}
$Secret = Join-Path $Root 'etc\ingest.secret'
$secText = Get-Content -LiteralPath $Secret -Raw
if ($secText -match '^\s*#' -or [string]::IsNullOrWhiteSpace($secText)) {
  throw 'etc\ingest.secret missing or still a placeholder'
}

# Stop prior lab installs (legacy sc.exe service and/or scheduled task) before replacing binaries.
$svc = Get-Service -Name KunariSentinel -ErrorAction SilentlyContinue
if ($svc) {
  Stop-Service KunariSentinel -Force -ErrorAction SilentlyContinue
  $null = cmd.exe /c 'sc.exe delete KunariSentinel >nul 2>&1'
  Start-Sleep -Seconds 1
}
foreach ($tn in @($TaskName, 'KunariSentinel') | Select-Object -Unique) {
  if (Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
  }
}
Get-Process -Name $ProcName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force -Path $Prefix, (Join-Path $Prefix 'decoys'), (Join-Path $Prefix 'etc'), (Join-Path $Prefix 'data'), (Join-Path $Prefix 'bin') | Out-Null
Copy-Item -LiteralPath $BinSrc -Destination (Join-Path $Prefix ('bin\' + $BinName)) -Force
Copy-Item -LiteralPath (Join-Path $Root 'etc\sentinel.json') -Destination (Join-Path $Prefix 'etc\sentinel.json') -Force
Copy-Item -LiteralPath $Secret -Destination (Join-Path $Prefix 'etc\ingest.secret') -Force
Copy-Item -Path (Join-Path $Root 'decoys\*') -Destination (Join-Path $Prefix 'decoys') -Force

# Restrict package tree to local Administrators + SYSTEM.
$null = cmd.exe /c ('icacls "{0}" /inheritance:r >nul' -f $Prefix)
$null = cmd.exe /c ('icacls "{0}" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" >nul' -f $Prefix)
$IngestDst = Join-Path $Prefix 'etc\ingest.secret'
$null = cmd.exe /c ('icacls "{0}" /inheritance:r >nul' -f $IngestDst)
$null = cmd.exe /c ('icacls "{0}" /grant:r "SYSTEM:F" "Administrators:F" >nul' -f $IngestDst)

$Bin = Join-Path $Prefix ('bin\' + $BinName)
$Cfg = Join-Path $Prefix 'etc\sentinel.json'
# Wrapper sets KUNARI_SENTINEL_CONFIG so process argv omits the config path.
$Runner = Join-Path $Prefix 'bin\run-sentinel.cmd'
@(
  '@echo off'
  ('set "KUNARI_SENTINEL_CONFIG={0}"' -f $Cfg)
  ('"{0}" sentinel run' -f $Bin)
) | Set-Content -LiteralPath $Runner -Encoding ascii
$action = New-ScheduledTaskAction -Execute $Runner
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2
if (-not (Get-Process -Name $ProcName -ErrorAction SilentlyContinue)) {
  throw ("scheduled task {0} was created but process {1} is not running; check Task Scheduler history" -f $TaskName, $ProcName)
}
Write-Host "installed under $Prefix; scheduled task $TaskName started (SYSTEM, AtStartup)"
`, p, b, u)
}
