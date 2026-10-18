package pack

import (
	"fmt"
	"strings"
)

func linuxInstall(prefix, binName string) string {
	pq := shQuote(prefix)
	bq := shQuote(binName)
	return fmt.Sprintf(`#!/usr/bin/env bash
# Kunari agent install (Linux). Authorized use only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX=%s
BIN_NAME=%s
BIN_SRC="$ROOT/bin/$BIN_NAME"
if [[ ! -f "$BIN_SRC" ]]; then
  echo "error: place $BIN_NAME in $ROOT/bin/ first" >&2
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
install -m 0644 "$ROOT/kunari-sentinel.service" /etc/systemd/system/kunari-sentinel.service
systemctl daemon-reload
systemctl enable --now kunari-sentinel.service
echo "installed under $PREFIX; service kunari-sentinel started"
`, pq, bq)
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
	pq := shQuote(prefix)
	bq := shQuote(binName)
	return fmt.Sprintf(`#!/usr/bin/env bash
# Kunari agent install (macOS). Authorized use only. Prefer a dedicated operator account.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX=%s
BIN_NAME=%s
BIN_SRC="$ROOT/bin/$BIN_NAME"
if [[ ! -f "$BIN_SRC" ]]; then
  echo "error: place $BIN_NAME in $ROOT/bin/ first" >&2
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
PLIST_DST="/Library/LaunchDaemons/com.jimididit.kunari-sentinel.plist"
install -m 0644 "$ROOT/com.jimididit.kunari-sentinel.plist" "$PLIST_DST"
launchctl bootout system/com.jimididit.kunari-sentinel 2>/dev/null || true
launchctl bootstrap system "$PLIST_DST"
launchctl enable system/com.jimididit.kunari-sentinel
launchctl kickstart -k system/com.jimididit.kunari-sentinel
echo "installed under $PREFIX; launchd job started"
echo "Note: Full Disk Access may be required for stronger macOS tiers."
`, pq, bq)
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
	p := strings.ReplaceAll(prefix, `'`, `''`)
	return fmt.Sprintf(`# Kunari agent install (Windows). Run elevated. Authorized use only.
# kunari.exe is not a Windows Service binary; install uses a SYSTEM scheduled task.
# Prefer ScheduledTasks cmdlets over schtasks.exe to avoid native stderr/quote pitfalls under $ErrorActionPreference=Stop.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Prefix = '%s'
$BinName = '%s'
$TaskName = 'KunariSentinel'
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
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
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
$action = New-ScheduledTaskAction -Execute $Bin -Argument ('sentinel run --config "{0}"' -f $Cfg)
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
`, p, binName)
}
