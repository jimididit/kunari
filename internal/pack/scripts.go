package pack

import (
	"fmt"
	"strings"
)

func linuxInstall(prefix, binName, unitName, visibleUnder, decoyBase string) string {
	pq := shQuote(prefix)
	bq := shQuote(binName)
	uq := shQuote(unitName)
	vq := shQuote(visibleUnder)
	dq := shQuote(decoyBase)
	helpers := unixVisibleShellHelpers()
	return fmt.Sprintf(`#!/usr/bin/env bash
# Endpoint helper install (Linux).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX=%s
BIN_NAME=%s
UNIT_NAME=%s
VISIBLE_UNDER=%s
DECOY_BASE=%s
UNIT_FILE="$UNIT_NAME.service"
BIN_SRC="$ROOT/bin/$BIN_NAME"
%s
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

WATCH_PATH="$PREFIX/decoys/$DECOY_BASE"
if [[ -n "$VISIBLE_UNDER" ]]; then
  TARGET_USER="$(logname 2>/dev/null || true)"
  if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    TARGET_USER="$(awk -F: '$3>=1000 && $1!="nobody"{print $1; exit}' /etc/passwd)"
  fi
  if [[ -z "$TARGET_USER" ]]; then
    echo "error: could not resolve interactive user for --visible-under" >&2
    exit 1
  fi
  HOME_DIR="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
  if [[ -z "$HOME_DIR" || ! -d "$HOME_DIR" ]]; then
    echo "error: home directory missing for $TARGET_USER" >&2
    exit 1
  fi
  refuse_if_symlink "$HOME_DIR"
  DOCS_ROOT="$HOME_DIR/Documents"
  VISIBLE_DIR="$(ensure_visible_dir "$DOCS_ROOT" "$VISIBLE_UNDER")"
  WATCH_PATH="$VISIBLE_DIR/$DECOY_BASE"
  install_visible_decoy "$ROOT/decoys/$DECOY_BASE" "$WATCH_PATH" "$TARGET_USER" "$TARGET_USER"
  # Grant service user read on the decoy and traverse on parents (Documents homes are often 0700).
  if command -v setfacl >/dev/null 2>&1; then
    cur="$WATCH_PATH"
    while [[ "$cur" != "/" && "$cur" != "$HOME_DIR" ]]; do
      if [[ -e "$cur" ]]; then
        safe_setfacl "$cur" -m "u:kunari:x" || true
      fi
      cur="$(dirname "$cur")"
    done
    safe_setfacl "$HOME_DIR" -m "u:kunari:x" || true
    safe_setfacl "$WATCH_PATH" -m "u:kunari:r" || {
      echo "error: setfacl failed granting kunari read on $WATCH_PATH" >&2
      exit 1
    }
  else
    echo "error: setfacl required for --visible-under on Linux so user kunari can read $WATCH_PATH" >&2
    exit 1
  fi
  restore_visible_docs_write "$DOCS_ROOT" "$TARGET_USER" "$TARGET_USER" "$VISIBLE_DIR"
  PLACEHOLDER="__KUNARI_VISIBLE__/${VISIBLE_UNDER}/${DECOY_BASE}"
  patch_sentinel_watch "$PREFIX/etc/sentinel.json" "$WATCH_PATH" "$PLACEHOLDER"
  chown kunari:kunari "$PREFIX/etc/sentinel.json"
  chmod 0600 "$PREFIX/etc/sentinel.json"
fi

# Remove legacy default unit when operators rename persistence.
if [[ "$UNIT_NAME" != "kunari-sentinel" ]] && [[ -f /etc/systemd/system/kunari-sentinel.service ]]; then
  systemctl disable --now kunari-sentinel.service 2>/dev/null || true
  rm -f /etc/systemd/system/kunari-sentinel.service
fi
install -m 0644 "$ROOT/$UNIT_FILE" "/etc/systemd/system/$UNIT_FILE"
systemctl daemon-reload
systemctl enable --now "$UNIT_FILE"
echo "installed under $PREFIX; service $UNIT_NAME started"
if [[ -n "$VISIBLE_UNDER" ]]; then
  echo "watching visible decoy: $WATCH_PATH"
fi
`, pq, bq, uq, vq, dq, helpers)
}

func linuxUninstall(prefix, binName, unitName, visibleUnder, decoyBase string) string {
	pq := shQuote(prefix)
	bq := shQuote(binName)
	uq := shQuote(unitName)
	vq := shQuote(visibleUnder)
	dq := shQuote(decoyBase)
	helpers := unixVisibleShellHelpers()
	return fmt.Sprintf(`#!/usr/bin/env bash
# Endpoint helper uninstall (Linux).
set -euo pipefail
PREFIX=%s
BIN_NAME=%s
UNIT_NAME=%s
VISIBLE_UNDER=%s
DECOY_BASE=%s
UNIT_FILE="$UNIT_NAME.service"
%s
systemctl disable --now "$UNIT_FILE" 2>/dev/null || true
rm -f "/etc/systemd/system/$UNIT_FILE"
systemctl daemon-reload 2>/dev/null || true
if [[ -n "$VISIBLE_UNDER" ]]; then
  TARGET_USER="$(logname 2>/dev/null || true)"
  if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    TARGET_USER="$(awk -F: '$3>=1000 && $1!="nobody"{print $1; exit}' /etc/passwd)"
  fi
  if [[ -n "$TARGET_USER" ]]; then
    HOME_DIR="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
    if [[ -n "$HOME_DIR" ]]; then
      VIS="$HOME_DIR/Documents/$VISIBLE_UNDER/$DECOY_BASE"
      clear_visible_acls "$VIS"
      clear_visible_acls "$HOME_DIR/Documents/$VISIBLE_UNDER"
      clear_visible_acls "$HOME_DIR/Documents"
      clear_visible_acls "$HOME_DIR"
      safe_rm_visible_file "$VIS"
    fi
  fi
fi
rm -rf "$PREFIX"
echo "uninstalled $UNIT_NAME and removed $PREFIX"
`, pq, bq, uq, vq, dq, helpers)
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

func darwinInstall(prefix, binName, unitName, visibleUnder, decoyBase string) string {
	pq := shQuote(prefix)
	bq := shQuote(binName)
	uq := shQuote(unitName)
	vq := shQuote(visibleUnder)
	dq := shQuote(decoyBase)
	helpers := unixVisibleShellHelpers()
	return fmt.Sprintf(`#!/usr/bin/env bash
# Endpoint helper install (macOS).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX=%s
BIN_NAME=%s
UNIT_NAME=%s
VISIBLE_UNDER=%s
DECOY_BASE=%s
PLIST_SRC="$ROOT/$UNIT_NAME.plist"
BIN_SRC="$ROOT/bin/$BIN_NAME"
%s
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

WATCH_PATH="$PREFIX/decoys/$DECOY_BASE"
if [[ -n "$VISIBLE_UNDER" ]]; then
  TARGET_USER="$(stat -f '%%Su' /dev/console 2>/dev/null || true)"
  if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    TARGET_USER="$(logname 2>/dev/null || true)"
  fi
  if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    echo "error: could not resolve console user for --visible-under" >&2
    exit 1
  fi
  HOME_DIR="$(dscl . -read /Users/"$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
  if [[ -z "$HOME_DIR" ]]; then
    HOME_DIR="/Users/$TARGET_USER"
  fi
  if [[ ! -d "$HOME_DIR" ]]; then
    echo "error: home directory missing for $TARGET_USER" >&2
    exit 1
  fi
  refuse_if_symlink "$HOME_DIR"
  DOCS_ROOT="$HOME_DIR/Documents"
  VISIBLE_DIR="$(ensure_visible_dir "$DOCS_ROOT" "$VISIBLE_UNDER")"
  WATCH_PATH="$VISIBLE_DIR/$DECOY_BASE"
  install_visible_decoy "$ROOT/decoys/$DECOY_BASE" "$WATCH_PATH" "$TARGET_USER" staff
  restore_visible_docs_write "$DOCS_ROOT" "$TARGET_USER" staff "$VISIBLE_DIR"
  PLACEHOLDER="__KUNARI_VISIBLE__/${VISIBLE_UNDER}/${DECOY_BASE}"
  patch_sentinel_watch "$PREFIX/etc/sentinel.json" "$WATCH_PATH" "$PLACEHOLDER"
  chmod 0600 "$PREFIX/etc/sentinel.json"
fi

# Quarantine from a downloaded zip makes launchctl bootstrap fail with I/O error.
xattr -dr com.apple.quarantine "$PREFIX" 2>/dev/null || true
xattr -dr com.apple.quarantine "$ROOT" 2>/dev/null || true
PLIST_DST="/Library/LaunchDaemons/$UNIT_NAME.plist"
if [[ "$UNIT_NAME" != "com.jimididit.kunari-sentinel" ]]; then
  launchctl bootout system/com.jimididit.kunari-sentinel 2>/dev/null || true
  rm -f /Library/LaunchDaemons/com.jimididit.kunari-sentinel.plist
fi
install -m 0644 "$PLIST_SRC" "$PLIST_DST"
xattr -dr com.apple.quarantine "$PLIST_DST" 2>/dev/null || true
launchctl bootout "system/$UNIT_NAME" 2>/dev/null || true
launchctl bootstrap system "$PLIST_DST"
launchctl enable "system/$UNIT_NAME"
launchctl kickstart -k "system/$UNIT_NAME"
echo "installed under $PREFIX; launchd job $UNIT_NAME started"
if [[ -n "$VISIBLE_UNDER" ]]; then
  echo "watching visible decoy: $WATCH_PATH"
fi
echo "Note: Full Disk Access may be required for stronger macOS tiers."
`, pq, bq, uq, vq, dq, helpers)
}

func darwinUninstall(prefix, binName, unitName, visibleUnder, decoyBase string) string {
	pq := shQuote(prefix)
	bq := shQuote(binName)
	uq := shQuote(unitName)
	vq := shQuote(visibleUnder)
	dq := shQuote(decoyBase)
	helpers := unixVisibleShellHelpers()
	return fmt.Sprintf(`#!/usr/bin/env bash
# Endpoint helper uninstall (macOS).
set -euo pipefail
PREFIX=%s
BIN_NAME=%s
UNIT_NAME=%s
VISIBLE_UNDER=%s
DECOY_BASE=%s
PLIST_DST="/Library/LaunchDaemons/$UNIT_NAME.plist"
%s
launchctl bootout "system/$UNIT_NAME" 2>/dev/null || true
rm -f "$PLIST_DST"
if [[ -n "$VISIBLE_UNDER" ]]; then
  TARGET_USER="$(stat -f '%%Su' /dev/console 2>/dev/null || true)"
  if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    TARGET_USER="$(logname 2>/dev/null || true)"
  fi
  if [[ -n "$TARGET_USER" && "$TARGET_USER" != "root" ]]; then
    HOME_DIR="$(dscl . -read /Users/"$TARGET_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    if [[ -z "$HOME_DIR" ]]; then
      HOME_DIR="/Users/$TARGET_USER"
    fi
    safe_rm_visible_file "$HOME_DIR/Documents/$VISIBLE_UNDER/$DECOY_BASE"
  fi
fi
rm -rf "$PREFIX"
echo "uninstalled $UNIT_NAME and removed $PREFIX"
`, pq, bq, uq, vq, dq, helpers)
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

func windowsInstall(prefix, binName, unitName, visibleUnder, decoyBase string) string {
	p := strings.ReplaceAll(prefix, `'`, `''`)
	b := strings.ReplaceAll(binName, `'`, `''`)
	u := strings.ReplaceAll(unitName, `'`, `''`)
	v := strings.ReplaceAll(visibleUnder, `'`, `''`)
	d := strings.ReplaceAll(decoyBase, `'`, `''`)
	helpers := windowsVisiblePSHelpers()
	return fmt.Sprintf(`# Endpoint helper install (Windows). Run elevated.
# Not a Windows Service binary; install uses a SYSTEM scheduled task.
# Prefer ScheduledTasks cmdlets over schtasks.exe under $ErrorActionPreference=Stop.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Prefix = '%s'
$BinName = '%s'
$TaskName = '%s'
$VisibleUnder = '%s'
$DecoyBase = '%s'
$ProcName = [System.IO.Path]::GetFileNameWithoutExtension($BinName)
%s
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

# Restrict package tree to local Administrators + SYSTEM (secrets stay private).
$null = cmd.exe /c ('icacls "{0}" /inheritance:r >nul' -f $Prefix)
$null = cmd.exe /c ('icacls "{0}" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" >nul' -f $Prefix)
$IngestDst = Join-Path $Prefix 'etc\ingest.secret'
$null = cmd.exe /c ('icacls "{0}" /inheritance:r >nul' -f $IngestDst)
$null = cmd.exe /c ('icacls "{0}" /grant:r "SYSTEM:F" "Administrators:F" >nul' -f $IngestDst)

$WatchPath = Join-Path $Prefix ('decoys\' + $DecoyBase)
if ($VisibleUnder -ne '') {
  $console = (Get-CimInstance Win32_ComputerSystem).UserName
  if ([string]::IsNullOrWhiteSpace($console) -or $console -notmatch '\\') {
    throw 'could not resolve interactive user for --visible-under'
  }
  $userSam = $console.Split('\')[-1]
  $userProfile = Join-Path 'C:\Users' $userSam
  if (-not (Test-Path -LiteralPath $userProfile)) {
    throw ("interactive user profile not found: {0}" -f $userProfile)
  }
  Assert-NoReparse $userProfile
  $docsRoot = Join-Path $userProfile 'Documents'
  $VisibleDir = Ensure-VisibleDir $docsRoot $VisibleUnder
  $WatchPath = Join-Path $VisibleDir $DecoyBase
  Install-VisibleDecoy (Join-Path $Root ('decoys\' + $DecoyBase)) $WatchPath
  # Intended user may open/read the decoy; write stays with SYSTEM/Administrators.
  Grant-VisibleUserRead $VisibleDir $WatchPath $console
  $cfgPath = Join-Path $Prefix 'etc\sentinel.json'
  $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
  $cfg.targets[0].path = $WatchPath
  ($cfg | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $cfgPath -Encoding utf8
  # Enable object-access auditing and attach SACL so win-sacl-4663 sees open/read.
  $null = cmd.exe /c 'auditpol /set /subcategory:"File System" /success:enable >nul'
  $acl = Get-Acl -Path $WatchPath -Audit
  $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    'Everyone','ReadData,WriteData,Delete,ReadAttributes','None','None','Success')
  $acl.AddAuditRule($rule)
  Set-Acl -Path $WatchPath -AclObject $acl
}

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
if ($VisibleUnder -ne '') {
  Write-Host ("watching visible decoy: {0}" -f $WatchPath)
}
`, p, b, u, v, d, helpers)
}

func windowsUninstall(prefix, binName, unitName, visibleUnder, decoyBase string) string {
	p := strings.ReplaceAll(prefix, `'`, `''`)
	b := strings.ReplaceAll(binName, `'`, `''`)
	u := strings.ReplaceAll(unitName, `'`, `''`)
	v := strings.ReplaceAll(visibleUnder, `'`, `''`)
	d := strings.ReplaceAll(decoyBase, `'`, `''`)
	helpers := windowsVisiblePSHelpers()
	return fmt.Sprintf(`# Endpoint helper uninstall (Windows). Run elevated.
$ErrorActionPreference = 'Stop'
$Prefix = '%s'
$BinName = '%s'
$TaskName = '%s'
$VisibleUnder = '%s'
$DecoyBase = '%s'
$ProcName = [System.IO.Path]::GetFileNameWithoutExtension($BinName)
%s
foreach ($tn in @($TaskName, 'KunariSentinel') | Select-Object -Unique) {
  if (Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
  }
}
Get-Process -Name $ProcName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$svc = Get-Service -Name KunariSentinel -ErrorAction SilentlyContinue
if ($svc) {
  Stop-Service KunariSentinel -Force -ErrorAction SilentlyContinue
  $null = cmd.exe /c 'sc.exe delete KunariSentinel >nul 2>&1'
}
if ($VisibleUnder -ne '') {
  $console = (Get-CimInstance Win32_ComputerSystem).UserName
  if (-not [string]::IsNullOrWhiteSpace($console) -and $console -match '\\') {
    $userSam = $console.Split('\')[-1]
    $watch = Join-Path (Join-Path (Join-Path 'C:\Users' $userSam) ('Documents\' + $VisibleUnder)) $DecoyBase
    Remove-VisibleDecoy $watch
  }
}
if (Test-Path -LiteralPath $Prefix) {
  Remove-Item -LiteralPath $Prefix -Recurse -Force
}
Write-Host ("uninstalled {0} and removed {1}" -f $TaskName, $Prefix)
`, p, b, u, v, d, helpers)
}
