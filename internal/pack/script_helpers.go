package pack

// unixVisibleShellHelpers is embedded into Linux/Darwin install and uninstall scripts.
// Visible decoys are created/copied as the interactive user (no root/SYSTEM write
// into a user-writable tree). Linux grants the service read via setfacl run as the
// owner. Windows SACL is applied by the sentinel at startup, not by install.
// sentinel.json patches require jq.
func unixVisibleShellHelpers() string {
	// NOTE: this string is inserted via fmt %s and is NOT re-parsed as a format
	// string, so keep single "%" for shell printf/stat formats.
	return `
refuse_if_symlink() {
  local p="$1"
  if [[ -L "$p" ]]; then
    echo "error: refusing symlink in visible path: $p" >&2
    exit 1
  fi
}

run_as_user() {
  local user="$1"
  shift
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$user" -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "$user" -- "$@"
  else
    echo "error: need runuser or sudo to install visible decoy as $user" >&2
    exit 1
  fi
}

# Create Documents/<rel> as the interactive user; refuse symlink components.
ensure_visible_dir() {
  local docs_root="$1"
  local rel="$2"
  local owner="$3"
  refuse_if_symlink "$docs_root"
  if [[ ! -d "$docs_root" ]]; then
    run_as_user "$owner" mkdir -p "$docs_root"
  fi
  refuse_if_symlink "$docs_root"
  if [[ ! -d "$docs_root" ]]; then
    echo "error: Documents path is not a directory: $docs_root" >&2
    exit 1
  fi
  local cur="$docs_root"
  local IFS='/'
  local -a parts
  read -r -a parts <<< "$rel"
  local p
  for p in "${parts[@]}"; do
    [[ -n "$p" ]] || continue
    cur="$cur/$p"
    if [[ -e "$cur" || -L "$cur" ]]; then
      refuse_if_symlink "$cur"
      if [[ ! -d "$cur" ]]; then
        echo "error: not a directory: $cur" >&2
        exit 1
      fi
    else
      run_as_user "$owner" mkdir -p "$cur"
      refuse_if_symlink "$cur"
    fi
  done
  printf '%s' "$cur"
}

# Copy decoy as the interactive user (no root write into the user tree).
install_visible_decoy() {
  local src="$1"
  local dest="$2"
  local owner="$3"
  local dir
  dir="$(dirname "$dest")"
  refuse_if_symlink "$dir"
  case "$dest" in
    "$dir"/*) ;;
    *)
      echo "error: decoy path escapes parent dir" >&2
      exit 1
      ;;
  esac
  chmod a+r "$src" 2>/dev/null || true
  # Single user-owned shell avoids check/cp races following a swapped symlink dest.
  run_as_user "$owner" bash -c '
    set -euo pipefail
    dest="$1"
    src="$2"
    if [[ -L "$dest" ]]; then
      echo "error: refusing symlink decoy: $dest" >&2
      exit 1
    fi
    if [[ -e "$dest" && ! -f "$dest" ]]; then
      echo "error: visible decoy path exists and is not a regular file: $dest" >&2
      exit 1
    fi
    tmp="${dest}.kunari.new.$$"
    cp -f -- "$src" "$tmp"
    if [[ -L "$dest" ]]; then
      rm -f -- "$tmp"
      echo "error: refusing symlink decoy: $dest" >&2
      exit 1
    fi
    mv -f -- "$tmp" "$dest"
    if [[ -L "$dest" || ! -f "$dest" ]]; then
      echo "error: visible decoy is not a regular file after install: $dest" >&2
      exit 1
    fi
    chmod 600 -- "$dest"
  ' bash "$dest" "$src"
}

# Owner-applied ACL so kunari can read/traverse without root setfacl or group join.
grant_kunari_acl_as_user() {
  local owner="$1"
  local home_dir="$2"
  local watch_path="$3"
  if ! command -v setfacl >/dev/null 2>&1; then
    echo "error: setfacl required for --visible-under on Linux" >&2
    exit 1
  fi
  refuse_if_symlink "$watch_path"
  run_as_user "$owner" setfacl -m "u:kunari:r" "$watch_path"
  local cur
  cur="$(dirname "$watch_path")"
  while [[ "$cur" != "/" && "$cur" != "$home_dir" ]]; do
    refuse_if_symlink "$cur"
    run_as_user "$owner" setfacl -m "u:kunari:x" "$cur" || true
    cur="$(dirname "$cur")"
  done
  refuse_if_symlink "$home_dir"
  run_as_user "$owner" setfacl -m "u:kunari:x" "$home_dir" || true
  if [[ -d "$home_dir/Documents" ]]; then
    refuse_if_symlink "$home_dir/Documents"
    run_as_user "$owner" setfacl -m "u:kunari:x" "$home_dir/Documents" || true
  fi
}

# Elevated uninstall: walk docs_root/rel, refuse symlink components, delete as the user.
safe_rm_visible_file() {
  local owner="$1"
  local docs_root="$2"
  local rel="$3"
  if [[ -z "$owner" || -z "$docs_root" || -z "$rel" ]]; then
    return 0
  fi
  if [[ -L "$docs_root" || ! -d "$docs_root" ]]; then
    echo "warning: skipping visible uninstall; Documents path unsafe: $docs_root" >&2
    return 0
  fi
  local cur="$docs_root"
  local IFS='/'
  local -a parts
  read -r -a parts <<< "$rel"
  local p
  for p in "${parts[@]}"; do
    [[ -n "$p" ]] || continue
    cur="$cur/$p"
    if [[ -L "$cur" ]]; then
      echo "warning: skipping symlink in visible path (not removing): $cur" >&2
      return 0
    fi
  done
  if [[ -f "$cur" ]]; then
    run_as_user "$owner" rm -f -- "$cur"
    return 0
  fi
  if [[ -e "$cur" ]]; then
    echo "warning: skipping non-regular visible path: $cur" >&2
  fi
}

# Replace packaged __KUNARI_VISIBLE__ placeholder with the real watch path (jq required).
patch_sentinel_watch() {
  local cfg="$1"
  local watch="$2"
  local placeholder="$3"
  if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required to patch sentinel.json for --visible-under" >&2
    exit 1
  fi
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/kunari-sentinel.XXXXXX")"
  if ! jq --arg p "$watch" '.targets[0].path = $p' "$cfg" >"$tmp"; then
    rm -f "$tmp"
    echo "error: jq failed patching sentinel.json" >&2
    exit 1
  fi
  if [[ ! -s "$tmp" ]] || ! grep -Fq "$watch" "$tmp"; then
    rm -f "$tmp"
    echo "error: failed to patch sentinel.json watch path" >&2
    exit 1
  fi
  # Keep ownership/mode by writing through the existing inode.
  cat "$tmp" >"$cfg"
  rm -f "$tmp"
}
`
}

// windowsVisiblePSHelpers is embedded into Windows install/uninstall scripts.
// Visible decoy create/copy/delete runs as the interactive user via a one-shot
// scheduled task so SYSTEM never write-races through a user-writable tree.
func windowsVisiblePSHelpers() string {
	return `
function Assert-NoReparse([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw ("refusing reparse point (symlink/junction): {0}" -f $Path)
  }
}
function Resolve-InteractiveProfile([string]$ConsoleUser) {
  if ([string]::IsNullOrWhiteSpace($ConsoleUser) -or $ConsoleUser -notmatch '\\') {
    throw 'could not resolve interactive user for --visible-under'
  }
  $account = New-Object System.Security.Principal.NTAccount($ConsoleUser)
  $sid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
  $profileKey = Join-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' $sid
  if (-not (Test-Path -LiteralPath $profileKey)) {
    throw ("profile list entry missing for {0} ({1})" -f $ConsoleUser, $sid)
  }
  $userProfile = (Get-ItemProperty -LiteralPath $profileKey).ProfileImagePath
  if ([string]::IsNullOrWhiteSpace($userProfile) -or -not (Test-Path -LiteralPath $userProfile)) {
    throw ("interactive user profile not found for {0}: {1}" -f $ConsoleUser, $userProfile)
  }
  Assert-NoReparse $userProfile
  return $userProfile
}
function Invoke-AsInteractiveUser([string]$User, [string]$ScriptBody) {
  $tmpPs1 = Join-Path $env:TEMP ('kunari-vis-' + [guid]::NewGuid().ToString('N') + '.ps1')
  $taskName = 'KunariVisible-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
  $utf8 = New-Object System.Text.UTF8Encoding $false
  [System.IO.File]::WriteAllText($tmpPs1, $ScriptBody, $utf8)
  # SYSTEM-created temp files are often unreadable by the interactive user.
  $null = cmd.exe /c ('icacls "{0}" /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" "Authenticated Users:R" >nul' -f $tmpPs1)
  try {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $tmpPs1 + '"')
    $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(60)
    do {
      Start-Sleep -Milliseconds 200
      $info = Get-ScheduledTaskInfo -TaskName $taskName
    } while ($info.LastTaskResult -eq 267009 -and (Get-Date) -lt $deadline)
    $info = Get-ScheduledTaskInfo -TaskName $taskName
    if ($info.LastTaskResult -ne 0) {
      throw ("interactive user task failed with code {0}" -f $info.LastTaskResult)
    }
  } finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpPs1 -Force -ErrorAction SilentlyContinue
  }
}
function Ensure-VisibleDir([string]$DocumentsRoot, [string]$Rel, [string]$User) {
  Assert-NoReparse $DocumentsRoot
  $dir = Join-Path $DocumentsRoot (($Rel -replace '/', '\'))
  $dirLit = $dir.Replace("'", "''")
  $scriptBody = @(
    '$ErrorActionPreference = ''Stop'''
    ('New-Item -ItemType Directory -Force -Path ''{0}'' | Out-Null' -f $dirLit)
  ) -join [Environment]::NewLine
  Invoke-AsInteractiveUser $User $scriptBody
  # Reject reparse points on Documents and every intermediate component.
  Assert-NoReparse $DocumentsRoot
  $cur = $DocumentsRoot
  foreach ($part in ($Rel -split '[\\/]+')) {
    if ([string]::IsNullOrWhiteSpace($part)) { continue }
    $cur = Join-Path $cur $part
    Assert-NoReparse $cur
    $it = Get-Item -LiteralPath $cur -Force
    if (-not $it.PSIsContainer) { throw ("not a directory: {0}" -f $cur) }
  }
  if (-not (Test-Path -LiteralPath $dir)) {
    throw ("visible directory was not created: {0}" -f $dir)
  }
  return $dir
}
function Install-VisibleDecoy([string]$Src, [string]$Dest, [string]$User) {
  $dir = Split-Path -Parent $Dest
  Assert-NoReparse $dir
  $srcLit = $Src.Replace("'", "''")
  $destLit = $Dest.Replace("'", "''")
  $dirLit = $dir.Replace("'", "''")
  $scriptBody = @(
    '$ErrorActionPreference = ''Stop'''
    ('New-Item -ItemType Directory -Force -Path ''{0}'' | Out-Null' -f $dirLit)
    ('if (Test-Path -LiteralPath ''{0}'') {{' -f $destLit)
    ('  $item = Get-Item -LiteralPath ''{0}'' -Force' -f $destLit)
    '  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ''refusing reparse decoy destination'' }'
    '  if ($item.PSIsContainer) { throw ''decoy destination is a directory'' }'
    ('  Remove-Item -LiteralPath ''{0}'' -Force' -f $destLit)
    '}'
    ('Copy-Item -LiteralPath ''{0}'' -Destination ''{1}'' -Force' -f $srcLit, $destLit)
  ) -join [Environment]::NewLine
  Invoke-AsInteractiveUser $User $scriptBody
  Assert-NoReparse $Dest
  if (-not (Test-Path -LiteralPath $Dest)) {
    throw ("visible decoy was not installed: {0}" -f $Dest)
  }
}
function Remove-VisibleDecoy([string]$DocumentsRoot, [string]$RelFile, [string]$User) {
  if ([string]::IsNullOrWhiteSpace($DocumentsRoot) -or [string]::IsNullOrWhiteSpace($RelFile)) { return }
  if (-not (Test-Path -LiteralPath $DocumentsRoot)) { return }
  Assert-NoReparse $DocumentsRoot
  $target = Join-Path $DocumentsRoot (($RelFile -replace '/', '\'))
  if (-not (Test-Path -LiteralPath $target)) { return }
  Assert-NoReparse $target
  $targetLit = $target.Replace("'", "''")
  $scriptBody = @(
    '$ErrorActionPreference = ''Stop'''
    ('if (Test-Path -LiteralPath ''{0}'') {{' -f $targetLit)
    ('  $item = Get-Item -LiteralPath ''{0}'' -Force' -f $targetLit)
    '  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ''refusing reparse decoy delete'' }'
    '  if ($item.PSIsContainer) { throw ''refusing to delete directory'' }'
    ('  Remove-Item -LiteralPath ''{0}'' -Force' -f $targetLit)
    '}'
  ) -join [Environment]::NewLine
  Invoke-AsInteractiveUser $User $scriptBody
}
`
}
