package pack

// unixVisibleShellHelpers is embedded into Linux/Darwin install and uninstall scripts.
// Visible decoys are created/copied as the interactive user (no root chown/mv into a
// user-writable tree). setfacl still runs as root with symlink + inode checks.
// sentinel.json is patched with jq or sed (no interpreter dependency).
func unixVisibleShellHelpers() string {
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
  # Block rename-swap of our tree under Documents during elevated ACL work.
  chmod u-w "$docs_root" 2>/dev/null || true
  printf '%%s' "$cur"
}

restore_docs_write() {
  local docs_root="$1"
  if [[ -d "$docs_root" && ! -L "$docs_root" ]]; then
    chmod u+w "$docs_root" 2>/dev/null || true
  fi
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
  if [[ -L "$dest" ]]; then
    echo "error: refusing symlink decoy: $dest" >&2
    exit 1
  fi
  if [[ -e "$dest" && ! -f "$dest" ]]; then
    echo "error: visible decoy path exists and is not a regular file: $dest" >&2
    exit 1
  fi
  # Ensure the package decoy is readable by the target user for this copy.
  chmod a+r "$src" 2>/dev/null || true
  run_as_user "$owner" cp -f "$src" "$dest"
  run_as_user "$owner" chmod 600 "$dest"
  refuse_if_symlink "$dest"
  if [[ ! -f "$dest" ]]; then
    echo "error: visible decoy is not a regular file after install: $dest" >&2
    exit 1
  fi
}

# setfacl only on verified regular/dir non-symlink paths; inode must be stable.
safe_setfacl() {
  local path="$1"
  shift
  refuse_if_symlink "$path"
  if [[ ! -e "$path" ]]; then
    echo "error: setfacl target missing: $path" >&2
    exit 1
  fi
  local before after
  if before="$(stat -c '%%d:%%i' "$path" 2>/dev/null)"; then
    :
  else
    before="$(stat -f '%%d:%%i' "$path")"
  fi
  setfacl "$@" "$path"
  refuse_if_symlink "$path"
  if after="$(stat -c '%%d:%%i' "$path" 2>/dev/null)"; then
    :
  else
    after="$(stat -f '%%d:%%i' "$path")"
  fi
  if [[ "$before" != "$after" ]]; then
    echo "error: setfacl target changed during update: $path" >&2
    exit 1
  fi
}

# Elevated uninstall: only remove a regular non-symlink file.
safe_rm_visible_file() {
  local target="$1"
  if [[ -L "$target" ]]; then
    echo "warning: skipping symlink (not removing): $target" >&2
    return 0
  fi
  if [[ -f "$target" ]]; then
    rm -f -- "$target"
    return 0
  fi
  if [[ -e "$target" ]]; then
    echo "warning: skipping non-regular visible path: $target" >&2
  fi
}

clear_visible_acls() {
  local path="$1"
  if [[ -e "$path" && ! -L "$path" ]] && command -v setfacl >/dev/null 2>&1; then
    setfacl -x "u:kunari" "$path" 2>/dev/null || true
  fi
}

# Replace packaged __KUNARI_VISIBLE__ placeholder with the real watch path.
patch_sentinel_watch() {
  local cfg="$1"
  local watch="$2"
  local placeholder="$3"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/kunari-sentinel.XXXXXX")"
  if command -v jq >/dev/null 2>&1; then
    jq --arg p "$watch" '.targets[0].path = $p' "$cfg" >"$tmp"
    mv "$tmp" "$cfg"
    return 0
  fi
  local esc="$watch"
  esc="${esc//\\/\\\\}"
  esc="${esc//\"/\\\"}"
  # shellcheck disable=SC2001
  sed "s|${placeholder}|${esc}|g" "$cfg" >"$tmp"
  if ! grep -Fq "$watch" "$tmp"; then
    rm -f "$tmp"
    echo "error: failed to patch sentinel.json watch path (install jq for reliable JSON edits)" >&2
    exit 1
  fi
  mv "$tmp" "$cfg"
}
`
}

// windowsVisiblePSHelpers is embedded into Windows install/uninstall scripts.
func windowsVisiblePSHelpers() string {
	return `
function Assert-NoReparse([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw ("refusing reparse point (symlink/junction): {0}" -f $Path)
  }
}
function Ensure-VisibleDir([string]$DocumentsRoot, [string]$Rel) {
  if (-not (Test-Path -LiteralPath $DocumentsRoot)) {
    New-Item -ItemType Directory -Force -Path $DocumentsRoot | Out-Null
  }
  Assert-NoReparse $DocumentsRoot
  $cur = $DocumentsRoot
  foreach ($part in ($Rel -split '[\\/]+')) {
    if ([string]::IsNullOrWhiteSpace($part)) { continue }
    $cur = Join-Path $cur $part
    if (Test-Path -LiteralPath $cur) {
      Assert-NoReparse $cur
      $it = Get-Item -LiteralPath $cur -Force
      if (-not $it.PSIsContainer) { throw ("not a directory: {0}" -f $cur) }
    } else {
      New-Item -ItemType Directory -Force -Path $cur | Out-Null
      Assert-NoReparse $cur
    }
  }
  return $cur
}
function Lock-VisibleDir([string]$Dir, [string]$User) {
  Assert-NoReparse $Dir
  # Disable inheritance and drop explicit grants so lingering write ACEs cannot race the copy.
  $null = cmd.exe /c ('icacls "{0}" /inheritance:r >nul' -f $Dir)
  if (-not [string]::IsNullOrWhiteSpace($User)) {
    $null = cmd.exe /c ('icacls "{0}" /remove:g "{1}" >nul' -f $Dir, $User)
  }
  foreach ($acct in @('Users', 'Authenticated Users', 'Everyone')) {
    $null = cmd.exe /c ('icacls "{0}" /remove:g "{1}" >nul' -f $Dir, $acct)
  }
  $null = cmd.exe /c ('icacls "{0}" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" >nul' -f $Dir)
  Assert-NoReparse $Dir
}
function Install-VisibleDecoy([string]$Src, [string]$Dest, [string]$User) {
  $dir = Split-Path -Parent $Dest
  Lock-VisibleDir $dir $User
  if (Test-Path -LiteralPath $Dest) {
    Assert-NoReparse $Dest
    $existing = Get-Item -LiteralPath $Dest -Force
    if ($existing.PSIsContainer) { throw ("visible decoy path is a directory: {0}" -f $Dest) }
    Remove-Item -LiteralPath $Dest -Force
  }
  # Direct copy into the locked directory (no predictable temp name in the user tree).
  Copy-Item -LiteralPath $Src -Destination $Dest -Force
  Assert-NoReparse $Dest
}
function Grant-VisibleUserRead([string]$Dir, [string]$File, [string]$User) {
  $null = cmd.exe /c ('icacls "{0}" /grant:r "{1}:(RX)" >nul' -f $Dir, $User)
  $null = cmd.exe /c ('icacls "{0}" /inheritance:r >nul' -f $File)
  $null = cmd.exe /c ('icacls "{0}" /grant:r "SYSTEM:F" "Administrators:F" "{1}:(R)" >nul' -f $File, $User)
  Assert-NoReparse $File
}
function Remove-VisibleDecoy([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    Write-Host ("warning: skipping reparse point (not removing): {0}" -f $Path)
    return
  }
  if ($item.PSIsContainer) {
    Write-Host ("warning: skipping directory (not removing): {0}" -f $Path)
    return
  }
  Remove-Item -LiteralPath $Path -Force
}
`
}
