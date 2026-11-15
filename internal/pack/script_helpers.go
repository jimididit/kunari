package pack

// unixVisibleShellHelpers is embedded into Linux/Darwin install and uninstall scripts.
// Visible-path writes lock the leaf directory as root for the install window (no user
// symlink plant / predictable temp / root mv into a user-writable name), then restore
// ownership. sentinel.json is patched with jq or sed (no interpreter dependency).
func unixVisibleShellHelpers() string {
	return `
refuse_if_symlink() {
  local p="$1"
  if [[ -L "$p" ]]; then
    echo "error: refusing symlink in visible path: $p" >&2
    exit 1
  fi
}

# Create Documents/<rel> component-by-component; refuse symlinks.
# Leaf directories are left root-owned 0755 until install_visible_decoy finishes.
ensure_visible_dir() {
  local docs_root="$1"
  local rel="$2"
  refuse_if_symlink "$docs_root"
  if [[ ! -d "$docs_root" ]]; then
    install -d -m 0755 "$docs_root"
  fi
  refuse_if_symlink "$docs_root"
  if [[ ! -d "$docs_root" ]]; then
    echo "error: Documents path is not a directory: $docs_root" >&2
    exit 1
  fi
  # Prevent rename-swap of our tree under Documents during the elevated write window.
  chmod u-w "$docs_root" 2>/dev/null || true
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
      install -d -m 0755 -o root -g root "$cur"
      refuse_if_symlink "$cur"
    fi
    chown root:root "$cur"
    chmod 0755 "$cur"
  done
  printf '%%s' "$cur"
}

restore_visible_docs_write() {
  local docs_root="$1"
  local owner="$2"
  local group="$3"
  local leaf="$4"
  if [[ -d "$leaf" && ! -L "$leaf" ]]; then
    chown "$owner:$group" "$leaf" 2>/dev/null || true
  fi
  if [[ -d "$docs_root" && ! -L "$docs_root" ]]; then
    chmod u+w "$docs_root" 2>/dev/null || true
    # Do not chown Documents; only restore owner write.
  fi
}

# Install decoy with no temp name and no mv into a user-writable directory:
# leaf dir is root-owned, so the unprivileged user cannot plant a symlink race.
install_visible_decoy() {
  local src="$1"
  local dest="$2"
  local owner="$3"
  local group="$4"
  local dir
  dir="$(dirname "$dest")"
  refuse_if_symlink "$dir"
  if [[ "$(stat -c '%%u' "$dir" 2>/dev/null || stat -f '%%u' "$dir")" != "0" ]]; then
    chown root:root "$dir"
    chmod 0755 "$dir"
  fi
  if [[ -L "$dest" ]]; then
    echo "error: refusing symlink decoy: $dest" >&2
    exit 1
  fi
  if [[ -e "$dest" ]]; then
    if [[ ! -f "$dest" ]]; then
      echo "error: visible decoy path exists and is not a regular file: $dest" >&2
      exit 1
    fi
    rm -f -- "$dest"
  fi
  # Direct install into root-owned directory (no predictable .tmp, no mv).
  install -m 0600 -o "$owner" -g "$group" "$src" "$dest"
  refuse_if_symlink "$dest"
  if [[ ! -f "$dest" ]]; then
    echo "error: visible decoy is not a regular file after install: $dest" >&2
    exit 1
  fi
}

# setfacl only on verified regular non-symlink paths; inode must be stable.
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
function Lock-VisibleDir([string]$Dir) {
  Assert-NoReparse $Dir
  # Drop inherited / user write for the elevated copy window.
  $null = cmd.exe /c ('icacls "{0}" /inheritance:r >nul' -f $Dir)
  $null = cmd.exe /c ('icacls "{0}" /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" >nul' -f $Dir)
  Assert-NoReparse $Dir
}
function Install-VisibleDecoy([string]$Src, [string]$Dest) {
  $dir = Split-Path -Parent $Dest
  Lock-VisibleDir $dir
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
