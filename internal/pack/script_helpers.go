package pack

// unixVisibleShellHelpers is embedded into Linux/Darwin install and uninstall scripts.
// Visible decoys are created/copied as the interactive user (no root chown/mv/setfacl
// into a user-writable tree). Linux grants the service access via the owner's group +
// systemd SupplementaryGroups. sentinel.json is patched with jq or sed.
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
  printf '%%s' "$cur"
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
  chmod a+r "$src" 2>/dev/null || true
  run_as_user "$owner" cp -f "$src" "$dest"
  run_as_user "$owner" chmod 600 "$dest"
  refuse_if_symlink "$dest"
  if [[ ! -f "$dest" ]]; then
    echo "error: visible decoy is not a regular file after install: $dest" >&2
    exit 1
  fi
}

# Allow service user (via owner's group) to traverse parents and read the decoy.
grant_group_read_path() {
  local owner="$1"
  local home_dir="$2"
  local watch_path="$3"
  refuse_if_symlink "$watch_path"
  run_as_user "$owner" chmod g+r "$watch_path"
  local cur
  cur="$(dirname "$watch_path")"
  while [[ "$cur" != "/" && "$cur" != "$home_dir" ]]; do
    refuse_if_symlink "$cur"
    run_as_user "$owner" chmod g+x "$cur" || true
    cur="$(dirname "$cur")"
  done
  refuse_if_symlink "$home_dir"
  run_as_user "$owner" chmod g+x "$home_dir" || true
  if [[ -d "$home_dir/Documents" ]]; then
    refuse_if_symlink "$home_dir/Documents"
    run_as_user "$owner" chmod g+x "$home_dir/Documents" || true
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

# Replace packaged __KUNARI_VISIBLE__ placeholder with the real watch path.
# Writes through the existing inode when possible so ownership/mode stay intact.
patch_sentinel_watch() {
  local cfg="$1"
  local watch="$2"
  local placeholder="$3"
  local tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/kunari-sentinel.XXXXXX")"
  if command -v jq >/dev/null 2>&1; then
    if ! jq --arg p "$watch" '.targets[0].path = $p' "$cfg" >"$tmp"; then
      rm -f "$tmp"
      echo "error: jq failed patching sentinel.json" >&2
      exit 1
    fi
  else
    local esc="$watch"
    esc="${esc//\\/\\\\}"
    esc="${esc//\"/\\\"}"
    # shellcheck disable=SC2001
    if ! sed "s|${placeholder}|${esc}|g" "$cfg" >"$tmp"; then
      rm -f "$tmp"
      echo "error: sed failed patching sentinel.json" >&2
      exit 1
    fi
  fi
  if [[ ! -s "$tmp" ]] || ! grep -Fq "$watch" "$tmp"; then
    rm -f "$tmp"
    echo "error: failed to patch sentinel.json watch path (install jq for reliable JSON edits)" >&2
    exit 1
  fi
  if [[ -f "$cfg" ]]; then
    cat "$tmp" >"$cfg"
    rm -f "$tmp"
  else
    mv "$tmp" "$cfg"
  fi
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
function Install-VisibleDecoy([string]$Src, [string]$Dest, [string]$User, [string]$DocumentsRoot) {
  $dir = Split-Path -Parent $Dest
  # Lock Documents as well so the leaf cannot be rename-swapped for a junction mid-copy.
  if (-not [string]::IsNullOrWhiteSpace($DocumentsRoot)) {
    Lock-VisibleDir $DocumentsRoot $User
  }
  Lock-VisibleDir $dir $User
  if (Test-Path -LiteralPath $Dest) {
    Assert-NoReparse $Dest
    $existing = Get-Item -LiteralPath $Dest -Force
    if ($existing.PSIsContainer) { throw ("visible decoy path is a directory: {0}" -f $Dest) }
    Remove-Item -LiteralPath $Dest -Force
  }
  Assert-NoReparse $dir
  # Direct copy into the locked directory (no predictable temp name in the user tree).
  Copy-Item -LiteralPath $Src -Destination $Dest -Force
  Assert-NoReparse $Dest
}
function Grant-VisibleUserRead([string]$DocumentsRoot, [string]$Dir, [string]$File, [string]$User) {
  if (-not [string]::IsNullOrWhiteSpace($DocumentsRoot)) {
    $null = cmd.exe /c ('icacls "{0}" /grant:r "{1}:(RX)" >nul' -f $DocumentsRoot, $User)
  }
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
