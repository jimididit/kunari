package pack

// unixVisibleShellHelpers is embedded into Linux/Darwin install and uninstall scripts.
// It refuses symlink components under the user's Documents tree and patches sentinel.json
// with jq when available, otherwise a sed placeholder replace (no interpreter dependency).
func unixVisibleShellHelpers() string {
	return `
refuse_if_symlink() {
  local p="$1"
  if [[ -L "$p" ]]; then
    echo "error: refusing symlink in visible path: $p" >&2
    exit 1
  fi
}

# Create Documents/<rel> component-by-component; refuse symlinks/junctions (TOCTOU hardening).
ensure_visible_dir() {
  local docs_root="$1"
  local rel="$2"
  local owner="$3"
  local group="$4"
  refuse_if_symlink "$docs_root"
  if [[ ! -d "$docs_root" ]]; then
    install -d -m 0755 -o "$owner" -g "$group" "$docs_root"
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
      install -d -m 0755 -o "$owner" -g "$group" "$cur"
      refuse_if_symlink "$cur"
    fi
  done
  printf '%%s' "$cur"
}

# Install decoy as a regular file only (no symlink replace / follow).
install_visible_decoy() {
  local src="$1"
  local dest="$2"
  local owner="$3"
  local group="$4"
  if [[ -e "$dest" || -L "$dest" ]]; then
    refuse_if_symlink "$dest"
    if [[ ! -f "$dest" ]]; then
      echo "error: visible decoy path exists and is not a regular file: $dest" >&2
      exit 1
    fi
  fi
  local tmp="${dest}.kunari.tmp.$$"
  install -m 0600 -o "$owner" -g "$group" "$src" "$tmp"
  if [[ -L "$dest" ]]; then
    rm -f "$tmp"
    echo "error: refusing symlink decoy: $dest" >&2
    exit 1
  fi
  mv -f "$tmp" "$dest"
  refuse_if_symlink "$dest"
  if [[ ! -f "$dest" ]]; then
    echo "error: visible decoy is not a regular file after install: $dest" >&2
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
    rm -f "$target"
    return 0
  fi
  if [[ -e "$target" ]]; then
    echo "warning: skipping non-regular visible path: $target" >&2
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
  # Placeholder is packager-validated (no sed metacharacters beyond /).
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
function Install-VisibleDecoy([string]$Src, [string]$Dest) {
  if (Test-Path -LiteralPath $Dest) {
    Assert-NoReparse $Dest
    $existing = Get-Item -LiteralPath $Dest -Force
    if ($existing.PSIsContainer) { throw ("visible decoy path is a directory: {0}" -f $Dest) }
  }
  $tmp = "$Dest.kunari.tmp"
  Copy-Item -LiteralPath $Src -Destination $tmp -Force
  if (Test-Path -LiteralPath $Dest) { Assert-NoReparse $Dest }
  Move-Item -LiteralPath $tmp -Destination $Dest -Force
  Assert-NoReparse $Dest
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
