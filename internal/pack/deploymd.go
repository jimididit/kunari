package pack

import "fmt"

func deployMarkdown(goos, prefix, binName, unitName, decoyBase, detect, visibleUnder string) string {
	warn := ""
	switch detect {
	case "", "both":
		// ok
	default:
		warn = fmt.Sprintf(`
**Warning:** sibling forge manifest reports detect=%q. For this agent package, re-forge with `+"`--detect both`"+` so beacons remain if the sentinel is stopped.

`, detect)
	}

	persist := ""
	switch goos {
	case "windows":
		persist = fmt.Sprintf("scheduled task `%s`", unitName)
	case "darwin":
		persist = fmt.Sprintf("launchd label `%s`", unitName)
	default:
		persist = fmt.Sprintf("systemd unit `%s.service`", unitName)
	}

	watchNote := fmt.Sprintf("secrets and sentinel config under `%s`; decoy watched under `%s/decoys/%s` after install", prefix, prefix, decoyBase)
	if visibleUnder != "" {
		docsRel := visibleUnder
		switch goos {
		case "windows":
			watchNote = fmt.Sprintf("secrets under `%s`; decoy installed+watched at interactive user `Documents\\%s\\%s` (placeholder in packaged sentinel.json is rewritten at install)", prefix, docsRel, decoyBase)
		default:
			watchNote = fmt.Sprintf("secrets under `%s`; decoy installed+watched at interactive user `Documents/%s/%s` (placeholder in packaged sentinel.json is rewritten at install)", prefix, docsRel, decoyBase)
		}
	}

	return fmt.Sprintf(`# Kunari agent package (%s)

Authorized use only. Deploy only on systems you own or have written authorization to monitor.
%s
## Dual-layer (preferred)

Forge the decoy with `+"`--detect both`"+` **before** `+"`kunari package agent`"+`. This package installs a sentinel; dual-layer keeps HTTPS/DNS beacons alive if a local admin kills the agent process.

| Forge detect | With this package |
|---|---|
| `+"`both`"+` (preferred) | Sentinel watches the file; beacons can still fire if the process dies |
| `+"`sentinel`"+` | Agent-only - hub `+"`agent_missing`"+` shortens time-to-notice but does not replace a beacon |
| `+"`beacon`"+` | Wrong model for `+"`package agent`"+` - use beacon-max / TLS hub recipes instead |

Example:

`+"```"+`bash
kunari forge --type env --name app-secrets --detect both \
  --collector https://beacon.example.com \
  --authz-ref LAB-1 --out ./forge-out
kunari package agent --target %s --out ./agent-pack \
  --artifact ./forge-out/<decoy> --token <token_id> \
  --hub-url https://beacon.example.com \
  --hub-secret-file ./data/ingest.secret
`+"```"+`

## Contents

- decoys/%s - forged decoy (with `+"`--detect both`"+`, beacon may still fire if the sentinel is stopped)
- etc/sentinel.json - sentinel config (%s)
- etc/ingest.secret - hub HMAC key file (embedded at package time; required)
- bin/ - place %s here before install
- platform install script and service unit (%s)

Protect this bundle in transit; it contains hub ingest material.

## Install (high level)

1. Put the matching Kunari binary in bin/ as **%s** (rename the release binary if you used `+"`--binary-name`"+`).
2. Review etc/sentinel.json paths (default prefix: %s).
3. Run the platform install script as a privileged operator (on Unix: chmod u+x install.sh if needed).
4. Confirm hub reachability and touch the decoy in a lab first.

Notes:
- Linux: install under /opt (not /home); the systemd unit runs as user kunari. Without CAP_SYS_ADMIN the sentinel falls back to inotify (open/read/modify, no PID); fanotify is preferred when elevated.
- Windows: install.ps1 registers a SYSTEM scheduled task (ONSTART). The package binary is not a Windows Service binary, so sc.exe create will time out.
- Persistence name for this package: %s.
- Optional OPSEC knobs at package time: `+"`--binary-name`"+`, `+"`--unit-name`"+`, `+"`--prefix`"+`. Do not choose names that impersonate OS components (denied by the packager).
- Human-visible decoy: `+"`--visible-under Work/Finance`"+` installs and watches under the interactive user's Documents; secrets stay under the private prefix. Windows enables File System audit policy at install; the elevated sentinel applies the per-file SACL at startup. Install refuses symlink/junction components under Documents.
- Client handoff: `+"`--client-bundle`"+` omits this DEPLOY.md and bin/README.txt.
- Uninstall: run uninstall.sh / uninstall.ps1 from the same package (elevated); visible-path uninstall skips symlinks/reparse points.
- Hub: with hub push configured, silence longer than `+"`--agent-stale-after`"+` emits `+"`agent_missing`"+` (time-to-notice, not stealth).

This is an agent deploy (sentinel process on the endpoint). It is not beacon-only.
`, goos, warn, goos, decoyBase, watchNote, binName, persist, binName, prefix, persist)
}