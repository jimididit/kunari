package sensor

import (
	"fmt"
	"path/filepath"
	"runtime"
)

// ServiceUnitHints prints systemd or Windows service install sketches.
func ServiceUnitHints(cfg *Config, configPath string) string {
	absCfg, _ := filepath.Abs(configPath)
	opsec := `
# OPSEC (local attackers)
# - chmod 0600 the config + hub_secret_file; chmod 0700 data_dir (Unix).
# - Run as a dedicated low-privilege user; do not world-expose config paths.
# - Prefer detect=both decoys: beacons still fire if the sentinel process is killed.
# - Assume a local admin can eventually find the watch list; Kunari is not stealth malware.
`
	switch runtime.GOOS {
	case "linux":
		return opsec + fmt.Sprintf(`
# systemd unit example (adjust User/binary path)
# /etc/systemd/system/kunari-sentinel.service
[Unit]
Description=Kunari sentinel tripwire sensor
After=network.target

[Service]
Type=simple
User=kunari
Group=kunari
UMask=0077
Environment=KUNARI_SENTINEL_CONFIG=%s
ExecStart=/usr/local/bin/kunari sentinel run
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target

# systemctl daemon-reload && systemctl enable --now kunari-sentinel
`, absCfg)
	case "windows":
		return opsec + fmt.Sprintf(`
# Windows persistence sketch (run elevated).
# kunari.exe is not a Windows Service binary; prefer Register-ScheduledTask
# (see kunari package agent install.ps1) or a wrapper such as NSSM/WinSW.
# Restrict NTFS ACL on the config and data directory to SYSTEM + Administrators.
# Prefer a .cmd wrapper that sets KUNARI_SENTINEL_CONFIG then runs: kunari.exe sentinel run
# Example (config path for the wrapper's set line): %s
# $runner = 'C:\ProgramData\KunariAgent\bin\run-sentinel.cmd'
# $a = New-ScheduledTaskAction -Execute $runner
# $t = New-ScheduledTaskTrigger -AtStartup
# $p = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
# Register-ScheduledTask -TaskName KunariSentinel -Action $a -Trigger $t -Principal $p -Force
# Start-ScheduledTask -TaskName KunariSentinel
`, absCfg)
	default:
		return opsec + "\n# service install: use launchd / Phase 3 docs on macOS\n"
	}
}
