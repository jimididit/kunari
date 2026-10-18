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
ExecStart=/usr/local/bin/kunari sentinel run --config %s
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target

# systemctl daemon-reload && systemctl enable --now kunari-sentinel
`, absCfg)
	case "windows":
		return opsec + fmt.Sprintf(`
# Windows service sketch (run elevated; use sc.exe or NSSM)
# Restrict NTFS ACL on the config and data directory to the service account only.
# icacls config.json /inheritance:r /grant:r "NT SERVICE\KunariSentinel:(R)"
# sc.exe create KunariSentinel binPath= "C:\path\kunari.exe sentinel run --config %s" start= auto
# sc.exe description KunariSentinel "Kunari defensive tripwire sensor"
# sc.exe start KunariSentinel
`, absCfg)
	default:
		return opsec + "\n# service install: use launchd / Phase 3 docs on macOS\n"
	}
}
