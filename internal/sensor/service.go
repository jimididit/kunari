package sensor

import (
	"fmt"
	"path/filepath"
	"runtime"
)

// ServiceUnitHints prints systemd or Windows service install sketches.
func ServiceUnitHints(cfg *Config, configPath string) string {
	absCfg, _ := filepath.Abs(configPath)
	switch runtime.GOOS {
	case "linux":
		return fmt.Sprintf(`
# systemd unit example (adjust User/binary path)
# /etc/systemd/system/kunari-sentinel.service
[Unit]
Description=Kunari sentinel tripwire sensor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kunari sentinel run --config %s
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target

# systemctl daemon-reload && systemctl enable --now kunari-sentinel
`, absCfg)
	case "windows":
		return fmt.Sprintf(`
# Windows service sketch (run elevated; use sc.exe or NSSM)
# sc.exe create KunariSentinel binPath= "C:\path\kunari.exe sentinel run --config %s" start= auto
# sc.exe description KunariSentinel "Kunari defensive tripwire sensor"
# sc.exe start KunariSentinel
`, absCfg)
	default:
		return "\n# service install: use launchd / Phase 3 docs on macOS\n"
	}
}
