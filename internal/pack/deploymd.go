package pack

import "fmt"

func deployMarkdown(goos, prefix, binName, decoyBase string, _ bool) string {
	return fmt.Sprintf(`# Kunari agent package (%s)

Authorized use only. Deploy only on systems you own or have written authorization to monitor.

## Contents

- decoys/%s - forged decoy (beacon may still fire if the sentinel is stopped)
- etc/sentinel.json - sentinel config (install paths under %s)
- etc/ingest.secret - hub HMAC key file (embedded at package time; required)
- bin/ - place %s here before install
- platform install script and service unit

Protect this bundle in transit; it contains hub ingest material.

## Install (high level)

1. Put the matching Kunari binary in bin/.
2. Review etc/sentinel.json paths (default prefix: %s).
3. Run the platform install script as a privileged operator (on Unix: chmod u+x install.sh if needed).
4. Confirm hub reachability and touch the decoy in a lab first.

Notes:
- Linux: install under /opt (not /home); the systemd unit runs as user kunari.
- Windows: install.ps1 registers a SYSTEM scheduled task (ONSTART). kunari.exe is not a Windows Service binary, so sc.exe create will time out.

This is an agent deploy (sentinel process on the endpoint). It is not beacon-only.
`, goos, decoyBase, prefix, binName, prefix)
}
