package pack

import "fmt"

func deployMarkdown(goos, prefix, binName, decoyBase string, secretIncluded bool) string {
	secretNote := "Copy the hub ingest.secret into etc/ingest.secret in this package (mode 0600) before install."
	if secretIncluded {
		secretNote = "This package already includes etc/ingest.secret. Protect the bundle in transit; treat it as credential material."
	}
	return fmt.Sprintf(`# Kunari agent package (%s)

Authorized use only. Deploy only on systems you own or have written authorization to monitor.

## Contents

- decoys/%s - forged decoy (beacon may still fire if the sentinel is stopped)
- etc/sentinel.json - sentinel config (install paths under %s)
- etc/ingest.secret - hub HMAC secret (or placeholder)
- bin/ - place %s here before install
- platform install script and service unit

%s

## Install (high level)

1. Put the matching Kunari binary in bin/.
2. Review etc/sentinel.json paths (default prefix: %s).
3. Run the platform install script as a privileged operator.
4. Confirm hub reachability and touch the decoy in a lab first.

This is an agent deploy (sentinel process on the endpoint). It is not beacon-only.
`, goos, decoyBase, prefix, binName, secretNote, prefix)
}
