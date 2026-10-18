//go:build darwin

package sensor

import "fmt"

func OpenBest(targets []Target) (Watcher, error) {
	return nil, fmt.Errorf("macOS sentinel tiers (eslogger/FSEvents) are Phase 3; not armed yet")
}

func PlatformInstallHints(targets []Target) string {
	return "# macOS sentinel (eslogger / Endpoint Security) arrives in Phase 3.\n"
}
