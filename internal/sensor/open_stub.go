//go:build !linux && !windows && !darwin

package sensor

import "fmt"

func OpenBest(targets []Target, preferTiers []string) (Watcher, error) {
	_ = preferTiers
	return nil, fmt.Errorf("sentinel unsupported on this OS")
}

func PlatformInstallHints(targets []Target) string {
	return "# unsupported OS\n"
}
