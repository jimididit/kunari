//go:build !linux && !windows && !darwin

package sensor

import "fmt"

func OpenBest(targets []Target) (Watcher, error) {
	return nil, fmt.Errorf("sentinel unsupported on this OS")
}

func PlatformInstallHints(targets []Target) string {
	return "# unsupported OS\n"
}
