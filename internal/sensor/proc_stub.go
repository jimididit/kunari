//go:build !linux

package sensor

func resolveExe(pid int) (exe, cmdline string, quality string) {
	return "", "", "none"
}
