//go:build linux

package sensor

import (
	"os"
	"strconv"
	"strings"
)

func resolveExe(pid int) (exe, cmdline string, quality string) {
	if pid <= 0 {
		return "", "", "none"
	}
	exeLink := "/proc/" + strconv.Itoa(pid) + "/exe"
	exe, err := os.Readlink(exeLink)
	if err != nil {
		quality = "partial"
	} else {
		quality = "full"
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err == nil {
		cmdline = strings.ReplaceAll(string(raw), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
	} else if quality == "full" {
		quality = "partial"
	} else {
		quality = "none"
	}
	return exe, cmdline, quality
}
