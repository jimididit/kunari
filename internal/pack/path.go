package pack

import (
	"fmt"
	"path"
	"strings"
)

func normalizeTarget(goos string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(goos)) {
	case "linux":
		return "linux", nil
	case "windows", "win":
		return "windows", nil
	case "darwin", "macos", "mac":
		return "darwin", nil
	default:
		return "", fmt.Errorf("unsupported --target %q (want linux|windows|darwin)", goos)
	}
}

func defaultPrefix(goos string) string {
	switch goos {
	case "windows":
		return `C:\ProgramData\KunariAgent`
	case "darwin":
		return "/usr/local/kunari-agent"
	default:
		return "/opt/kunari-agent"
	}
}

// targetJoin joins path elements using the target OS separator (not the builder OS).
func targetJoin(goos string, elem ...string) string {
	if len(elem) == 0 {
		return ""
	}
	if goos == "windows" {
		out := elem[0]
		for _, e := range elem[1:] {
			e = strings.Trim(e, `\`)
			if e == "" {
				continue
			}
			if strings.HasSuffix(out, `\`) {
				out += e
			} else {
				out += `\` + e
			}
		}
		return out
	}
	return path.Join(elem...)
}
