package safepath

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Clean validates and cleans a local filesystem path supplied by the operator
// or config. Rejects empty paths, NUL bytes, and ".." elements after cleaning.
func Clean(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path is empty")
	}
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("path contains NUL")
	}
	cleaned := filepath.Clean(path)
	if cleaned == "." {
		return "", fmt.Errorf("invalid path %q", path)
	}
	// Reject any remaining parent traversal after Clean (e.g. rooted escapes).
	for _, part := range strings.Split(cleaned, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("path must not contain '..': %q", path)
		}
	}
	// On Windows, also reject alternate stream separators in basenames.
	if strings.Contains(filepath.Base(cleaned), ":") && filepath.VolumeName(cleaned) == "" {
		return "", fmt.Errorf("invalid path basename: %q", path)
	}
	return cleaned, nil
}
