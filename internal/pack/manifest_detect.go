package pack

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/jimididit/kunari/internal/registry"
	"github.com/jimididit/kunari/internal/safepath"
)

// detectFromSiblingManifest reads detect from a sibling *.manifest.json when present.
// Handles forged names like name-folder.zip / name-stubs.zip mapping to name.manifest.json.
func detectFromSiblingManifest(artifactPath string) string {
	artifactPath, err := safepath.Clean(artifactPath)
	if err != nil {
		return ""
	}
	manPath := siblingManifestPath(artifactPath)
	if manPath == "" {
		return ""
	}
	b, err := os.ReadFile(manPath) // #nosec G304 -- path from siblingManifestPath under cleaned artifact dir
	if err != nil {
		return ""
	}
	var m registry.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return ""
	}
	return strings.TrimSpace(m.Detect)
}
