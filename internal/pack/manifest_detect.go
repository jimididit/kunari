package pack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/jimididit/kunari/internal/registry"
	"github.com/jimididit/kunari/internal/safepath"
)

// detectFromSiblingManifest reads detect from <artifact-stem>.manifest.json when present.
func detectFromSiblingManifest(artifactPath string) string {
	artifactPath, err := safepath.Clean(artifactPath)
	if err != nil {
		return ""
	}
	stem := strings.TrimSuffix(filepath.Base(artifactPath), filepath.Ext(artifactPath))
	if stem == "" || stem == "." {
		return ""
	}
	manPath := filepath.Join(filepath.Dir(artifactPath), stem+".manifest.json")
	b, err := os.ReadFile(manPath) // #nosec G304 -- path derived from cleaned artifact dir + fixed suffix
	if err != nil {
		return ""
	}
	var m registry.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return ""
	}
	return strings.TrimSpace(m.Detect)
}
