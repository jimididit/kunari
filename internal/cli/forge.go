package cli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/jimididit/kunari/internal/forge"
	"github.com/spf13/cobra"
)

func newForgeCmd() *cobra.Command {
	var (
		platform     string
		itemType     string
		name         string
		theme        string
		detect       string
		collector    string
		collectorDNS string
		collect      string
		memo         string
		authz        string
		expire       string
		tags         []string
		out          string
		registryDB   string
		keyPath      string
	)
	cmd := &cobra.Command{
		Use:   "forge",
		Short: "Generate tripwire artifacts and signed manifests",
		Long:  "Generate defensive tripwire artifacts.\n\n" + authorizedUse,
		RunE: func(cmd *cobra.Command, args []string) error {
			plats, err := forge.ParsePlatforms(platform)
			if err != nil {
				return err
			}
			var exp time.Duration
			if expire != "" {
				exp, err = time.ParseDuration(expire)
				if err != nil {
					// allow 90d style
					if len(expire) > 1 && expire[len(expire)-1] == 'd' {
						var days int
						if _, err2 := fmt.Sscanf(expire, "%dd", &days); err2 == nil {
							exp = time.Duration(days) * 24 * time.Hour
							err = nil
						}
					}
					if err != nil {
						return fmt.Errorf("invalid --expire: %w", err)
					}
				}
			}
			res, err := forge.Run(forge.Options{
				Platforms:    plats,
				Type:         itemType,
				Name:         name,
				Theme:        theme,
				Detect:       detect,
				Collector:    collector,
				CollectorDNS: collectorDNS,
				Collect:      collect,
				Memo:         memo,
				AuthzRef:     authz,
				Expire:       exp,
				Tags:         forge.ParseTags(tags),
				OutDir:       out,
				RegistryDB:   registryDB,
				KeyPath:      keyPath,
			})
			if err != nil {
				return err
			}
			fmt.Printf("token_id:  %s\n", res.TokenID)
			fmt.Printf("artifact:  %s\n", res.ArtifactPath)
			if res.DirPath != "" {
				fmt.Printf("directory: %s\n", res.DirPath)
				fmt.Printf("watch:     %s\n", filepath.Join(res.DirPath, "secrets.env"))
			}
			fmt.Printf("manifest:  %s\n", res.ManifestPath)
			fmt.Printf("install:   %s\n", res.InstallPath)
			fmt.Println(authorizedUse)
			return nil
		},
	}
	cmd.Flags().StringVar(&platform, "platform", "all", "windows,linux,macos or all")
	cmd.Flags().StringVar(&itemType, "type", "", "env|svg|html|docx|xlsx|pdf|folder|stub-exe")
	cmd.Flags().StringVar(&name, "name", "", "artifact base name")
	cmd.Flags().StringVar(&theme, "theme", "devops", "finance|it-admin|hr|devops")
	cmd.Flags().StringVar(&detect, "detect", "both", "beacon|sentinel|both")
	cmd.Flags().StringVar(&collector, "collector", "", "HTTPS collector base URL")
	cmd.Flags().StringVar(&collectorDNS, "collector-dns", "", "DNS beacon zone")
	cmd.Flags().StringVar(&collect, "collect", "standard", "minimal|standard|forensic")
	cmd.Flags().StringVar(&memo, "memo", "", "operator memo / placement note")
	cmd.Flags().StringVar(&authz, "authz-ref", "", "authorization / ticket reference (required)")
	cmd.Flags().StringVar(&expire, "expire", "", "optional expiry (e.g. 90d, 2160h)")
	cmd.Flags().StringArrayVar(&tags, "tags", nil, "k:v tags (repeatable)")
	cmd.Flags().StringVar(&out, "out", "./dist", "output directory")
	cmd.Flags().StringVar(&registryDB, "registry", "kunari-registry.db", "local registry sqlite path")
	cmd.Flags().StringVar(&keyPath, "key", "kunari-signing.key", "ed25519 signing key path (created if missing)")
	_ = cmd.MarkFlagRequired("type")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("authz-ref")
	return cmd
}
