package cli

import (
	"fmt"

	"github.com/jimididit/kunari/internal/pack"
	"github.com/spf13/cobra"
)

func newPackageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package",
		Short: "Build deployable endpoint bundles",
		Long:  "Build authorized-use packages for endpoint deploy.\n\n" + authorizedUse,
	}
	cmd.AddCommand(newPackageAgentCmd())
	return cmd
}

func newPackageAgentCmd() *cobra.Command {
	var (
		target        string
		out           string
		artifact      string
		token         string
		memo          string
		hubURL        string
		hubSecretFile string
		prefix        string
	)
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Build a per-OS sentinel + decoy agent package",
		Long: "Write a directory with decoy, sentinel.json, install script, and service unit " +
			"for linux, windows, or darwin. Place a matching kunari binary in bin/ before install.\n\n" +
			authorizedUse,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := pack.BuildAgent(pack.AgentOptions{
				Target:        target,
				OutDir:        out,
				ArtifactPath:  artifact,
				TokenID:       token,
				Memo:          memo,
				HubURL:        hubURL,
				HubSecretFile: hubSecretFile,
				InstallPrefix: prefix,
				BinaryName:    "",
			}); err != nil {
				return err
			}
			fmt.Println("wrote agent package to", out)
			fmt.Println(authorizedUse)
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "endpoint OS: linux|windows|darwin")
	cmd.Flags().StringVar(&out, "out", "", "output directory for the package")
	cmd.Flags().StringVar(&artifact, "artifact", "", "forged decoy file path")
	cmd.Flags().StringVar(&token, "token", "", "token_id from the forge manifest")
	cmd.Flags().StringVar(&memo, "memo", "", "optional memo on the watch target")
	cmd.Flags().StringVar(&hubURL, "hub-url", "", "hub base URL for sentinel HMAC push")
	cmd.Flags().StringVar(&hubSecretFile, "hub-secret-file", "", "path to hub ingest.secret to embed (required)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "install prefix override (optional; safe absolute path only)")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("out")
	_ = cmd.MarkFlagRequired("artifact")
	_ = cmd.MarkFlagRequired("token")
	_ = cmd.MarkFlagRequired("hub-url")
	_ = cmd.MarkFlagRequired("hub-secret-file")
	return cmd
}
