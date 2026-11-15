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
		binaryName    string
		unitName      string
		engagement    string
		agentLabel    string
		hubRegistry   string
		hubSigningKey string
		visibleUnder  string
		clientBundle  bool
	)
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Build a per-OS sentinel + decoy agent package",
		Long: "Write a directory with decoy, sentinel.json, install script, and service unit " +
			"for linux, windows, or darwin. Place a matching kunari binary in bin/ before install " +
			"(rename it to match --binary-name if set).\n\n" +
			"Optional OPSEC knobs: --binary-name, --unit-name, --prefix. Names that impersonate " +
			"well-known OS binaries or services are denied. This is authorized packaging, not stealth.\n\n" +
			"--visible-under places the watched decoy under the interactive user's Documents " +
			"(e.g. Work/Finance) so a normal open can trip the sentinel; secrets stay under --prefix. " +
			"--client-bundle omits operator-only DEPLOY.md and bin/README.txt.\n\n" +
			"Forge the decoy with --detect both first so beacons remain if the sentinel is stopped. " +
			"DEPLOY.md in the package (unless --client-bundle) repeats this dual-layer guidance.\n\n" +
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
				BinaryName:    binaryName,
				UnitName:      unitName,
				Engagement:    engagement,
				AgentLabel:    agentLabel,
				HubRegistry:   hubRegistry,
				HubSigningKey: hubSigningKey,
				VisibleUnder:  visibleUnder,
				ClientBundle:  clientBundle,
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
	cmd.Flags().StringVar(&binaryName, "binary-name", "", "installed binary basename (default kunari / kunari.exe; OS-name deny-list)")
	cmd.Flags().StringVar(&unitName, "unit-name", "", "persistence name: systemd unit, launchd label, or Windows task (defaults kunari-*)")
	cmd.Flags().StringVar(&engagement, "engagement", "", "engagement id/name written into sentinel.json")
	cmd.Flags().StringVar(&agentLabel, "agent-label", "", "operator label written into sentinel.json / heartbeats")
	cmd.Flags().StringVar(&hubRegistry, "hub-registry", "", "hub registry.db path; imports sibling forge manifest after packaging")
	cmd.Flags().StringVar(&hubSigningKey, "hub-signing-key", "", "hub Ed25519 private key (writes etc/hub.pub for job verify; also used with --hub-registry)")
	cmd.Flags().StringVar(&visibleUnder, "visible-under", "", "Documents-relative decoy dir (e.g. Work/Finance); install watches that path")
	cmd.Flags().BoolVar(&clientBundle, "client-bundle", false, "omit operator-only DEPLOY.md and bin/README.txt")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("out")
	_ = cmd.MarkFlagRequired("artifact")
	_ = cmd.MarkFlagRequired("token")
	_ = cmd.MarkFlagRequired("hub-url")
	_ = cmd.MarkFlagRequired("hub-secret-file")
	return cmd
}
