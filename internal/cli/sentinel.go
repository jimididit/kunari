package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jimididit/kunari/internal/sensor"
	"github.com/spf13/cobra"
)

func newSentinelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sentinel",
		Short: "On-host tripwire sensor (best available OS tier)",
		Long:  "Watch deployed tripwires using the best available detection tier and report it honestly.\n\n" + authorizedUse,
	}
	cmd.AddCommand(newSentinelRunCmd())
	cmd.AddCommand(newSentinelInitConfigCmd())
	cmd.AddCommand(newSentinelInstallHintsCmd())
	return cmd
}

func newSentinelRunCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the sentinel sensor",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := sensor.LoadConfig(configPath)
			if err != nil {
				return err
			}
			r, err := sensor.NewRunner(cfg, nil)
			if err != nil {
				return err
			}
			defer r.Close()
			fmt.Fprintf(os.Stderr, "kunari sentinel tier=%s caps=%q\n", r.Watcher.Tier(), r.Watcher.Capabilities())
			fmt.Println(authorizedUse)
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			return r.Run(ctx)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "sentinel.json", "sentinel config path")
	return cmd
}

func newSentinelInitConfigCmd() *cobra.Command {
	var (
		out           string
		path          string
		token         string
		memo          string
		hubURL        string
		hubSecretFile string
	)
	cmd := &cobra.Command{
		Use:   "init-config",
		Short: "Write an example sentinel.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			targets := []sensor.Target{{Path: path, TokenID: token, Memo: memo}}
			if err := sensor.WriteExampleConfig(out, targets, hubURL, hubSecretFile); err != nil {
				return err
			}
			fmt.Println("wrote", out)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "sentinel.json", "output config path")
	cmd.Flags().StringVar(&path, "path", "", "path to watch")
	cmd.Flags().StringVar(&token, "token", "", "token id from forge manifest")
	cmd.Flags().StringVar(&memo, "memo", "", "memo")
	cmd.Flags().StringVar(&hubURL, "hub-url", "", "optional hub base URL for HMAC event push")
	cmd.Flags().StringVar(&hubSecretFile, "hub-secret-file", "", "path to hub ingest.secret (shared with hub)")
	_ = cmd.MarkFlagRequired("path")
	return cmd
}

func newSentinelInstallHintsCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "install-hints",
		Short: "Print OS-specific install commands (SACL/auditd/systemd)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := sensor.LoadConfig(configPath)
			if err != nil {
				return err
			}
			fmt.Print(sensor.PlatformInstallHints(cfg.Targets))
			fmt.Print(sensor.ServiceUnitHints(cfg, configPath))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "sentinel.json", "sentinel config path")
	return cmd
}
