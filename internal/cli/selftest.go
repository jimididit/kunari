package cli

import (
	"fmt"
	"os"
	"path/filepath"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/forge"
	"github.com/spf13/cobra"
)

func newSelfTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "self-test",
		Short: "Run offline integrity checks (forge, lint, evidence chain)",
		Long:  "Creates a temporary lab workspace, forges a decoy, lints it, appends a signed event, and verifies the chain. No network and no host watches.",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := os.MkdirTemp("", "kunari-selftest-*")
			if err != nil {
				return err
			}
			defer os.RemoveAll(dir)

			fmt.Println("self-test: forge")
			res, err := forge.Run(forge.Options{
				Type: "env", Name: "selftest", Detect: "sentinel",
				Memo: "self-test only", AuthzRef: "SELFTEST",
				OutDir: dir, KeyPath: filepath.Join(dir, "signing.key"),
				RegistryDB: filepath.Join(dir, "registry.db"),
			})
			if err != nil {
				return fmt.Errorf("forge: %w", err)
			}

			fmt.Println("self-test: lint")
			lint, err := forge.LintFile(res.ArtifactPath)
			if err != nil {
				return fmt.Errorf("lint: %w", err)
			}
			if len(lint.Findings) > 0 {
				return fmt.Errorf("lint findings: %v", lint.Findings)
			}

			fmt.Println("self-test: evidence chain")
			keys, err := kcrypto.LoadOrCreate(filepath.Join(dir, "chain.key"))
			if err != nil {
				return err
			}
			logPath := filepath.Join(dir, "events.jsonl")
			chain, err := event.Open(logPath, keys)
			if err != nil {
				return err
			}
			ev := event.New(res.TokenID, "self-test", "none", "open")
			ev.Memo = "self-test"
			if err := chain.Append(ev); err != nil {
				return fmt.Errorf("append: %w", err)
			}
			if err := event.VerifyFile(logPath, keys.Public); err != nil {
				return fmt.Errorf("verify: %w", err)
			}

			fmt.Println("self-test: OK")
			return nil
		},
	}
}
