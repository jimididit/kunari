package cli

import (
	"encoding/hex"
	"fmt"
	"os"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/forge"
	"github.com/spf13/cobra"
)

func newVerifyCmd() *cobra.Command {
	var (
		logPath string
		keyPath string
		pubHex  string
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a hash-chained signed event log",
		RunE: func(cmd *cobra.Command, args []string) error {
			var pub []byte
			var err error
			if pubHex != "" {
				pub, err = hex.DecodeString(pubHex)
				if err != nil {
					return err
				}
			} else {
				kp, err := kcrypto.LoadOrCreate(keyPath)
				if err != nil {
					return err
				}
				pub = kp.Public
			}
			if err := event.VerifyFile(logPath, pub); err != nil {
				return err
			}
			fmt.Println("OK: event log integrity verified")
			return nil
		},
	}
	cmd.Flags().StringVar(&logPath, "log", "events.jsonl", "event log path")
	cmd.Flags().StringVar(&keyPath, "key", "kunari-signing.key", "private key path (public derived)")
	cmd.Flags().StringVar(&pubHex, "pubkey", "", "optional public key hex (overrides --key)")
	return cmd
}

func newLintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lint [files...]",
		Short: "Scan artifacts for static fingerprint / secret tells",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var failed bool
			for _, p := range args {
				r, err := forge.LintFile(p)
				if err != nil {
					return err
				}
				if len(r.Findings) == 0 {
					fmt.Printf("OK %s\n", p)
					continue
				}
				failed = true
				fmt.Printf("FINDINGS %s\n", p)
				for _, f := range r.Findings {
					fmt.Printf("  - %s\n", f)
				}
			}
			if failed {
				os.Exit(2)
			}
			return nil
		},
	}
	return cmd
}
