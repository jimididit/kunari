package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const authorizedUse = `Authorized use only. Deploy Kunari only on systems you own or have written
authorization to monitor. Defensive DFIR / tripwire use. No offensive operations.`

func Execute() error {
	root := &cobra.Command{
		Use:   "kunari",
		Short: "Cross-platform canary / tripwire toolkit (defensive use only)",
		Long:  "Kunari forges tripwire artifacts, collects beacons via hub, and runs on-host sensors.\n\n" + authorizedUse,
		SilenceUsage: true,
	}
	root.AddCommand(newForgeCmd())
	root.AddCommand(newHubCmd())
	root.AddCommand(newSentinelCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newLintCmd())
	root.AddCommand(newListCmd())
	root.AddCommand(newRevokeCmd())
	root.AddCommand(newSelfTestCmd())
	root.AddCommand(newVersionCmd())
	return root.Execute()
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("kunari %s (commit %s, built %s)\n", Version, Commit, Date)
		},
	}
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
}
