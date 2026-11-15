package cli

import (
	"fmt"
	"time"

	"github.com/jimididit/kunari/internal/registry"
	"github.com/spf13/cobra"
)

func newImportCmd() *cobra.Command {
	var (
		db       string
		manifest string
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import a signed forge manifest into a registry",
		Long: "Verify and upsert a .manifest.json into the given registry sqlite file.\n" +
			"Point --registry at the hub data directory registry.db so beacons resolve on that collector.\n\n" +
			authorizedUse,
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := registry.Open(db)
			if err != nil {
				return err
			}
			defer st.Close()
			m, err := st.ImportFile(manifest)
			if err != nil {
				return err
			}
			fmt.Printf("imported %s (%s)", m.TokenID, m.Name)
			if m.Engagement != "" {
				fmt.Printf(" engagement=%s", m.Engagement)
			}
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&db, "registry", "kunari-registry.db", "registry sqlite path (use <hub-data>/registry.db for the live hub)")
	cmd.Flags().StringVar(&manifest, "manifest", "", "path to signed *.manifest.json")
	_ = cmd.MarkFlagRequired("manifest")
	return cmd
}

func newListCmd() *cobra.Command {
	var db string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List tokens in the local registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := registry.Open(db)
			if err != nil {
				return err
			}
			defer st.Close()
			items, err := st.List()
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			for _, m := range items {
				status := "active"
				if m.Revoked {
					status = "revoked"
				} else if m.Expired(now) {
					status = "expired"
				}
				eng := m.Engagement
				if eng == "" {
					eng = "-"
				}
				fmt.Printf("%s  %-8s  %-10s  %-12s  %s  %s\n", m.TokenID, status, m.Type, eng, m.Name, m.AuthzRef)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&db, "registry", "kunari-registry.db", "registry sqlite path")
	return cmd
}

func newRevokeCmd() *cobra.Command {
	var (
		db    string
		token string
	)
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a token in the local registry",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := registry.Open(db)
			if err != nil {
				return err
			}
			defer st.Close()
			if err := st.Revoke(token); err != nil {
				return err
			}
			fmt.Println("revoked", token)
			return nil
		},
	}
	cmd.Flags().StringVar(&db, "registry", "kunari-registry.db", "registry sqlite path")
	cmd.Flags().StringVar(&token, "token", "", "token id")
	_ = cmd.MarkFlagRequired("token")
	return cmd
}
