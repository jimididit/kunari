package cli

import (
	"fmt"

	"github.com/jimididit/kunari/internal/registry"
	"github.com/spf13/cobra"
)

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
			for _, m := range items {
				status := "active"
				if m.Revoked {
					status = "revoked"
				}
				fmt.Printf("%s  %-8s  %-10s  %s  %s\n", m.TokenID, status, m.Type, m.Name, m.AuthzRef)
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
