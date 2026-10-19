package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jimididit/kunari/internal/collect"
	"github.com/jimididit/kunari/internal/hub"
	"github.com/spf13/cobra"
)

func newHubCmd() *cobra.Command {
	var (
		listen          string
		dnsListen       string
		dnsZone         string
		dataDir         string
		keyPath         string
		ingestSecret    string
		apiToken        string
		collectLvl      string
		trustedProxies  []string
		clientIPHeader  string
		agentStaleAfter time.Duration
	)
	cmd := &cobra.Command{
		Use:   "hub",
		Short: "Run the self-hosted beacon collector",
		Long:  "HTTPS (+ optional DNS) beacon collector with disk-backed alert queue.\n\n" + authorizedUse,
		RunE: func(cmd *cobra.Command, args []string) error {
			lvl, err := collect.Parse(collectLvl)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				return err
			}
			h, err := hub.New(hub.Config{
				HTTPListen:       listen,
				DNSListen:        dnsListen,
				DNSZone:          dnsZone,
				DataDir:          dataDir,
				RegistryDB:       filepath.Join(dataDir, "registry.db"),
				KeyPath:          keyPath,
				IngestSecretPath: ingestSecret,
				APITokenPath:     apiToken,
				TrustedProxies:   trustedProxies,
				ClientIPHeader:   clientIPHeader,
				AgentStaleAfter:  agentStaleAfter,
				Collect:          lvl,
			})
			if err != nil {
				return err
			}
			defer h.Close()

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			fmt.Println(authorizedUse)
			return h.Run(ctx)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", ":8080", "HTTP listen address (use TLS terminator in production)")
	cmd.Flags().StringVar(&dnsListen, "dns-listen", "", "optional UDP DNS listen (e.g. :5353)")
	cmd.Flags().StringVar(&dnsZone, "dns-zone", "", "DNS zone this hub is authoritative for")
	cmd.Flags().StringVar(&dataDir, "data", "./data", "data directory")
	cmd.Flags().StringVar(&keyPath, "key", "", "signing key path (default: <data>/signing.key)")
	cmd.Flags().StringVar(&ingestSecret, "ingest-secret", "", "HMAC ingest secret path (default: <data>/ingest.secret)")
	cmd.Flags().StringVar(&apiToken, "api-token", "", "operator API bearer token path (default: <data>/api.token)")
	cmd.Flags().StringSliceVar(&trustedProxies, "trusted-proxy", nil, "CIDR/IP of reverse proxies allowed to set client-IP header (repeatable); empty = trust RemoteAddr only")
	cmd.Flags().StringVar(&clientIPHeader, "client-ip-header", "X-Forwarded-For", "header used when peer matches --trusted-proxy")
	cmd.Flags().DurationVar(&agentStaleAfter, "agent-stale-after", 3*time.Minute, "alert when a heartbeating sentinel is silent this long (0 disables)")
	cmd.Flags().StringVar(&collectLvl, "collect", "standard", "minimal|standard|forensic")
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if keyPath == "" {
			keyPath = filepath.Join(dataDir, "signing.key")
		}
		if ingestSecret == "" {
			ingestSecret = filepath.Join(dataDir, "ingest.secret")
		}
		if apiToken == "" {
			apiToken = filepath.Join(dataDir, "api.token")
		}
		return nil
	}
	return cmd
}
