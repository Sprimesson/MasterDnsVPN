// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package main

import (
	"fmt"
	"os"

	"masterdnsvpn-go/internal/client"
)

func main() {
	app, err := client.Bootstrap("client_config.toml")
	if err != nil {
		_, _ = os.Stderr.WriteString(fmt.Sprintf("Client startup failed: %v\n", err))
		os.Exit(1)
	}

	cfg := app.Config()
	log := app.Logger()
	log.Infof("[*] <green>Client Configuration Loaded</green>")
	log.Infof(
		"[*] <green>Protocol Type</green>: <cyan>%s</cyan>  |  <green>Encryption Method</green>: <cyan>%d</cyan>",
		cfg.ProtocolType,
		cfg.DataEncryptionMethod,
	)
	log.Infof(
		"[*] <green>Resolver Balancing Strategy</green>: <cyan>%d</cyan>",
		cfg.ResolverBalancingStrategy,
	)
	log.Infof(
		"[*] <green>Configured Domains</green>: <magenta>%d</magenta>",
		len(cfg.Domains),
	)
	log.Infof(
		"[*] <green>Loaded Resolvers</green>: <magenta>%d</magenta> unique IPs",
		len(cfg.Resolvers),
	)
	log.Infof(
		"[*] <green>Connection Catalog</green>: <magenta>%d</magenta> domain-resolver pairs",
		len(app.Connections()),
	)
	log.Infof(
		"[*] <green>Active Connections</green>: <magenta>%d</magenta>",
		app.Balancer().ValidCount(),
	)
	log.Infof("[*] <green>Client Bootstrap Ready</green>")
}
