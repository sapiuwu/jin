// Command jin is a CLI for server & network reconnaissance.
package main

import (
	"os"

	"github.com/aliftech/jin/internal/adapter/in/cli"
	"github.com/aliftech/jin/internal/config"
	"github.com/aliftech/jin/internal/container"
)

func main() {
	// Composition root: build the full application graph from config,
	// then hand its driving ports to the CLI adapter.
	cfg := config.Default()
	c := container.New(cfg)
	app := cli.NewApp(c.ServerInfo, c.PortScan, c.TechStack,
		cli.WithDNS(c.DNS),
		cli.WithSubdomains(c.Subdomains),
		cli.WithWhois(c.Whois),
		cli.WithFullScan(c.FullScan),
	)

	// With no arguments, enter the interactive REPL; otherwise run a
	// one-shot command (kept for scripting/Docker use).
	if len(os.Args) < 2 {
		os.Exit(app.RunInteractive())
	}
	os.Exit(app.Run(os.Args[1:]))
}
