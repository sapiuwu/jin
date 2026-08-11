// Package container is the composition root: the only place where the
// concrete implementations of every port are chosen and wired together.
// Everything outside this package depends on interfaces.
package container

import (
	"github.com/aliftech/jin/internal/adapter/out/scanner"
	"github.com/aliftech/jin/internal/application/service"
	"github.com/aliftech/jin/internal/config"
	"github.com/aliftech/jin/internal/port/in"
)

// Container exposes the application's driving ports wired to their
// concrete driven adapters.
type Container struct {
	ServerInfo in.ServerInfoService
	PortScan   in.PortScanService
	TechStack  in.TechStackService
}

// New builds the full application graph from a configuration.
func New(cfg config.Config) *Container {
	httpScanner := scanner.NewHTTPServerScanner(cfg.HTTPTimeout)
	tcpScanner := scanner.NewTCPPortScanner(cfg.PortConnectTimeout)
	detector := scanner.NewHTTPTechStackDetector(cfg.TechStackTimeout)
	subdomains := scanner.NewCTSubdomainEnumerator(cfg.SubdomainTimeout)
	dns := scanner.NewDNSLookuper()

	return &Container{
		ServerInfo: service.NewServerInfoService(httpScanner, cfg.HTTPTimeout),
		PortScan:   service.NewPortScanService(tcpScanner, cfg.PortScanTimeout, cfg.DefaultPorts),
		TechStack: service.NewTechStackService(detector, cfg.TechStackTimeout,
			service.WithSubdomainEnumerator(subdomains),
			service.WithDNSLookuper(dns),
			service.WithMaxSubdomains(cfg.MaxSubdomains),
			service.WithSubdomainConcurrency(cfg.SubdomainConcurrency),
		),
	}
}
