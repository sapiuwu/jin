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
	DNS        in.DNSService
	Subdomains in.SubdomainService
	Whois      in.WhoisService
	FullScan   in.FullScanService
}

// New builds the full application graph from a configuration.
func New(cfg config.Config) *Container {
	httpScanner := scanner.NewHTTPServerScanner(cfg.HTTPTimeout)
	tcpScanner := scanner.NewTCPPortScanner(cfg.PortConnectTimeout)
	detector := scanner.NewHTTPTechStackDetector(cfg.TechStackTimeout)
	subdomains := scanner.NewCTSubdomainEnumerator(cfg.SubdomainTimeout)
	dns := scanner.NewDNSLookuper()
	whois := scanner.NewRDAPWhoisProvider(cfg.WhoisTimeout)
	cve := scanner.NewNVDChecker(cfg.CVETimeout)

	return &Container{
		ServerInfo: service.NewServerInfoService(httpScanner, cfg.HTTPTimeout),
		PortScan:   service.NewPortScanService(tcpScanner, cfg.PortScanTimeout, cfg.DefaultPorts),
		TechStack: service.NewTechStackService(detector, cfg.TechStackTimeout,
			service.WithSubdomainEnumerator(subdomains),
			service.WithDNSLookuper(dns),
			service.WithCVEChecker(cve),
			service.WithMaxSubdomains(cfg.MaxSubdomains),
			service.WithSubdomainConcurrency(cfg.SubdomainConcurrency),
			service.WithCVEConcurrency(4),
		),
		DNS:        service.NewDNSService(dns),
		Subdomains: service.NewSubdomainService(subdomains, cfg.SubdomainTimeout),
		Whois:      service.NewWhoisService(whois, cfg.WhoisTimeout),
		FullScan: service.NewFullScanService(
			service.NewServerInfoService(httpScanner, cfg.HTTPTimeout),
			service.NewPortScanService(tcpScanner, cfg.PortScanTimeout, cfg.DefaultPorts),
			service.NewTechStackService(detector, cfg.TechStackTimeout,
				service.WithSubdomainEnumerator(subdomains),
				service.WithDNSLookuper(dns),
				service.WithCVEChecker(cve),
				service.WithMaxSubdomains(cfg.MaxSubdomains),
				service.WithSubdomainConcurrency(cfg.SubdomainConcurrency),
				service.WithCVEConcurrency(4),
			),
		),
	}
}
