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
	Cookie     in.CookieService
	TLS        in.TLSService
	Wayback    in.WaybackService
	Exposed    in.ExposedService
	CDN        in.CDNService
}

// New builds the full application graph from a configuration.
func New(cfg config.Config) *Container {
	httpScanner := scanner.NewHTTPServerScanner(cfg.HTTPTimeout, cfg.Proxy)
	tcpScanner := scanner.NewTCPPortScanner(cfg.PortConnectTimeout, cfg.PortConcurrency)
	detector := scanner.NewHTTPTechStackDetector(cfg.TechStackTimeout, cfg.Proxy)
	subdomains := scanner.NewCTSubdomainEnumerator(cfg.SubdomainTimeout, cfg.Proxy)
	dns := scanner.NewDNSLookuper()
	whois := scanner.NewRDAPWhoisProvider(cfg.WhoisTimeout, cfg.Proxy)
	cve := scanner.NewNVDChecker(cfg.CVETimeout, cfg.Proxy)
	cookieAnalyzer := scanner.NewHTTPCookieAnalyzer(cfg.HTTPTimeout, cfg.Proxy)
	tlsInspector := scanner.NewTLSInspector(cfg.HTTPTimeout)
	wayback := scanner.NewWaybackLister(cfg.SubdomainTimeout, cfg.Proxy)
	exposed := scanner.NewExposedChecker(cfg.HTTPTimeout, cfg.Proxy)
	cdn := scanner.NewCDNDetector(cfg.HTTPTimeout, cfg.Proxy)

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
		Cookie:  service.NewCookieService(cookieAnalyzer, cfg.HTTPTimeout),
		TLS:     service.NewTLSService(tlsInspector, cfg.HTTPTimeout),
		Wayback: service.NewWaybackService(wayback, cfg.SubdomainTimeout),
		Exposed: service.NewExposedService(exposed, cfg.HTTPTimeout),
		CDN:     service.NewCDNService(cdn, cfg.HTTPTimeout),
	}
}
