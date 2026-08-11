// Package out defines the secondary (driven) ports: the contracts the
// application needs from its driven adapters (HTTP/TCP/DNS clients).
// The application depends only on these interfaces, never on concrete
// implementations.
package out

import (
	"context"

	"github.com/aliftech/jin/internal/domain"
)

// ServerScanner gathers web server info for a URL.
type ServerScanner interface {
	Scan(ctx context.Context, url string) (*domain.ServerInfo, error)
}

// PortScanner probes a host for open ports.
type PortScanner interface {
	Scan(ctx context.Context, host string, ports []int) ([]domain.PortInfo, error)
}

// TechStackDetector fingerprints the technologies (CMS, web server,
// language, frameworks, JS libraries, analytics, CDN, etc.) used by a
// target website. Implementations typically inspect HTTP response
// headers, HTML markup, cookies, and script/asset URLs against a
// signature database.
type TechStackDetector interface {
	Detect(ctx context.Context, url string) (*domain.TechStackInfo, error)
}

// SubdomainEnumerator discovers subdomains of a given root domain using
// passive sources (e.g. certificate transparency logs). It does not
// actively brute-force or guess hostnames.
type SubdomainEnumerator interface {
	Enumerate(ctx context.Context, domain string) ([]string, error)
}

// DNSLookuper resolves a domain's nameserver, mail exchange, and TXT
// records.
type DNSLookuper interface {
	Lookup(ctx context.Context, domain string) (*domain.DNSInfo, error)
}
