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

// WhoisProvider retrieves passive registration data for a domain.
type WhoisProvider interface {
	Lookup(ctx context.Context, domain string) (*domain.WhoisInfo, error)
}

// CVEChecker cross-references a detected technology (by name and version)
// against a vulnerability database. Implementations should be best-effort:
// network failures or missing mappings simply yield no results.
type CVEChecker interface {
	Check(ctx context.Context, name, version string) ([]domain.CVE, error)
}

// CookieAnalyzer inspects the Set-Cookie attributes returned by a target and
// reports any missing security flags (Secure/HttpOnly/SameSite).
type CookieAnalyzer interface {
	Analyze(ctx context.Context, url string) (*domain.CookieAnalysis, error)
}

// TLSInspector performs a deep TLS handshake against a host and reports the
// negotiated protocol, cipher suite, certificate chain, and posture issues.
type TLSInspector interface {
	Inspect(ctx context.Context, host string) (*domain.TLSReport, error)
}

// WaybackLister discovers historic URLs for a domain via the Internet
// Archive's Wayback Machine CDX API (passive URL enumeration).
type WaybackLister interface {
	List(ctx context.Context, domain string) (*domain.WaybackResult, error)
}

// ExposedChecker probes a target for commonly-misconfigured files and paths
// (robots.txt, sitemap.xml, .git, .env, security.txt, backups) that may
// leak source or credentials when left publicly accessible.
type ExposedChecker interface {
	Check(ctx context.Context, url string) (*domain.ExposedResult, error)
}

// CDNDetector determines whether a target is fronted by a CDN/WAF and
// whether its origin server appears to be directly reachable.
type CDNDetector interface {
	Detect(ctx context.Context, domain string) (*domain.CDNResult, error)
}
