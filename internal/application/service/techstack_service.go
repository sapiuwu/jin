package service

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// TechStackService is the tech-stack fingerprinting use case.
type TechStackService struct {
	detector   out.TechStackDetector
	subdomains out.SubdomainEnumerator // optional; nil disables subdomain discovery
	dns        out.DNSLookuper         // optional; nil disables DNS record lookup
	timeout    time.Duration
	maxSubs    int // cap on how many discovered subdomains get individually scanned
	subWorkers int // concurrency for per-subdomain scans
}

// TechStackOption configures optional capabilities of the use case.
type TechStackOption func(*TechStackService)

// WithSubdomainEnumerator enables `--subdomains` deep scans by supplying a
// passive subdomain discovery source.
func WithSubdomainEnumerator(e out.SubdomainEnumerator) TechStackOption {
	return func(s *TechStackService) { s.subdomains = e }
}

// WithDNSLookuper enables DNS record reporting (nameservers, MX, TXT) as
// part of deep scans.
func WithDNSLookuper(d out.DNSLookuper) TechStackOption {
	return func(s *TechStackService) { s.dns = d }
}

// WithMaxSubdomains caps how many discovered subdomains get individually
// fingerprinted, to keep deep scans bounded on domains with hundreds of
// certificate transparency entries. Default: 25.
func WithMaxSubdomains(n int) TechStackOption {
	return func(s *TechStackService) {
		if n > 0 {
			s.maxSubs = n
		}
	}
}

// WithSubdomainConcurrency sets how many subdomains are scanned in
// parallel. Default: 8.
func WithSubdomainConcurrency(n int) TechStackOption {
	return func(s *TechStackService) {
		if n > 0 {
			s.subWorkers = n
		}
	}
}

// NewTechStackService builds the use case. Deep-scan sources (subdomain
// enumeration, DNS) are optional and enabled via options.
func NewTechStackService(detector out.TechStackDetector, timeout time.Duration, opts ...TechStackOption) *TechStackService {
	s := &TechStackService{
		detector:   detector,
		timeout:    timeout,
		maxSubs:    25,
		subWorkers: 8,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

var _ in.TechStackService = (*TechStackService)(nil)

// Scan fingerprints target. When deep is true and the optional sources are
// configured, it also discovers subdomains (passively, via certificate
// transparency), fingerprints each one, and reports DNS records for the
// root domain. Deep scans take meaningfully longer since they involve one
// HTTP request per discovered subdomain.
func (s *TechStackService) Scan(ctx context.Context, target string, deep bool) (*in.TechStackResult, error) {
	// The overall timeout scales with deep scans since they fan out into
	// many additional requests; a single flat budget would starve
	// subdomain scanning on anything but tiny domains.
	overall := s.timeout
	if deep {
		overall = s.timeout * time.Duration(s.maxSubs+2)
	}
	ctx, cancel := context.WithTimeout(ctx, overall)
	defer cancel()

	start := time.Now()
	info, err := s.detector.Detect(ctx, target)
	if err != nil {
		return nil, err
	}

	if deep {
		root := rootDomain(target)
		if root != "" {
			info.Subdomains = s.scanSubdomains(ctx, root)
			info.DNS = s.lookupDNS(ctx, root)
		}
	}

	return &in.TechStackResult{Info: info, Duration: time.Since(start)}, nil
}

// scanSubdomains discovers subdomains of root and fingerprints each one
// concurrently, bounded by s.subWorkers. Individual failures (host down,
// timeout, TLS error) are recorded per-subdomain rather than aborting the
// whole scan.
func (s *TechStackService) scanSubdomains(ctx context.Context, root string) []domain.SubdomainInfo {
	if s.subdomains == nil {
		return nil
	}

	hosts, err := s.subdomains.Enumerate(ctx, root)
	if err != nil || len(hosts) == 0 {
		return nil
	}
	if len(hosts) > s.maxSubs {
		hosts = hosts[:s.maxSubs]
	}

	results := make([]domain.SubdomainInfo, len(hosts))
	sem := make(chan struct{}, s.subWorkers)
	var wg sync.WaitGroup

	for i, host := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			subCtx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()

			info, err := s.detector.Detect(subCtx, "https://"+host)
			if err != nil {
				results[i] = domain.SubdomainInfo{Host: host, Reachable: false, Error: err.Error()}
				return
			}
			results[i] = domain.SubdomainInfo{Host: host, Reachable: true, Technologies: info.Technologies}
		}(i, host)
	}
	wg.Wait()

	return results
}

func (s *TechStackService) lookupDNS(ctx context.Context, root string) *domain.DNSInfo {
	if s.dns == nil {
		return nil
	}
	info, err := s.dns.Lookup(ctx, root)
	if err != nil {
		return nil
	}
	return info
}

// rootDomain extracts a bare hostname from a URL or host:port string, for
// use as the subdomain-enumeration / DNS-lookup query. Note: this uses a
// naive last-two-labels heuristic and does not handle multi-part public
// suffixes correctly (e.g. "example.co.uk" would be truncated to
// "co.uk"). For full correctness, resolve against the public suffix list.
func rootDomain(target string) string {
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Host
	}
	if i := strings.Index(host, ":"); i != -1 {
		host = host[:i]
	}
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}
