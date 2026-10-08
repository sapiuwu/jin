package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/hostutil"
	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// maxScanWarnings caps how many distinct warnings a single scan reports,
// so a fully throttled run cannot drown the report in per-technology noise.
const maxScanWarnings = 3

// TechStackService is the tech-stack fingerprinting use case.
type TechStackService struct {
	detector   out.TechStackDetector
	subdomains out.SubdomainEnumerator // optional; nil disables subdomain discovery
	dns        out.DNSLookuper         // optional; nil disables DNS record lookup
	cve        out.CVEChecker          // optional; nil disables CVE cross-reference
	timeout    time.Duration
	maxSubs    int // cap on how many discovered subdomains get individually scanned
	subWorkers int // concurrency for per-subdomain scans
	cveWorkers int // concurrency for CVE checks
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

// WithCVEChecker enables a CVE cross-reference of detected (versioned)
// technologies against a vulnerability database.
func WithCVEChecker(c out.CVEChecker) TechStackOption {
	return func(s *TechStackService) { s.cve = c }
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

// WithCVEConcurrency sets how many CVE checks run in parallel. Default: 4.
func WithCVEConcurrency(n int) TechStackOption {
	return func(s *TechStackService) {
		if n > 0 {
			s.cveWorkers = n
		}
	}
}

// NewTechStackService builds the use case. Deep-scan sources (subdomain
// enumeration, DNS, CVE) are optional and enabled via options.
func NewTechStackService(detector out.TechStackDetector, timeout time.Duration, opts ...TechStackOption) *TechStackService {
	s := &TechStackService{
		detector:   detector,
		timeout:    timeout,
		maxSubs:    25,
		subWorkers: 8,
		cveWorkers: 4,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

var _ in.TechStackService = (*TechStackService)(nil)

// Scan fingerprints target. When opts.Deep is true and the optional sources
// are configured, it also discovers subdomains (passively, via certificate
// transparency), fingerprints each one, and reports DNS records for the root
// domain. When opts.CVE is true, detected versioned technologies are
// cross-referenced against the vulnerability database.
//
// Non-fatal problems encountered along the way (an upstream throttling us,
// an enumeration failing) are reported in TechStackResult.Warnings instead
// of being silently folded into "no results".
func (s *TechStackService) Scan(ctx context.Context, target string, opts in.TechStackOptions) (*in.TechStackResult, error) {
	// The overall timeout scales with deep scans since they fan out into
	// many additional requests; a single flat budget would starve
	// subdomain scanning on anything but tiny domains.
	overall := s.timeout
	if opts.Deep {
		overall = s.timeout * time.Duration(s.maxSubs+2)
	}
	if opts.CVE && s.cve != nil && overall < s.timeout*4 {
		// NVD is rate limited (5 req/30s unauthenticated ≈ one token per 6s
		// after the initial burst), so a cross-reference of several
		// technologies needs room to pace through the limiter instead of
		// blowing the plain per-request budget and reporting false timeouts.
		overall = s.timeout * 4
	}
	ctx, cancel := context.WithTimeout(ctx, overall)
	defer cancel()

	start := time.Now()
	info, err := s.detector.Detect(ctx, target)
	if err != nil {
		return nil, err
	}

	var warnings []string
	if opts.Deep {
		root := hostutil.RootDomain(target)
		if root != "" {
			subs, warns := s.scanSubdomains(ctx, root)
			info.Subdomains = subs
			warnings = append(warnings, warns...)
			info.DNS = s.lookupDNS(ctx, root)
		}
	}

	if opts.CVE && s.cve != nil {
		warnings = append(warnings, s.checkCVE(ctx, info)...)
	}

	return &in.TechStackResult{Info: info, Duration: time.Since(start), Warnings: warnings}, nil
}

// checkCVE attaches known vulnerabilities to each detected technology that
// has a version and a known CPE mapping. Checks run concurrently but never
// abort the scan on failure: problems are deduplicated and returned as
// warnings so the user learns that results may be incomplete — a throttled
// NVD must never look like "this stack has no known CVEs".
func (s *TechStackService) checkCVE(ctx context.Context, info *domain.TechStackInfo) []string {
	type job struct {
		idx  int
		tech *domain.Technology
	}
	var jobs []job
	for i := range info.Technologies {
		t := &info.Technologies[i]
		if t.Version != "" {
			jobs = append(jobs, job{i, t})
		}
	}
	if len(jobs) == 0 {
		return nil
	}

	var (
		mu       sync.Mutex
		warnings []string
	)
	addWarning := func(msg string) {
		mu.Lock()
		defer mu.Unlock()
		if len(warnings) >= maxScanWarnings {
			return
		}
		for _, w := range warnings {
			if w == msg {
				return
			}
		}
		warnings = append(warnings, msg)
	}

	sem := make(chan struct{}, s.cveWorkers)
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// The shared context carries the scan-wide budget (scaled for
			// rate-limited pacing); the HTTP client bounds each request.
			cves, err := s.cve.Check(ctx, j.tech.Name, j.tech.Version)
			switch {
			case err == nil:
				if len(cves) > 0 {
					j.tech.CVEs = cves
				}
			case errors.Is(err, out.ErrRateLimited):
				addWarning("NVD rate-limited, CVE results may be incomplete")
			default:
				addWarning(fmt.Sprintf("NVD lookup failed: %v", err))
			}
		}(j)
	}
	wg.Wait()
	return warnings
}

// scanSubdomains discovers subdomains of root and fingerprints each one
// concurrently, bounded by s.subWorkers. Individual failures (host down,
// timeout, TLS error) are recorded per-subdomain rather than aborting the
// whole scan. A failure of the enumeration source itself is returned as a
// warning instead of being silently reported as "no subdomains".
func (s *TechStackService) scanSubdomains(ctx context.Context, root string) ([]domain.SubdomainInfo, []string) {
	if s.subdomains == nil {
		return nil, nil
	}

	hosts, err := s.subdomains.Enumerate(ctx, root)
	if err != nil {
		return nil, []string{fmt.Sprintf(
			"subdomain enumeration failed (%v), subdomain results may be incomplete", err)}
	}
	if len(hosts) == 0 {
		return nil, nil
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

	return results, nil
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
