package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// fakeTechDetector returns a canned fingerprint.
type fakeTechDetector struct {
	info *domain.TechStackInfo
	err  error
}

func (f *fakeTechDetector) Detect(context.Context, string) (*domain.TechStackInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.info, nil
}

var _ out.TechStackDetector = (*fakeTechDetector)(nil)

// fakeCVEChecker returns a canned result/error and counts its calls.
// Checks run concurrently in the use case, so the counter is guarded.
type fakeCVEChecker struct {
	mu    sync.Mutex
	cves  []domain.CVE
	err   error
	calls int
}

func (f *fakeCVEChecker) Check(context.Context, string, string) ([]domain.CVE, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.cves, f.err
}

func (f *fakeCVEChecker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

var _ out.CVEChecker = (*fakeCVEChecker)(nil)

// fakeEnumerator returns a canned subdomain list or failure.
type fakeEnumerator struct {
	hosts []string
	err   error
}

func (f *fakeEnumerator) Enumerate(context.Context, string) ([]string, error) {
	return f.hosts, f.err
}

var _ out.SubdomainEnumerator = (*fakeEnumerator)(nil)

func techWithVersions(names ...string) *domain.TechStackInfo {
	info := &domain.TechStackInfo{URL: "https://example.com"}
	for _, n := range names {
		info.Technologies = append(info.Technologies, domain.Technology{Name: n, Version: "1.2.3"})
	}
	return info
}

func TestTechStackScanSurfacesRateLimitWarning(t *testing.T) {
	detector := &fakeTechDetector{info: techWithVersions("Nginx")}
	cve := &fakeCVEChecker{err: fmt.Errorf("nvd returned status 403: %w", out.ErrRateLimited)}
	s := NewTechStackService(detector, time.Second, WithCVEChecker(cve))

	res, err := s.Scan(context.Background(), "example.com", in.TechStackOptions{CVE: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	want := "NVD rate-limited, CVE results may be incomplete"
	if len(res.Warnings) != 1 || res.Warnings[0] != want {
		t.Errorf("Scan() warnings = %v, want [%q]", res.Warnings, want)
	}
	if len(res.Info.Technologies[0].CVEs) != 0 {
		t.Errorf("technologies carry CVEs after a throttled lookup: %v", res.Info.Technologies[0].CVEs)
	}
}

func TestTechStackScanWarnsOnCVEFailure(t *testing.T) {
	detector := &fakeTechDetector{info: techWithVersions("Nginx")}
	cve := &fakeCVEChecker{err: errors.New("connection refused")}
	s := NewTechStackService(detector, time.Second, WithCVEChecker(cve))

	res, err := s.Scan(context.Background(), "example.com", in.TechStackOptions{CVE: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "NVD lookup failed") {
		t.Errorf("Scan() warnings = %v, want a single \"NVD lookup failed\" warning", res.Warnings)
	}
}

func TestTechStackScanDeduplicatesAndCapsWarnings(t *testing.T) {
	detector := &fakeTechDetector{info: techWithVersions("Nginx", "PHP", "Apache", "jQuery")}
	cve := &fakeCVEChecker{err: errors.New("nvd down")}
	s := NewTechStackService(detector, time.Second, WithCVEChecker(cve))

	res, err := s.Scan(context.Background(), "example.com", in.TechStackOptions{CVE: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if cve.callCount() != 4 {
		t.Errorf("Check() called %d times, want 4 (one per versioned tech)", cve.callCount())
	}
	if len(res.Warnings) != 1 {
		t.Errorf("Scan() warnings = %v, want identical errors deduplicated to one", res.Warnings)
	}
}

func TestTechStackScanReportsCVEsWithoutWarnings(t *testing.T) {
	detector := &fakeTechDetector{info: techWithVersions("Nginx")}
	cve := &fakeCVEChecker{cves: []domain.CVE{{ID: "CVE-2024-1234", URL: "https://example.org"}}}
	s := NewTechStackService(detector, time.Second, WithCVEChecker(cve))

	res, err := s.Scan(context.Background(), "example.com", in.TechStackOptions{CVE: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("Scan() warnings = %v, want none on success", res.Warnings)
	}
	got := res.Info.Technologies[0].CVEs
	if len(got) != 1 || got[0].ID != "CVE-2024-1234" {
		t.Errorf("attached CVEs = %v, want CVE-2024-1234", got)
	}
}

func TestTechStackScanSkipsTechnologiesWithoutVersion(t *testing.T) {
	detector := &fakeTechDetector{info: &domain.TechStackInfo{
		URL:          "https://example.com",
		Technologies: []domain.Technology{{Name: "Nginx"}, {Name: "PHP", Version: "8.2"}},
	}}
	cve := &fakeCVEChecker{}
	s := NewTechStackService(detector, time.Second, WithCVEChecker(cve))

	res, err := s.Scan(context.Background(), "example.com", in.TechStackOptions{CVE: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if cve.callCount() != 1 {
		t.Errorf("Check() called %d times, want 1 (only the versioned technology)", cve.callCount())
	}
	if len(res.Warnings) != 0 {
		t.Errorf("Scan() warnings = %v, want none", res.Warnings)
	}
}

func TestTechStackScanWarnsWhenEnumerationFails(t *testing.T) {
	detector := &fakeTechDetector{info: techWithVersions()}
	s := NewTechStackService(detector, time.Second,
		WithSubdomainEnumerator(&fakeEnumerator{err: errors.New("crt.sh returned status 503")}))

	res, err := s.Scan(context.Background(), "example.com", in.TechStackOptions{Deep: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(res.Warnings) != 1 ||
		!strings.Contains(res.Warnings[0], "subdomain enumeration failed") ||
		!strings.Contains(res.Warnings[0], "crt.sh returned status 503") {
		t.Errorf("Scan() warnings = %v, want the enumeration failure surfaced", res.Warnings)
	}
	if len(res.Info.Subdomains) != 0 {
		t.Errorf("subdomains = %v, want none after a failed enumeration", res.Info.Subdomains)
	}
}

func TestTechStackScanEnumeratesWithoutWarnings(t *testing.T) {
	detector := &fakeTechDetector{info: techWithVersions()}
	s := NewTechStackService(detector, time.Second,
		WithSubdomainEnumerator(&fakeEnumerator{hosts: []string{"a.example.com", "b.example.com"}}))

	res, err := s.Scan(context.Background(), "example.com", in.TechStackOptions{Deep: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("Scan() warnings = %v, want none", res.Warnings)
	}
	if len(res.Info.Subdomains) != 2 {
		t.Errorf("subdomains = %d, want 2", len(res.Info.Subdomains))
	}
}
