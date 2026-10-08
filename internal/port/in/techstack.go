package in

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// TechStackResult is the outcome of a tech-stack fingerprinting use case.
type TechStackResult struct {
	Info     *domain.TechStackInfo
	Duration time.Duration
	// Warnings reports non-fatal problems that affect result completeness
	// (e.g. "NVD rate-limited, CVE results may be incomplete"). Renderers
	// must surface these — dropping them silently would make a throttled
	// scan indistinguishable from a clean one.
	Warnings []string
}

// TechStackOptions controls a tech-stack scan's behaviour.
type TechStackOptions struct {
	// Deep enables passive subdomain discovery + DNS record lookup.
	Deep bool
	// CVE enables a cross-reference of detected (versioned) technologies
	// against the NVD advisory database.
	CVE bool
}

// TechStackService fingerprints the technology stack of a target. When
// Deep is true, implementations should also discover subdomains and DNS
// records for the root domain. When CVE is true, they should attach known
// vulnerabilities to detected technologies.
type TechStackService interface {
	Scan(ctx context.Context, target string, opts TechStackOptions) (*TechStackResult, error)
}
