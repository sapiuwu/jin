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
}

// TechStackService fingerprints the technology stack of a target. When
// deep is true, implementations should also discover subdomains and DNS
// records for the root domain.
type TechStackService interface {
	Scan(ctx context.Context, target string, deep bool) (*TechStackResult, error)
}
