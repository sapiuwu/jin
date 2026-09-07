package in

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// CDNResult is the outcome of a CDN/origin analysis use case.
type CDNResult struct {
	Result   *domain.CDNResult
	Duration time.Duration
}

// CDNService analyzes whether a target is fronted by a CDN and whether its
// origin is directly reachable.
type CDNService interface {
	Detect(ctx context.Context, domain string) (*CDNResult, error)
}
