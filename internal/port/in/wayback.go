package in

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// WaybackResult is the outcome of a Wayback URL-discovery use case.
type WaybackResult struct {
	Result   *domain.WaybackResult
	Duration time.Duration
}

// WaybackService discovers historic URLs for a domain via the Wayback Machine.
type WaybackService interface {
	List(ctx context.Context, domain string) (*WaybackResult, error)
}
