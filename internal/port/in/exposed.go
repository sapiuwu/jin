package in

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// ExposedResult is the outcome of an exposed-files use case.
type ExposedResult struct {
	Result   *domain.ExposedResult
	Duration time.Duration
}

// ExposedService probes a target for commonly-misconfigured exposed files.
type ExposedService interface {
	Check(ctx context.Context, target string) (*ExposedResult, error)
}
