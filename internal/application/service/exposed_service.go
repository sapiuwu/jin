package service

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// ExposedService is the exposed-files use case.
type ExposedService struct {
	checker out.ExposedChecker
	timeout time.Duration
}

// NewExposedService builds the use case.
func NewExposedService(checker out.ExposedChecker, timeout time.Duration) *ExposedService {
	return &ExposedService{checker: checker, timeout: timeout}
}

var _ in.ExposedService = (*ExposedService)(nil)

// Check probes a target for commonly-misconfigured exposed files.
func (s *ExposedService) Check(ctx context.Context, target string) (*in.ExposedResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	result, err := s.checker.Check(ctx, target)
	if err != nil {
		return nil, err
	}
	return &in.ExposedResult{Result: result, Duration: time.Since(start)}, nil
}
