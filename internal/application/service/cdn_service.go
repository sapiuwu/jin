package service

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// CDNService is the CDN/origin analysis use case.
type CDNService struct {
	detector out.CDNDetector
	timeout  time.Duration
}

// NewCDNService builds the use case.
func NewCDNService(detector out.CDNDetector, timeout time.Duration) *CDNService {
	return &CDNService{detector: detector, timeout: timeout}
}

var _ in.CDNService = (*CDNService)(nil)

// Detect analyzes whether a target is fronted by a CDN and whether its origin
// is directly reachable.
func (s *CDNService) Detect(ctx context.Context, domain string) (*in.CDNResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	result, err := s.detector.Detect(ctx, domain)
	if err != nil {
		return nil, err
	}
	return &in.CDNResult{Result: result, Duration: time.Since(start)}, nil
}
