package service

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// WaybackService is the Wayback URL-discovery use case.
type WaybackService struct {
	lister out.WaybackLister
	timeout time.Duration
}

// NewWaybackService builds the use case.
func NewWaybackService(lister out.WaybackLister, timeout time.Duration) *WaybackService {
	return &WaybackService{lister: lister, timeout: timeout}
}

var _ in.WaybackService = (*WaybackService)(nil)

// List discovers historic URLs for a domain via the Wayback Machine.
func (s *WaybackService) List(ctx context.Context, domain string) (*in.WaybackResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	result, err := s.lister.List(ctx, domain)
	if err != nil {
		return nil, err
	}
	return &in.WaybackResult{Result: result, Duration: time.Since(start)}, nil
}
