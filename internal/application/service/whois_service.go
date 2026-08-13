package service

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// WhoisService is the whois/RDAP use case.
type WhoisService struct {
	provider out.WhoisProvider
	timeout  time.Duration
}

// NewWhoisService builds the use case.
func NewWhoisService(provider out.WhoisProvider, timeout time.Duration) *WhoisService {
	return &WhoisService{provider: provider, timeout: timeout}
}

var _ in.WhoisService = (*WhoisService)(nil)

// Lookup retrieves registration data for a domain.
func (s *WhoisService) Lookup(ctx context.Context, domain string) (*in.WhoisResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	info, err := s.provider.Lookup(ctx, domain)
	if err != nil {
		return &in.WhoisResult{Error: err.Error()}, nil
	}
	return &in.WhoisResult{Info: info}, nil
}
