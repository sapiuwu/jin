package service

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// SubdomainService is the subdomain-enumeration use case.
type SubdomainService struct {
	enumerator out.SubdomainEnumerator
	timeout    time.Duration
}

// NewSubdomainService builds the use case.
func NewSubdomainService(enumerator out.SubdomainEnumerator, timeout time.Duration) *SubdomainService {
	return &SubdomainService{enumerator: enumerator, timeout: timeout}
}

var _ in.SubdomainService = (*SubdomainService)(nil)

// Enumerate discovers subdomains of a root domain passively.
func (s *SubdomainService) Enumerate(ctx context.Context, domain string) (*in.SubdomainResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	hosts, err := s.enumerator.Enumerate(ctx, domain)
	if err != nil {
		return &in.SubdomainResult{Domain: domain, Error: err.Error()}, nil
	}
	return &in.SubdomainResult{Domain: domain, Subdomains: hosts}, nil
}
