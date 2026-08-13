package service

import (
	"context"

	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// DNSService is the DNS-lookup use case.
type DNSService struct {
	lookup out.DNSLookuper
}

// NewDNSService builds the use case.
func NewDNSService(lookup out.DNSLookuper) *DNSService {
	return &DNSService{lookup: lookup}
}

var _ in.DNSService = (*DNSService)(nil)

// Lookup resolves DNS records for a domain.
func (s *DNSService) Lookup(ctx context.Context, domain string) (*in.DNSResult, error) {
	info, err := s.lookup.Lookup(ctx, domain)
	if err != nil {
		return &in.DNSResult{Domain: domain, Error: err.Error()}, nil
	}
	return &in.DNSResult{Domain: domain, DNS: info}, nil
}
