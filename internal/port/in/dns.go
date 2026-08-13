package in

import (
	"context"

	"github.com/aliftech/jin/internal/domain"
)

// DNSResult is the outcome of a DNS use case.
type DNSResult struct {
	Domain string
	DNS    *domain.DNSInfo
	Error  string
}

// DNSService resolves a domain's nameserver, mail exchange, and TXT records.
type DNSService interface {
	Lookup(ctx context.Context, domain string) (*DNSResult, error)
}
