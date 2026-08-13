package in

import (
	"context"

	"github.com/aliftech/jin/internal/domain"
)

// WhoisResult is the outcome of a whois/RDAP use case.
type WhoisResult struct {
	Info  *domain.WhoisInfo
	Error string
}

// WhoisService looks up passive registration data for a domain.
type WhoisService interface {
	Lookup(ctx context.Context, domain string) (*WhoisResult, error)
}
