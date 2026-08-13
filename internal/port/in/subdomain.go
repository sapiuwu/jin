package in

import (
	"context"
)

// SubdomainResult is the outcome of a subdomain-enumeration use case.
type SubdomainResult struct {
	Domain     string
	Subdomains []string
	Error      string
}

// SubdomainService discovers subdomains of a root domain using passive
// sources (e.g. certificate transparency logs).
type SubdomainService interface {
	Enumerate(ctx context.Context, domain string) (*SubdomainResult, error)
}
