package scanner

import (
	"context"
	"net"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/out"
)

// StdlibDNSLookuper is an out.DNSLookuper adapter backed by the standard
// library's DNS resolver. No external service or API key required.
type StdlibDNSLookuper struct{}

// NewDNSLookuper builds the adapter.
func NewDNSLookuper() out.DNSLookuper {
	return &StdlibDNSLookuper{}
}

// Lookup implements out.DNSLookuper.
func (l *StdlibDNSLookuper) Lookup(ctx context.Context, name string) (*domain.DNSInfo, error) {
	resolver := &net.Resolver{}
	info := &domain.DNSInfo{}

	if ns, err := resolver.LookupNS(ctx, name); err == nil {
		for _, n := range ns {
			info.NameServers = append(info.NameServers, n.Host)
		}
	}

	if mx, err := resolver.LookupMX(ctx, name); err == nil {
		for _, m := range mx {
			info.MXRecords = append(info.MXRecords, m.Host)
		}
	}

	if txt, err := resolver.LookupTXT(ctx, name); err == nil {
		info.TXTRecords = txt
	}

	// A DNS lookup failing entirely (e.g. domain doesn't resolve) isn't
	// treated as a hard error here — we still return whatever partial
	// info we gathered, since some record types commonly fail
	// independently of others (e.g. no MX record is normal).
	return info, nil
}
