// internal/scrape/dns.go
package scrape

import (
	"context"
	"net"

	"github.com/aliftech/jin/internal/core"
)

type stdlibDNSLookuper struct{}

// NewDNSLookuper returns a core.DNSLookuper backed by the standard
// library's DNS resolver. No external service or API key required.
func NewDNSLookuper() core.DNSLookuper {
	return &stdlibDNSLookuper{}
}

func (l *stdlibDNSLookuper) Lookup(ctx context.Context, domain string) (*core.DNSInfo, error) {
	resolver := &net.Resolver{}
	info := &core.DNSInfo{}

	if ns, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, n := range ns {
			info.NameServers = append(info.NameServers, n.Host)
		}
	}

	if mx, err := resolver.LookupMX(ctx, domain); err == nil {
		for _, m := range mx {
			info.MXRecords = append(info.MXRecords, m.Host)
		}
	}

	if txt, err := resolver.LookupTXT(ctx, domain); err == nil {
		info.TXTRecords = txt
	}

	// A DNS lookup failing entirely (e.g. domain doesn't resolve) isn't
	// treated as a hard error here — we still return whatever partial
	// info we gathered, since some record types commonly fail
	// independently of others (e.g. no MX record is normal).
	return info, nil
}