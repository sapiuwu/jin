package cli

import (
	"fmt"

	"github.com/aliftech/jin/internal/port/in"
)

type dnsReport struct {
	Domain string         `json:"domain"`
	DNS    *domainDNSInfo `json:"dns,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// domainDNSInfo is a thin alias so the DNS report keeps the same field
// shape as the underlying domain model without importing it here.
type domainDNSInfo = struct {
	NameServers []string `json:"name_servers,omitempty"`
	MXRecords   []string `json:"mx_records,omitempty"`
	TXTRecords  []string `json:"txt_records,omitempty"`
}

func (a *App) renderDNS(res *in.DNSResult, wantJSON bool) error {
	if wantJSON {
		r := dnsReport{Domain: res.Domain, Error: res.Error}
		if res.DNS != nil {
			r.DNS = &domainDNSInfo{
				NameServers: res.DNS.NameServers,
				MXRecords:   res.DNS.MXRecords,
				TXTRecords:  res.DNS.TXTRecords,
			}
		}
		return a.emitJSON(r)
	}

	fmt.Fprintf(a.out, "🗂️  DNS Records for %s:\n", res.Domain)
	if res.Error != "" {
		fmt.Fprintf(a.out, "  %s %s\n", a.red("✗"), res.Error)
	}
	if res.DNS == nil {
		return nil
	}
	if len(res.DNS.NameServers) > 0 {
		fmt.Fprintf(a.out, "  Nameservers: %s\n", join(res.DNS.NameServers))
	}
	if len(res.DNS.MXRecords) > 0 {
		fmt.Fprintf(a.out, "  MX Records:  %s\n", join(res.DNS.MXRecords))
	}
	if len(res.DNS.TXTRecords) > 0 {
		fmt.Fprintln(a.out, "  TXT Records:")
		for _, t := range res.DNS.TXTRecords {
			fmt.Fprintf(a.out, "    • %s\n", t)
		}
	}
	if len(res.DNS.NameServers) == 0 && len(res.DNS.MXRecords) == 0 && len(res.DNS.TXTRecords) == 0 {
		fmt.Fprintln(a.out, "  No records found.")
	}
	return nil
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
