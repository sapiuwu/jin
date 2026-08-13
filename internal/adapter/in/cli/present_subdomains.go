package cli

import (
	"fmt"

	"github.com/aliftech/jin/internal/port/in"
)

type subdomainReport struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains,omitempty"`
	Error      string   `json:"error,omitempty"`
}

func (a *App) renderSubdomains(res *in.SubdomainResult, wantJSON bool) error {
	if wantJSON {
		return a.emitJSON(subdomainReport{
			Domain:     res.Domain,
			Subdomains: res.Subdomains,
			Error:      res.Error,
		})
	}

	fmt.Fprintf(a.out, "🌍 Subdomains discovered for %s (%d):\n", res.Domain, len(res.Subdomains))
	if res.Error != "" {
		fmt.Fprintf(a.out, "  %s %s\n", a.red("✗"), res.Error)
	}
	if len(res.Subdomains) == 0 {
		fmt.Fprintln(a.out, "  None found.")
		return nil
	}
	for _, s := range res.Subdomains {
		fmt.Fprintf(a.out, "  • %s\n", s)
	}
	return nil
}
