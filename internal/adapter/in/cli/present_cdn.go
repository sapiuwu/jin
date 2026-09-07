package cli

import (
	"fmt"

	"github.com/aliftech/jin/internal/port/in"
)

func (a *App) renderCDN(res *in.CDNResult) {
	r := res.Result
	fmt.Fprintf(a.out, "🌐 CDN/origin analysis for %s:\n", r.Domain)

	if !r.Detected {
		fmt.Fprintf(a.out, "  %s No CDN/WAF detected in response headers.\n", a.yellow("ℹ️"))
	} else {
		fmt.Fprintf(a.out, "  CDN/WAF: %s\n", a.cyan(r.Provider))
		for _, ind := range r.Indicators {
			fmt.Fprintf(a.out, "    • %s\n", ind)
		}
	}

	if r.OriginExposed {
		fmt.Fprintf(a.out, "  %s Origin server appears directly reachable — CDN bypass possible.\n", a.red("✗"))
	} else {
		fmt.Fprintf(a.out, "  %s Origin not directly serving the domain (good).\n", a.green("✓"))
	}

	if len(r.Notes) > 0 {
		fmt.Fprintln(a.out, "  Notes:")
		for _, n := range r.Notes {
			fmt.Fprintf(a.out, "    • %s\n", n)
		}
	}
}
