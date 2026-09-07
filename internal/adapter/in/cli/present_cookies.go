package cli

import (
	"fmt"
	"strings"

	"github.com/aliftech/jin/internal/port/in"
)

func (a *App) renderCookies(res *in.CookieResult) {
	info := res.Analysis
	fmt.Fprintf(a.out, "🍪 Cookies for %s:\n", info.URL)

	if len(info.Cookies) == 0 {
		fmt.Fprintln(a.out, "  No Set-Cookie headers observed.")
		return
	}

	for _, c := range info.Cookies {
		var flags []string
		if c.Secure {
			flags = append(flags, a.green("Secure"))
		} else {
			flags = append(flags, a.red("no-Secure"))
		}
		if c.HttpOnly {
			flags = append(flags, a.green("HttpOnly"))
		} else {
			flags = append(flags, a.red("no-HttpOnly"))
		}
		same := c.SameSite
		if same == "" {
			same = "not set"
		}
		fmt.Fprintf(a.out, "  • %s  [%s]  SameSite=%s\n", a.cyan(c.Name), strings.Join(flags, " "), same)
	}

	if len(info.Warnings) == 0 {
		fmt.Fprintf(a.out, "\n%s No cookie issues found.\n", a.green("✓"))
		return
	}
	fmt.Fprintf(a.out, "\n%s Cookie warnings (%d):\n", a.yellow("⚠️"), len(info.Warnings))
	for _, w := range info.Warnings {
		fmt.Fprintf(a.out, "  %s %s\n", a.red("✗"), w)
	}
}
