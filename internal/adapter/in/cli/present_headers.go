package cli

import (
	"fmt"

	"github.com/aliftech/jin/internal/port/in"
)

// renderHeadersHuman prints a focused security-headers view of a server-info
// scan: the evaluated headers with their pass/fail status, the resulting
// grade, and the raw header table.
func (a *App) renderHeadersHuman(res *in.ServerInfoResult) {
	info := res.Info
	fmt.Fprintf(a.out, "📋 Headers for %s\n", info.URL)
	if info.StatusCode != 0 {
		fmt.Fprintf(a.out, "✅ Status: %d\n", info.StatusCode)
	}

	a.printSecurity(res.Security)
	a.printHeaders(info)
}
