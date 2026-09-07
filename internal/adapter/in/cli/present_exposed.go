package cli

import (
	"fmt"

	"github.com/aliftech/jin/internal/port/in"
)

func (a *App) renderExposed(res *in.ExposedResult) {
	r := res.Result
	fmt.Fprintf(a.out, "📂 Exposed-file probe for %s:\n", r.URL)

	found := 0
	for _, f := range r.Files {
		if !f.Found {
			continue
		}
		found++
		icon := a.red("✗")
		if f.Status == 200 {
			icon = a.red("⚠️")
		}
		size := ""
		if f.Size > 0 {
			size = fmt.Sprintf(" (%d bytes)", f.Size)
		}
		fmt.Fprintf(a.out, "  %s %s [%d]%s\n", icon, a.cyan(f.Path), f.Status, size)
		fmt.Fprintf(a.out, "      %s\n", f.Note)
	}

	if found == 0 {
		fmt.Fprintf(a.out, "\n%s No exposed files detected.\n", a.green("✓"))
		return
	}
	fmt.Fprintf(a.out, "\n%s %d potentially exposed path(s) found.\n", a.yellow("⚠️"), found)
}
