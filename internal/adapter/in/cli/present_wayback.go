package cli

import (
	"fmt"
	"time"

	"github.com/aliftech/jin/internal/port/in"
)

func (a *App) renderWayback(res *in.WaybackResult) {
	r := res.Result
	fmt.Fprintf(a.out, "🗞️  Wayback Machine snapshots for %s:\n", r.Domain)
	fmt.Fprintf(a.out, "  Total captures: %d\n", r.Count)
	fmt.Fprintf(a.out, "⏱️  Query time:    %s\n", res.Duration.Round(time.Millisecond))

	if r.Count == 0 {
		fmt.Fprintln(a.out, "  No archived URLs found.")
		return
	}

	// Show the most recent captures first (CDX returns oldest-first).
	limit := r.Count
	if limit > 25 {
		limit = 25
	}
	fmt.Fprintf(a.out, "  Showing %d most recent:\n", limit)
	for i := r.Count - limit; i < r.Count; i++ {
		s := r.Snapshots[i]
		ts := s.Timestamp
		if len(ts) >= 8 {
			ts = fmt.Sprintf("%s-%s-%s", ts[0:4], ts[4:6], ts[6:8])
		}
		fmt.Fprintf(a.out, "  • %s  %s  [%s]\n", ts, s.URL, s.MimeType)
	}
}
