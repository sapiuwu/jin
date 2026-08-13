package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/in"
)

// --- JSON shapes -------------------------------------------------------

type techEntry struct {
	Name       string       `json:"name"`
	Version    string       `json:"version,omitempty"`
	Confidence int          `json:"confidence"`
	Evidence   []string     `json:"evidence,omitempty"`
	CVEs       []domain.CVE `json:"cves,omitempty"`
}

type subdomainEntry struct {
	Host      string   `json:"host"`
	Reachable bool     `json:"reachable"`
	Stack     []string `json:"stack,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type techStackEnvelope struct {
	URL        string                 `json:"url"`
	Detected   bool                   `json:"detected"`
	Summary    []string               `json:"summary,omitempty"`
	Categories map[string][]techEntry `json:"categories,omitempty"`
	Subdomains []subdomainEntry       `json:"subdomains,omitempty"`
	DNS        *domain.DNSInfo        `json:"dns,omitempty"`
	ScannedAt  time.Time              `json:"scanned_at"`
	DurationMs int64                  `json:"duration_ms"`
}

// --- Rendering ----------------------------------------------------------

func (a *App) renderTechStack(res *in.TechStackResult, wantJSON bool) error {
	if wantJSON {
		return a.renderTechStackJSON(res)
	}
	return a.renderTechStackHuman(res)
}

func (a *App) renderTechStackJSON(res *in.TechStackResult) error {
	return a.emitJSON(buildTechStackEnvelope(res))
}

// buildTechStackEnvelope assembles the JSON report for a tech-stack scan.
// It is reused by the combined `scan` report so the two shapes match.
func buildTechStackEnvelope(res *in.TechStackResult) techStackEnvelope {
	info := res.Info
	env := techStackEnvelope{
		URL:        info.URL,
		Detected:   len(info.Technologies) > 0,
		ScannedAt:  time.Now(),
		DurationMs: res.Duration.Milliseconds(),
		DNS:        info.DNS,
	}

	if env.Detected {
		grouped := groupByCategory(info.Technologies)
		env.Categories = make(map[string][]techEntry, len(grouped))
		for cat, techs := range grouped {
			entries := make([]techEntry, 0, len(techs))
			for _, t := range techs {
				score, _ := normalizeConfidence(t.Confidence)
				entries = append(entries, techEntry{
					Name:       t.Name,
					Version:    t.Version,
					Confidence: score,
					Evidence:   t.Evidence,
					CVEs:       t.CVEs,
				})
			}
			env.Categories[cat] = entries
		}
		env.Summary = summaryLine(info.Technologies)
	}

	for _, s := range info.Subdomains {
		env.Subdomains = append(env.Subdomains, subdomainEntry{
			Host:      s.Host,
			Reachable: s.Reachable,
			Stack:     summaryLine(s.Technologies),
			Error:     s.Error,
		})
	}

	return env
}

func (a *App) renderTechStackHuman(res *in.TechStackResult) error {
	info := res.Info

	fmt.Fprintf(a.out, "🌐 URL: %s\n", info.URL)

	if len(info.Technologies) == 0 {
		fmt.Fprintln(a.out, "❌ No technologies fingerprinted.")
	} else {
		fmt.Fprintf(a.out, "🧩 Stack:  %s\n", strings.Join(summaryLine(info.Technologies), ", "))
	}
	fmt.Fprintf(a.out, "⏱️  Scan Time: %s\n", res.Duration.Round(time.Millisecond))

	if len(info.Technologies) > 0 {
		fmt.Fprintln(a.out)
		a.printByCategory(info.Technologies)
	}

	if info.DNS != nil {
		a.printDNS(info.DNS)
	}
	if len(info.Subdomains) > 0 {
		a.printSubdomains(info.Subdomains)
	}

	return nil
}

func (a *App) printDNS(dns *domain.DNSInfo) {
	fmt.Fprintln(a.out, "\n🗂️  DNS Records:")
	if len(dns.NameServers) > 0 {
		fmt.Fprintf(a.out, "  Nameservers: %s\n", strings.Join(dns.NameServers, ", "))
	}
	if len(dns.MXRecords) > 0 {
		fmt.Fprintf(a.out, "  MX Records:  %s\n", strings.Join(dns.MXRecords, ", "))
	}
	if len(dns.TXTRecords) > 0 {
		fmt.Fprintln(a.out, "  TXT Records:")
		for _, t := range dns.TXTRecords {
			fmt.Fprintf(a.out, "    • %s\n", t)
		}
	}
	if len(dns.NameServers) == 0 && len(dns.MXRecords) == 0 && len(dns.TXTRecords) == 0 {
		fmt.Fprintln(a.out, "  No records found.")
	}
}

func (a *App) printSubdomains(subs []domain.SubdomainInfo) {
	fmt.Fprintf(a.out, "\n🌍 Subdomains (%d discovered):\n", len(subs))
	tw := tabwriter.NewWriter(a.out, 2, 4, 1, ' ', 0)
	for _, s := range subs {
		if !s.Reachable {
			fmt.Fprintf(tw, "  %s\t%s\n", s.Host, a.paint(31, "unreachable"))
			continue
		}
		stack := strings.Join(summaryLine(s.Technologies), ", ")
		if stack == "" {
			stack = a.paint(90, "no technologies fingerprinted")
		}
		fmt.Fprintf(tw, "  %s\t%s\n", a.paint(32, s.Host), stack)
	}
	tw.Flush()
}

// categoryOrder controls display order — most identity-defining categories
// first, generic/miscellaneous last.
var categoryOrder = []string{
	"CMS",
	"Web Server",
	"Backend Runtime",
	"Programming Language",
	"Web Framework",
	"JavaScript Framework",
	"JavaScript Library",
	"CSS Framework",
	"WAF / Reverse Proxy",
	"Analytics",
	"CDN",
	"Security",
	"Other",
}

func (a *App) printByCategory(techs []domain.Technology) {
	grouped := groupByCategory(techs)
	tw := tabwriter.NewWriter(a.out, 2, 4, 1, ' ', 0)

	printed := make(map[string]bool)
	printCategory := func(cat string) {
		items, ok := grouped[cat]
		if !ok {
			return
		}
		printed[cat] = true
		fmt.Fprintf(tw, "%s\n", a.paint(36, "▸ "+cat))
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		for _, t := range items {
			score, label := normalizeConfidence(t.Confidence)
			name := t.Name
			if t.Version != "" {
				name = fmt.Sprintf("%s (%s)", t.Name, t.Version)
			}
			fmt.Fprintf(tw, "  %s\t%s\n", name, a.confidenceBadge(score, label))
			for _, e := range t.Evidence {
				fmt.Fprintf(tw, "    • %s\t\n", e)
			}
			for _, c := range t.CVEs {
				fmt.Fprintf(tw, "    🔴 %s %s\n", a.red(c.ID), c.URL)
			}
		}
	}

	for _, cat := range categoryOrder {
		printCategory(cat)
	}
	// Catch any categories the detector returned that we didn't anticipate.
	var extra []string
	for cat := range grouped {
		if !printed[cat] {
			extra = append(extra, cat)
		}
	}
	sort.Strings(extra)
	for _, cat := range extra {
		printCategory(cat)
	}

	tw.Flush()
}

// summaryLine produces a compact "WordPress, Nginx, PHP, jQuery, Cloudflare"
// style rollup, ordered by category priority then confidence.
func summaryLine(techs []domain.Technology) []string {
	sorted := make([]domain.Technology, len(techs))
	copy(sorted, techs)

	rank := func(cat string) int {
		for i, c := range categoryOrder {
			if c == cat {
				return i
			}
		}
		return len(categoryOrder)
	}

	sort.Slice(sorted, func(i, j int) bool {
		ri, rj := rank(sorted[i].Category), rank(sorted[j].Category)
		if ri != rj {
			return ri < rj
		}
		si, _ := normalizeConfidence(sorted[i].Confidence)
		sj, _ := normalizeConfidence(sorted[j].Confidence)
		return si > sj
	})

	names := make([]string, 0, len(sorted))
	for _, t := range sorted {
		names = append(names, t.Name)
	}
	return names
}

func groupByCategory(techs []domain.Technology) map[string][]domain.Technology {
	grouped := make(map[string][]domain.Technology)
	for _, t := range techs {
		cat := t.Category
		if cat == "" {
			cat = "Other"
		}
		grouped[cat] = append(grouped[cat], t)
	}
	return grouped
}

// --- Confidence helpers ---------------------------------------------------

// normalizeConfidence accepts a percentage string ("92%"), a bare number
// ("92"), or a qualitative label ("High"/"Medium"/"Low") and returns a
// 0-100 score plus canonical label.
func normalizeConfidence(raw string) (int, string) {
	trimmed := strings.TrimSpace(strings.TrimSuffix(raw, "%"))
	if n, err := strconv.Atoi(trimmed); err == nil {
		n = clamp(n, 0, 100)
		return n, labelForScore(n)
	}

	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "very high", "confirmed":
		return 97, "Very High"
	case "high":
		return 80, "High"
	case "medium", "moderate":
		return 55, "Medium"
	case "low":
		return 30, "Low"
	case "very low", "weak":
		return 12, "Very Low"
	default:
		return 50, "Unknown"
	}
}

func labelForScore(score int) string {
	switch {
	case score >= 90:
		return "Very High"
	case score >= 70:
		return "High"
	case score >= 45:
		return "Medium"
	case score >= 20:
		return "Low"
	default:
		return "Very Low"
	}
}

func clamp(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// confidenceBadge renders "High (80%)" with an ANSI color keyed to the
// score, when color output is enabled.
func (a *App) confidenceBadge(score int, label string) string {
	text := fmt.Sprintf("%s (%d%%)", label, score)
	code := 32 // green
	switch {
	case score < 40:
		code = 31 // red
	case score < 70:
		code = 33 // yellow
	}
	return a.paint(code, text)
}
