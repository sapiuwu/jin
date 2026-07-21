// internal/module/techstack/cli_handler.go
package techstack

// NOTE ON ASSUMED TYPES
// ----------------------------------------------------------------------
// This file replaces database-detection with general tech-stack
// fingerprinting (CMS, web server, language, JS frameworks, analytics,
// CDN, security tooling, etc.) — the same category of signal Wappalyzer /
// whatweb produce. It assumes the following shape in `core`, since the
// original file only exposed a DatabaseDetector:
//
//   type TechStackDetector interface {
//       Detect(ctx context.Context, url string) (*TechStackInfo, error)
//   }
//
//   type TechStackInfo struct {
//       URL          string
//       Technologies []Technology
//   }
//
//   type Technology struct {
//       Name       string   // e.g. "WordPress", "Nginx", "React"
//       Category   string   // e.g. "CMS", "Web Server", "JavaScript Framework"
//       Version    string   // optional, "" if unknown
//       Confidence string   // "High" / "Medium" / "Low" / "92%" / etc.
//       Evidence   []string // e.g. "Header: X-Powered-By: WordPress"
//   }
//
// Adjust the field/type names below to match your actual core package.
// ----------------------------------------------------------------------

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/aliftech/jin/internal/core"
)

// ---------------------------------------------------------------------------
// Types & construction
// ---------------------------------------------------------------------------

type CLIHandler struct {
	detector    core.TechStackDetector
	subdomains  core.SubdomainEnumerator // optional; nil disables subdomain discovery
	dns         core.DNSLookuper         // optional; nil disables DNS record lookup
	out         io.Writer
	timeout     time.Duration
	color       bool
	maxSubs     int // cap on how many discovered subdomains get individually scanned
	subWorkers  int // concurrency for per-subdomain scans
}

type Option func(*CLIHandler)

func WithWriter(w io.Writer) Option      { return func(h *CLIHandler) { h.out = w } }
func WithTimeout(d time.Duration) Option { return func(h *CLIHandler) { h.timeout = d } }
func WithColor(enabled bool) Option      { return func(h *CLIHandler) { h.color = enabled } }

// WithSubdomainEnumerator enables `--subdomains` deep scans by supplying a
// passive subdomain discovery source.
func WithSubdomainEnumerator(e core.SubdomainEnumerator) Option {
	return func(h *CLIHandler) { h.subdomains = e }
}

// WithDNSLookuper enables DNS record reporting (nameservers, MX, TXT) as
// part of deep scans.
func WithDNSLookuper(d core.DNSLookuper) Option {
	return func(h *CLIHandler) { h.dns = d }
}

// WithMaxSubdomains caps how many discovered subdomains get individually
// fingerprinted, to keep deep scans bounded on domains with hundreds of
// certificate transparency entries. Default: 25.
func WithMaxSubdomains(n int) Option {
	return func(h *CLIHandler) { h.maxSubs = n }
}

// WithSubdomainConcurrency sets how many subdomains are scanned in
// parallel. Default: 8.
func WithSubdomainConcurrency(n int) Option {
	return func(h *CLIHandler) { h.subWorkers = n }
}

func NewCLIHandler(detector core.TechStackDetector, opts ...Option) *CLIHandler {
	h := &CLIHandler{
		detector:   detector,
		out:        os.Stdout,
		timeout:    10 * time.Second,
		color:      os.Getenv("NO_COLOR") == "",
		maxSubs:    25,
		subWorkers: 8,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// HandleScan fingerprints target. When deep is true and a subdomain
// enumerator/DNS lookuper have been configured via options, it also
// discovers subdomains (passively, via certificate transparency),
// fingerprints each one, and reports DNS records for the root domain.
// Deep scans take meaningfully longer since they involve one HTTP request
// per discovered subdomain.
func (h *CLIHandler) HandleScan(target string, outputJSON bool, deep bool) error {
	// The overall timeout scales with deep scans since they fan out into
	// many additional requests; a single flat 10s budget would starve
	// subdomain scanning on anything but tiny domains.
	overall := h.timeout
	if deep {
		overall = h.timeout * time.Duration(h.maxSubs+2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), overall)
	defer cancel()

	start := time.Now()
	info, err := h.detector.Detect(ctx, target)
	if err != nil {
		return fmt.Errorf("tech stack detection failed: %w", err)
	}

	if deep {
		root := rootDomain(target)
		if root != "" {
			info.Subdomains = h.scanSubdomains(ctx, root)
			info.DNS = h.lookupDNS(ctx, root)
		}
	}

	elapsed := time.Since(start)

	if outputJSON {
		return h.printJSON(info, elapsed)
	}
	return h.printHumanReadable(info, elapsed)
}

// scanSubdomains discovers subdomains of root and fingerprints each one
// concurrently, bounded by h.subWorkers. Individual failures (host down,
// timeout, TLS error) are recorded per-subdomain rather than aborting the
// whole scan.
func (h *CLIHandler) scanSubdomains(ctx context.Context, root string) []core.SubdomainInfo {
	if h.subdomains == nil {
		return nil
	}

	hosts, err := h.subdomains.Enumerate(ctx, root)
	if err != nil || len(hosts) == 0 {
		return nil
	}
	if len(hosts) > h.maxSubs {
		hosts = hosts[:h.maxSubs]
	}

	results := make([]core.SubdomainInfo, len(hosts))
	sem := make(chan struct{}, h.subWorkers)
	var wg sync.WaitGroup

	for i, host := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			subCtx, cancel := context.WithTimeout(ctx, h.timeout)
			defer cancel()

			info, err := h.detector.Detect(subCtx, "https://"+host)
			if err != nil {
				results[i] = core.SubdomainInfo{Host: host, Reachable: false, Error: err.Error()}
				return
			}
			results[i] = core.SubdomainInfo{Host: host, Reachable: true, Technologies: info.Technologies}
		}(i, host)
	}
	wg.Wait()

	return results
}

func (h *CLIHandler) lookupDNS(ctx context.Context, root string) *core.DNSInfo {
	if h.dns == nil {
		return nil
	}
	info, err := h.dns.Lookup(ctx, root)
	if err != nil {
		return nil
	}
	return info
}

// rootDomain extracts a bare hostname from a URL or host:port string, for
// use as the subdomain-enumeration / DNS-lookup query. Note: this uses a
// naive last-two-labels heuristic and does not handle multi-part public
// suffixes correctly (e.g. "example.co.uk" would be truncated to
// "co.uk"). For full correctness, resolve against the public suffix list.
func rootDomain(target string) string {
	host := target
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		host = u.Host
	}
	if i := strings.Index(host, ":"); i != -1 {
		host = host[:i]
	}
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

type scanEnvelope struct {
	URL        string                 `json:"url"`
	Detected   bool                   `json:"detected"`
	Summary    []string               `json:"summary,omitempty"`
	Categories map[string][]techEntry `json:"categories,omitempty"`
	Subdomains []subdomainEntry       `json:"subdomains,omitempty"`
	DNS        *core.DNSInfo          `json:"dns,omitempty"`
	ScannedAt  time.Time              `json:"scanned_at"`
	DurationMs int64                  `json:"duration_ms"`
}

type techEntry struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Confidence int      `json:"confidence"`
	Evidence   []string `json:"evidence,omitempty"`
}

type subdomainEntry struct {
	Host      string   `json:"host"`
	Reachable bool     `json:"reachable"`
	Stack     []string `json:"stack,omitempty"`
	Error     string   `json:"error,omitempty"`
}

func (h *CLIHandler) printJSON(info *core.TechStackInfo, elapsed time.Duration) error {
	env := scanEnvelope{
		URL:        info.URL,
		Detected:   len(info.Technologies) > 0,
		ScannedAt:  time.Now(),
		DurationMs: elapsed.Milliseconds(),
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

	enc := json.NewEncoder(h.out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// ---------------------------------------------------------------------------
// Human-readable output
// ---------------------------------------------------------------------------

func (h *CLIHandler) printHumanReadable(info *core.TechStackInfo, elapsed time.Duration) error {
	fmt.Fprintf(h.out, "🌐 URL: %s\n", info.URL)

	if len(info.Technologies) == 0 {
		fmt.Fprintln(h.out, "❌ No technologies fingerprinted.")
	} else {
		fmt.Fprintf(h.out, "🧩 Stack:  %s\n", strings.Join(summaryLine(info.Technologies), ", "))
	}
	fmt.Fprintf(h.out, "⏱️  Scan Time: %s\n", elapsed.Round(time.Millisecond))

	if len(info.Technologies) > 0 {
		fmt.Fprintln(h.out)
		h.printByCategory(info.Technologies)
	}

	if info.DNS != nil {
		h.printDNS(info.DNS)
	}
	if len(info.Subdomains) > 0 {
		h.printSubdomains(info.Subdomains)
	}

	return nil
}

func (h *CLIHandler) printDNS(dns *core.DNSInfo) {
	fmt.Fprintln(h.out, "\n🗂️  DNS Records:")
	if len(dns.NameServers) > 0 {
		fmt.Fprintf(h.out, "  Nameservers: %s\n", strings.Join(dns.NameServers, ", "))
	}
	if len(dns.MXRecords) > 0 {
		fmt.Fprintf(h.out, "  MX Records:  %s\n", strings.Join(dns.MXRecords, ", "))
	}
	if len(dns.TXTRecords) > 0 {
		fmt.Fprintln(h.out, "  TXT Records:")
		for _, t := range dns.TXTRecords {
			fmt.Fprintf(h.out, "    • %s\n", t)
		}
	}
	if len(dns.NameServers) == 0 && len(dns.MXRecords) == 0 && len(dns.TXTRecords) == 0 {
		fmt.Fprintln(h.out, "  No records found.")
	}
}

func (h *CLIHandler) printSubdomains(subs []core.SubdomainInfo) {
	fmt.Fprintf(h.out, "\n🌍 Subdomains (%d discovered):\n", len(subs))
	tw := tabwriter.NewWriter(h.out, 2, 4, 1, ' ', 0)
	for _, s := range subs {
		if !s.Reachable {
			fmt.Fprintf(tw, "  %s\t%s\n", s.Host, h.colorize("31", "unreachable"))
			continue
		}
		stack := strings.Join(summaryLine(s.Technologies), ", ")
		if stack == "" {
			stack = h.colorize("90", "no technologies fingerprinted")
		}
		fmt.Fprintf(tw, "  %s\t%s\n", h.colorize("32", s.Host), stack)
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

func (h *CLIHandler) printByCategory(techs []core.Technology) {
	grouped := groupByCategory(techs)
	tw := tabwriter.NewWriter(h.out, 2, 4, 1, ' ', 0)

	printed := make(map[string]bool)
	printCategory := func(cat string) {
		items, ok := grouped[cat]
		if !ok {
			return
		}
		printed[cat] = true
		fmt.Fprintf(tw, "%s\n", h.colorize("36", "▸ "+cat))
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		for _, t := range items {
			score, label := normalizeConfidence(t.Confidence)
			name := t.Name
			if t.Version != "" {
				name = fmt.Sprintf("%s (%s)", t.Name, t.Version)
			}
			fmt.Fprintf(tw, "  %s\t%s\n", name, h.confidenceBadge(score, label))
			for _, e := range t.Evidence {
				fmt.Fprintf(tw, "    • %s\t\n", e)
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
func summaryLine(techs []core.Technology) []string {
	sorted := make([]core.Technology, len(techs))
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

func groupByCategory(techs []core.Technology) map[string][]core.Technology {
	grouped := make(map[string][]core.Technology)
	for _, t := range techs {
		cat := t.Category
		if cat == "" {
			cat = "Other"
		}
		grouped[cat] = append(grouped[cat], t)
	}
	return grouped
}

// ---------------------------------------------------------------------------
// Confidence helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Presentation helpers
// ---------------------------------------------------------------------------

func (h *CLIHandler) colorize(code, s string) string {
	if !h.color {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func (h *CLIHandler) confidenceBadge(score int, label string) string {
	text := fmt.Sprintf("%s (%d%%)", label, score)
	code := "32" // green
	switch {
	case score < 40:
		code = "31" // red
	case score < 70:
		code = "33" // yellow
	}
	return h.colorize(code, text)
}