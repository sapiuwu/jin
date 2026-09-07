// Package cli implements the primary (driving) adapter of the application.
// It parses command-line input, invokes the use cases through the driving
// ports, and renders the results. It contains no business logic — every
// decision is delegated to the application layer.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/in"
)

// App is the CLI entry point, wired to the application's driving ports.
type App struct {
	info      in.ServerInfoService
	ports     in.PortScanService
	techstack in.TechStackService
	dns       in.DNSService
	subdm     in.SubdomainService
	whois     in.WhoisService
	fullscan  in.FullScanService
	cookie    in.CookieService
	tls       in.TLSService
	wayback   in.WaybackService
	exposed   in.ExposedService
	cdn       in.CDNService
	out       io.Writer
	color     bool
	output    string          // when set, JSON is written to this file
	format    string          // "table" (default) or "sarif"
	baseCtx   context.Context // canceled by Ctrl+C in interactive mode
}

// Option configures an App.
type Option func(*App)

// WithWriter overrides the output destination (default: os.Stdout).
func WithWriter(w io.Writer) Option { return func(a *App) { a.out = w } }

// WithColor toggles ANSI color output (default: auto, off if NO_COLOR is set).
func WithColor(enabled bool) Option { return func(a *App) { a.color = enabled } }

// WithDNS wires the DNS lookup use case.
func WithDNS(s in.DNSService) Option { return func(a *App) { a.dns = s } }

// WithSubdomains wires the subdomain-enumeration use case.
func WithSubdomains(s in.SubdomainService) Option { return func(a *App) { a.subdm = s } }

// WithWhois wires the whois/RDAP use case.
func WithWhois(s in.WhoisService) Option { return func(a *App) { a.whois = s } }

// WithFullScan wires the combined scan use case.
func WithFullScan(s in.FullScanService) Option { return func(a *App) { a.fullscan = s } }

// WithCookie wires the cookie-analysis use case.
func WithCookie(s in.CookieService) Option { return func(a *App) { a.cookie = s } }

// WithTLS wires the deep TLS inspection use case.
func WithTLS(s in.TLSService) Option { return func(a *App) { a.tls = s } }

// WithWayback wires the Wayback URL-discovery use case.
func WithWayback(s in.WaybackService) Option { return func(a *App) { a.wayback = s } }

// WithExposed wires the exposed-files use case.
func WithExposed(s in.ExposedService) Option { return func(a *App) { a.exposed = s } }

// WithCDN wires the CDN/origin analysis use case.
func WithCDN(s in.CDNService) Option { return func(a *App) { a.cdn = s } }

// NewApp builds the CLI adapter around the given driving ports.
func NewApp(info in.ServerInfoService, ports in.PortScanService, techstack in.TechStackService, opts ...Option) *App {
	a := &App{
		info:      info,
		ports:     ports,
		techstack: techstack,
		out:       os.Stdout,
		color:     os.Getenv("NO_COLOR") == "",
		format:    "table",
		baseCtx:   context.Background(),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Run executes a one-shot command line and returns an exit code. It is
// used for direct invocations such as `jin ports -t example.com`.
func (a *App) Run(args []string) int {
	fmt.Fprint(a.out, a.renderBanner())
	return a.execute(args)
}

// execute parses and dispatches a single command invocation. It is shared
// by the one-shot entry point and the interactive REPL, which is why it
// never prints the banner itself.
func (a *App) execute(args []string) int {
	p, err := parseArgs(args)
	if err != nil {
		a.errorf("Invalid usage: %v", err)
		a.help()
		return 1
	}
	if p.help {
		a.help()
		return 0
	}
	if len(p.positionals) == 0 {
		a.errorf("No target provided")
		a.help()
		return 1
	}
	if strings.HasPrefix(p.positionals[0], "-") {
		a.errorf("Unknown flag: %s", p.positionals[0])
		a.help()
		return 1
	}
	a.output = p.output
	if p.format != "" {
		a.format = p.format
	}

	command := strings.ToLower(p.positionals[0])

	// A bare command (e.g. `jin update`) has no explicit target; commands
	// that need one will report a sensible error. A non-command token is
	// treated as a direct URL target.
	if isCommand(command) {
		target := ""
		if len(p.positionals) > 1 {
			target = p.positionals[1]
		}
		return a.dispatch(command, target, p)
	}

	// Direct URL: jin https://example.com [--json] [--output ...]
	return a.runInfo(p.positionals[0], p)
}

// dispatch routes a recognized command (with its target, if any) to the
// appropriate runner. It is shared by one-shot invocations and the REPL.
func (a *App) dispatch(command, target string, p parsedArgs) int {
	switch command {
	case "info":
		return a.runInfo(target, p)
	case "ports":
		return a.runPorts(target, p)
	case "tech-stack":
		return a.runTechStack(target, p)
	case "dns":
		return a.runDNS(target, p)
	case "subdomains":
		return a.runSubdomains(target, p)
	case "whois":
		return a.runWhois(target, p)
	case "scan":
		return a.runScan(target, p)
	case "cookies":
		return a.runCookies(target, p)
	case "headers":
		return a.runHeaders(target, p)
	case "tls":
		return a.runTLS(target, p)
	case "wayback":
		return a.runWayback(target, p)
	case "exposed":
		return a.runExposed(target, p)
	case "cdn":
		return a.runCDN(target, p)
	case "watch":
		return a.runWatch(target, p)
	case "update":
		return a.runUpdate(p)
	case "diff":
		if len(p.positionals) < 3 {
			a.errorf("diff requires two report files: jin diff a.json b.json")
			return 1
		}
		return a.runDiff(p.positionals[1], p.positionals[2])
	case "completions":
		return a.runCompletions(p.positionals)
	default:
		a.errorf("Unknown command: %s", command)
		a.help()
		return 1
	}
}

// isCommand reports whether name is one of Jin's recognized subcommands.
func isCommand(name string) bool {
	switch name {
	case "info", "ports", "tech-stack", "dns", "subdomains", "whois",
		"cookies", "headers", "tls", "wayback", "exposed", "cdn",
		"scan", "watch", "update", "diff", "completions", "help":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Command runners
// ---------------------------------------------------------------------------

func (a *App) runInfo(target string, p parsedArgs) int {
	a.status("⏳", "Fetching full server info for %s...", target)
	res, err := a.info.Scan(a.baseCtx, target)
	if err != nil {
		if a.aborted() {
			fmt.Fprintln(a.out, "⏹️  Aborted")
			return 0
		}
		a.errorf("Error: %v", err)
		return 1
	}
	if a.format == "sarif" {
		if err := a.renderSARIF(res); err != nil {
			a.errorf("Error: %v", err)
			return 1
		}
		a.noteOutput()
		return a.applySecurityGate(res.Security, p)
	}
	wantJSON := p.json || a.output != ""
	if err := a.renderInfo(res, wantJSON); err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	if wantJSON {
		a.noteOutput()
	} else {
		a.finish(false)
	}
	return a.applySecurityGate(res.Security, p)
}

func (a *App) runPorts(target string, p parsedArgs) int {
	host := cleanHost(target)
	a.status("⏳", "Scanning open ports on %s...", host)
	res, err := a.ports.Scan(a.baseCtx, host, p.customPorts)
	if err != nil {
		if a.aborted() {
			fmt.Fprintln(a.out, "⏹️  Aborted")
			return 0
		}
		a.errorf("Error: %v", err)
		return 1
	}
	wantJSON := p.json || a.output != ""
	if err := a.renderPorts(res, wantJSON); err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	if wantJSON {
		a.noteOutput()
	} else {
		a.finish(false)
	}
	return 0
}

func (a *App) runTechStack(target string, p parsedArgs) int {
	if p.subdomains || p.cve {
		bits := []string{}
		if p.subdomains {
			bits = append(bits, "subdomains + DNS")
		}
		if p.cve {
			bits = append(bits, "CVE cross-reference")
		}
		a.status("⏳", "Detecting tech stack for %s (including %s)...", target, strings.Join(bits, " + "))
	} else {
		a.status("⏳", "Detecting tech stack for %s...", target)
	}
	res, err := a.techstack.Scan(a.baseCtx, target, in.TechStackOptions{Deep: p.subdomains, CVE: p.cve})
	if err != nil {
		if a.aborted() {
			fmt.Fprintln(a.out, "⏹️  Aborted")
			return 0
		}
		a.errorf("Error: %v", err)
		return 1
	}
	wantJSON := p.json || a.output != ""
	if err := a.renderTechStack(res, wantJSON); err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	if wantJSON {
		a.noteOutput()
	} else {
		a.finish(false)
	}
	return 0
}

func (a *App) runDNS(target string, p parsedArgs) int {
	domain := cleanHost(target)
	a.status("⏳", "Looking up DNS records for %s...", domain)
	res, err := a.dns.Lookup(a.baseCtx, domain)
	if err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	wantJSON := p.json || a.output != ""
	if err := a.renderDNS(res, wantJSON); err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	if wantJSON {
		a.noteOutput()
	} else {
		a.finish(false)
	}
	return 0
}

func (a *App) runSubdomains(target string, p parsedArgs) int {
	domain := cleanHost(target)
	a.status("⏳", "Enumerating subdomains of %s (certificate transparency)...", domain)
	res, err := a.subdm.Enumerate(a.baseCtx, domain)
	if err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	wantJSON := p.json || a.output != ""
	if err := a.renderSubdomains(res, wantJSON); err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	if wantJSON {
		a.noteOutput()
	} else {
		a.finish(false)
	}
	return 0
}

func (a *App) runWhois(target string, p parsedArgs) int {
	domain := cleanHost(target)
	a.status("⏳", "Looking up registration data for %s (RDAP)...", domain)
	res, err := a.whois.Lookup(a.baseCtx, domain)
	if err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	wantJSON := p.json || a.output != ""
	if err := a.renderWhois(res, wantJSON); err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	if wantJSON {
		a.noteOutput()
	} else {
		a.finish(false)
	}
	return 0
}

func (a *App) runScan(target string, p parsedArgs) int {
	a.status("⏳", "Running full recon on %s...", target)
	res, err := a.fullscan.Scan(a.baseCtx, target, in.FullScanOptions{
		Deep:        p.subdomains,
		CVE:         p.cve,
		CustomPorts: p.customPorts,
	})
	if err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	if a.format == "sarif" {
		if res.Info != nil {
			if err := a.renderSARIF(res.Info); err != nil {
				a.errorf("Error: %v", err)
				return 1
			}
		}
		a.noteOutput()
		return a.applySecurityGate(res.Info.Security, p)
	}
	wantJSON := p.json || a.output != ""
	if err := a.renderScan(res, wantJSON); err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	if wantJSON {
		a.noteOutput()
	} else {
		a.finish(false)
	}
	return a.applySecurityGate(res.Info.Security, p)
}

func (a *App) runDiff(fileA, fileB string) int {
	report, err := a.diffReports(fileA, fileB)
	if err != nil {
		a.errorf("Error: %v", err)
		return 1
	}
	if report == "" {
		fmt.Fprintf(a.out, "%s No differences found.\n", a.green("✓"))
		return 0
	}
	fmt.Fprintln(a.out, report)
	return 0
}

func (a *App) runCompletions(positionals []string) int {
	shell := "bash"
	if len(positionals) >= 2 {
		shell = positionals[1]
	}
	script, err := completionScript(shell)
	if err != nil {
		a.errorf("%v", err)
		return 1
	}
	fmt.Fprint(a.out, script)
	return 0
}

// ---------------------------------------------------------------------------
// CI security gate
// ---------------------------------------------------------------------------

// applySecurityGate returns a non-zero exit code when the security grade is
// below the configured threshold (--min-grade / --fail-on-low). It always
// prints nothing on its own; the report is already rendered.
func (a *App) applySecurityGate(sec *domain.SecurityReport, p parsedArgs) int {
	if sec == nil {
		return 0
	}
	threshold, ok := a.gradeThreshold(p)
	if !ok {
		return 0
	}
	if sec.Score >= threshold {
		return 0
	}
	fmt.Fprintf(a.out, "%s Security gate failed: grade %s (%d/100) is below minimum %s\n",
		a.red("✗"), sec.Grade, sec.Score, gradeLabel(threshold))
	return 1
}

// gradeThreshold resolves the minimum security score from the flags. The
// second return value reports whether a gate was requested at all.
func (a *App) gradeThreshold(p parsedArgs) (int, bool) {
	if p.minGrade != "" {
		t, ok := parseGrade(p.minGrade)
		if !ok {
			a.errorf("Invalid --min-grade %q (use A+..F)", p.minGrade)
			return 0, false
		}
		return t, true
	}
	if p.failOnLow {
		return 70, true // below C
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Output & color helpers
// ---------------------------------------------------------------------------

// emitJSON writes v as JSON to the configured output file (when -o is set)
// or to stdout otherwise.
func (a *App) emitJSON(v any) error {
	if a.output != "" {
		f, err := os.Create(a.output)
		if err != nil {
			return err
		}
		defer f.Close()
		return writeJSON(f, v)
	}
	return writeJSON(a.out, v)
}

// noteOutput prints a confirmation after a JSON report is written to a file.
func (a *App) noteOutput() {
	if a.output != "" {
		fmt.Fprintf(a.out, "%s Saved JSON report to %s\n", a.green("✓"), a.output)
	}
}

func (a *App) paint(code int, s string) string {
	if !a.color {
		return s
	}
	return fmt.Sprintf("\033[%dm%s\033[0m", code, s)
}

func (a *App) red(s string) string    { return a.paint(31, s) }
func (a *App) green(s string) string  { return a.paint(32, s) }
func (a *App) yellow(s string) string { return a.paint(33, s) }
func (a *App) blue(s string) string   { return a.paint(34, s) }
func (a *App) cyan(s string) string   { return a.paint(36, s) }
func (a *App) white(s string) string  { return a.paint(37, s) }

func (a *App) status(icon, format string, v ...any) {
	fmt.Fprintf(a.out, "%s %s\n", a.blue(icon), fmt.Sprintf(format, v...))
}

func (a *App) errorf(format string, v ...any) {
	fmt.Fprintf(a.out, "%s %s\n", a.red("✗"), fmt.Sprintf(format, v...))
}

// finish prints a short completion marker after human-readable output.
// Skipped for JSON output so piped/parsed output stays clean.
func (a *App) finish(wantJSON bool) {
	if wantJSON {
		return
	}
	fmt.Fprintf(a.out, "%s Done\n", a.green("✓"))
}

// aborted reports whether the base context was canceled (e.g. by Ctrl+C
// in interactive mode), in which case a scan error is expected.
func (a *App) aborted() bool {
	return a.baseCtx != nil && a.baseCtx.Err() != nil
}

// gradeLabel maps a minimum score back to its letter grade (for messages).
func gradeLabel(min int) string {
	for _, g := range []struct {
		label string
		score int
	}{
		{"A+", 97}, {"A", 93}, {"A-", 90}, {"B+", 87}, {"B", 83}, {"B-", 80},
		{"C", 70}, {"D", 60}, {"F", 0},
	} {
		if min >= g.score {
			return g.label
		}
	}
	return "F"
}

// parseGrade maps a letter grade to its minimum score.
func parseGrade(g string) (int, bool) {
	switch strings.ToUpper(strings.TrimSpace(g)) {
	case "A+":
		return 97, true
	case "A":
		return 93, true
	case "A-":
		return 90, true
	case "B+":
		return 87, true
	case "B":
		return 83, true
	case "B-":
		return 80, true
	case "C":
		return 70, true
	case "D":
		return 60, true
	case "F":
		return 0, true
	}
	return 0, false
}
