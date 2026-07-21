package info

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aliftech/jin/internal/core"
	"github.com/aliftech/jin/internal/module/info/dto"
)

// ---------------------------------------------------------------------------
// Types & construction
// ---------------------------------------------------------------------------

// CLIHandler renders scan results to a CLI. It is deliberately decoupled
// from os.Stdout so it can be unit tested and reused (e.g. piped output,
// --no-color, custom timeouts).
type CLIHandler struct {
	scanner core.ServerScanner
	out     io.Writer
	timeout time.Duration
	color   bool
}

// Option configures a CLIHandler.
type Option func(*CLIHandler)

// WithWriter overrides the output destination (default: os.Stdout).
func WithWriter(w io.Writer) Option { return func(h *CLIHandler) { h.out = w } }

// WithTimeout overrides the scan timeout (default: 10s).
func WithTimeout(d time.Duration) Option { return func(h *CLIHandler) { h.timeout = d } }

// WithColor toggles ANSI color output (default: auto, off if NO_COLOR is set).
func WithColor(enabled bool) Option { return func(h *CLIHandler) { h.color = enabled } }

func NewCLIHandler(scanner core.ServerScanner, opts ...Option) *CLIHandler {
	h := &CLIHandler{
		scanner: scanner,
		out:     os.Stdout,
		timeout: 10 * time.Second,
		color:   os.Getenv("NO_COLOR") == "",
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func (h *CLIHandler) HandleScan(url string, outputJSON bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	start := time.Now()
	scanInfo, err := h.scanner.Scan(ctx, url)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	elapsed := time.Since(start)

	checks := analyzeSecurityChecks(scanInfo)
	score, grade := scoreChecks(checks)

	if outputJSON {
		return h.printJSON(scanInfo, checks, score, grade, elapsed)
	}
	return h.printHumanReadable(scanInfo, checks, score, grade, elapsed)
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

type scanEnvelope struct {
	Data       any            `json:"data"`
	Security   securityReport `json:"security"`
	ScannedAt  time.Time      `json:"scanned_at"`
	DurationMs int64          `json:"duration_ms"`
}

type securityReport struct {
	Score  int           `json:"score"`
	Grade  string        `json:"grade"`
	Checks []checkResult `json:"checks"`
}

func (h *CLIHandler) printJSON(info *core.ServerInfo, checks []checkResult, score int, grade string, elapsed time.Duration) error {
	envelope := scanEnvelope{
		Data: dto.FromDomain(info),
		Security: securityReport{
			Score:  score,
			Grade:  grade,
			Checks: checks,
		},
		ScannedAt:  time.Now(),
		DurationMs: elapsed.Milliseconds(),
	}
	enc := json.NewEncoder(h.out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

// ---------------------------------------------------------------------------
// Human-readable output
// ---------------------------------------------------------------------------

func (h *CLIHandler) printHumanReadable(info *core.ServerInfo, checks []checkResult, score int, grade string, elapsed time.Duration) error {
	h.printBasicInfo(info, elapsed)
	h.printTLSInfo(info)
	h.printSecuritySummary(checks, score, grade)
	h.printHeaders(info)
	return nil
}

func (h *CLIHandler) printBasicInfo(info *core.ServerInfo, elapsed time.Duration) {
	fmt.Fprintf(h.out, "🌐 URL:          %s\n", info.URL)
	if info.RootDomain != "" && info.RootDomain != info.Domain {
		fmt.Fprintf(h.out, "🗃️  Base Domain:  %s\n", info.RootDomain)
	}
	if info.CloudProvider != "" && info.CloudProvider != "Unknown" {
		fmt.Fprintf(h.out, "☁️  Cloud:        %s\n", info.CloudProvider)
	}
	fmt.Fprintf(h.out, "✅ Status:       %d\n", info.StatusCode)
	if info.Server != "" {
		fmt.Fprintf(h.out, "🖥️  Server:      %s\n", info.Server)
	}
	if info.PoweredBy != "" {
		fmt.Fprintf(h.out, "⚡ Powered By:   %s\n", info.PoweredBy)
	}
	fmt.Fprintf(h.out, "📄 Content-Type: %s\n", info.ContentType)
	fmt.Fprintf(h.out, "⏱️  Scan Time:    %s\n", elapsed.Round(time.Millisecond))
}

func (h *CLIHandler) printTLSInfo(info *core.ServerInfo) {
	if info.TLSVersion == "" {
		return
	}
	fmt.Fprintf(h.out, "🔒 TLS Version:  %s\n", info.TLSVersion)
	fmt.Fprintf(h.out, "🔐 Cipher Suite: %s\n", info.TLSCipherSuite)
}

func (h *CLIHandler) printSecuritySummary(checks []checkResult, score int, grade string) {
	fmt.Fprintf(h.out, "\n🛡️  Security Insights: %s\n", h.colorGrade(grade, score))

	for _, c := range checks {
		icon := "✅"
		switch {
		case !c.Passed && c.Severity == sevCritical:
			icon = "🛑"
		case !c.Passed && c.Severity == sevHigh:
			icon = "⚠️"
		case !c.Passed && c.Severity == sevMedium:
			icon = "⚠️"
		case !c.Passed && c.Severity == sevLow:
			icon = "ℹ️"
		}
		fmt.Fprintf(h.out, "  %s %-28s %s\n", icon, c.Name+":", c.Detail)
	}
}

func (h *CLIHandler) printHeaders(info *core.ServerInfo) {
	fmt.Fprintln(h.out, "\n📋 Headers:")

	keys := make([]string, 0, len(info.Headers))
	for k := range info.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	tw := tabwriter.NewWriter(h.out, 2, 4, 1, ' ', 0)
	for _, key := range keys {
		value := info.Headers[key]
		if strings.EqualFold(key, "Set-Cookie") {
			value = summarizeCookies(value)
		}
		fmt.Fprintf(tw, "  %s:\t%s\n", key, value)
	}
	tw.Flush()
}

// colorGrade renders "B+ (82/100)" with an ANSI color keyed to grade, when
// color output is enabled.
func (h *CLIHandler) colorGrade(grade string, score int) string {
	text := fmt.Sprintf("%s (%d/100)", grade, score)
	if !h.color {
		return text
	}
	code := "32" // green
	switch {
	case score < 50:
		code = "31" // red
	case score < 80:
		code = "33" // yellow
	}
	return fmt.Sprintf("\033[%sm%s\033[0m", code, text)
}

// ---------------------------------------------------------------------------
// Security analysis
// ---------------------------------------------------------------------------

const (
	sevCritical = "critical"
	sevHigh     = "high"
	sevMedium   = "medium"
	sevLow      = "low"
)

type checkResult struct {
	Name     string `json:"name"`
	Passed   bool   `json:"passed"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	Weight   int    `json:"weight"`
}

var versionDisclosureRE = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

// analyzeSecurityChecks derives a fixed set of weighted checks from the scan
// result. It reuses signals already computed by the domain layer (HasCSP,
// HasHSTS, HasXFrameOptions, CSPWarnings, CookieWarnings) and adds checks
// against raw response headers that aren't otherwise surfaced.
func analyzeSecurityChecks(info *core.ServerInfo) []checkResult {
	var checks []checkResult

	// --- Transport security -------------------------------------------------
	checks = append(checks, checkResult{
		Name: "TLS", Passed: info.TLSVersion != "", Weight: 15,
		Severity: sevCritical,
		Detail:   pick(info.TLSVersion != "", "Serving over "+info.TLSVersion, "No TLS detected"),
	})

	checks = append(checks, checkResult{
		Name: "HSTS", Passed: info.HasHSTS, Weight: 10,
		Severity: sevHigh,
		Detail:   pick(info.HasHSTS, "Strict-Transport-Security present", "Missing Strict-Transport-Security header"),
	})

	// --- Content Security Policy ---------------------------------------------
	cspOK := (info.HasCSP || info.HasCSPReportOnly) && len(info.CSPWarnings) == 0
	cspDetail := "Not implemented"
	switch {
	case len(info.CSPWarnings) > 0:
		cspDetail = fmt.Sprintf("%d issue(s): %s", len(info.CSPWarnings), strings.Join(info.CSPWarnings, "; "))
	case info.HasCSP:
		cspDetail = "Policy enforced"
	case info.HasCSPReportOnly:
		cspDetail = "Policy is report-only (not enforced)"
	}
	checks = append(checks, checkResult{
		Name: "Content-Security-Policy", Passed: cspOK, Weight: 20,
		Severity: sevHigh, Detail: cspDetail,
	})

	// --- Clickjacking ---------------------------------------------------------
	checks = append(checks, checkResult{
		Name: "X-Frame-Options", Passed: info.HasXFrameOptions, Weight: 10,
		Severity: sevMedium,
		Detail:   pick(info.HasXFrameOptions, "Clickjacking protection enforced", "Missing X-Frame-Options (or frame-ancestors in CSP)"),
	})

	// --- MIME sniffing ----------------------------------------------------
	xcto := getHeader(info.Headers, "X-Content-Type-Options")
	checks = append(checks, checkResult{
		Name: "X-Content-Type-Options", Passed: strings.EqualFold(xcto, "nosniff"), Weight: 10,
		Severity: sevMedium,
		Detail:   pick(strings.EqualFold(xcto, "nosniff"), "nosniff set", "Missing or misconfigured (MIME sniffing possible)"),
	})

	// --- Referrer & permissions policies -------------------------------------
	refPolicy := getHeader(info.Headers, "Referrer-Policy")
	checks = append(checks, checkResult{
		Name: "Referrer-Policy", Passed: refPolicy != "", Weight: 5,
		Severity: sevLow,
		Detail:   pick(refPolicy != "", "Set to "+refPolicy, "Not set (defaults may leak referrer data)"),
	})

	permPolicy := getHeader(info.Headers, "Permissions-Policy")
	checks = append(checks, checkResult{
		Name: "Permissions-Policy", Passed: permPolicy != "", Weight: 5,
		Severity: sevLow,
		Detail:   pick(permPolicy != "", "Restricting browser features", "Not set"),
	})

	// --- Cookies --------------------------------------------------------------
	checks = append(checks, checkResult{
		Name: "Cookie Flags", Passed: len(info.CookieWarnings) == 0, Weight: 10,
		Severity: sevHigh,
		Detail: pick(len(info.CookieWarnings) == 0, "No obvious cookie issues",
			strings.Join(info.CookieWarnings, "; ")),
	})

	// --- CORS -------------------------------------------------------------
	acao := getHeader(info.Headers, "Access-Control-Allow-Origin")
	acac := getHeader(info.Headers, "Access-Control-Allow-Credentials")
	corsWildcardWithCreds := acao == "*" && strings.EqualFold(acac, "true")
	checks = append(checks, checkResult{
		Name: "CORS", Passed: !corsWildcardWithCreds, Weight: 10,
		Severity: sevCritical,
		Detail: func() string {
			switch {
			case corsWildcardWithCreds:
				return "Wildcard origin (*) combined with credentials=true — critical misconfiguration"
			case acao == "*":
				return "Wildcard origin (*) allowed, no credentials — low risk"
			case acao != "":
				return "Restricted to: " + acao
			default:
				return "No CORS headers present"
			}
		}(),
	})

	// --- Information disclosure ------------------------------------------
	discloses := versionDisclosureRE.MatchString(info.Server) || versionDisclosureRE.MatchString(info.PoweredBy)
	checks = append(checks, checkResult{
		Name: "Version Disclosure", Passed: !discloses, Weight: 5,
		Severity: sevLow,
		Detail:   pick(!discloses, "No version numbers exposed in Server/X-Powered-By", "Server/X-Powered-By header reveals version info"),
	})

	return checks
}

// scoreChecks turns weighted pass/fail checks into a 0-100 score and letter
// grade.
func scoreChecks(checks []checkResult) (int, string) {
	var earned, total int
	for _, c := range checks {
		total += c.Weight
		if c.Passed {
			earned += c.Weight
		}
	}
	if total == 0 {
		return 0, "N/A"
	}
	score := (earned * 100) / total

	switch {
	case score >= 97:
		return score, "A+"
	case score >= 93:
		return score, "A"
	case score >= 90:
		return score, "A-"
	case score >= 87:
		return score, "B+"
	case score >= 83:
		return score, "B"
	case score >= 80:
		return score, "B-"
	case score >= 70:
		return score, "C"
	case score >= 60:
		return score, "D"
	default:
		return score, "F"
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func pick(cond bool, ifTrue, ifFalse string) string {
	if cond {
		return ifTrue
	}
	return ifFalse
}

// getHeader looks up a header case-insensitively from a plain map, since
// upstream maps aren't guaranteed to use canonical MIME header casing.
func getHeader(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// summarizeCookies redacts cookie values while preserving the security-
// relevant attributes (Secure / HttpOnly / SameSite), which the original
// naive comma-split silently discarded.
func summarizeCookies(raw string) string {
	chunks := strings.Split(raw, ",")
	summaries := make([]string, 0, len(chunks))

	for _, chunk := range chunks {
		attrs := strings.Split(chunk, ";")
		if len(attrs) == 0 {
			continue
		}
		nameVal := strings.SplitN(strings.TrimSpace(attrs[0]), "=", 2)
		name := strings.TrimSpace(nameVal[0])
		if name == "" {
			continue
		}

		var secure, httpOnly bool
		sameSite := ""
		for _, a := range attrs[1:] {
			a = strings.TrimSpace(a)
			switch {
			case strings.EqualFold(a, "Secure"):
				secure = true
			case strings.EqualFold(a, "HttpOnly"):
				httpOnly = true
			case strings.HasPrefix(strings.ToLower(a), "samesite"):
				parts := strings.SplitN(a, "=", 2)
				if len(parts) == 2 {
					sameSite = strings.TrimSpace(parts[1])
				}
			}
		}

		var flags []string
		if secure {
			flags = append(flags, "Secure")
		}
		if httpOnly {
			flags = append(flags, "HttpOnly")
		}
		if sameSite != "" {
			flags = append(flags, "SameSite="+sameSite)
		}
		if len(flags) == 0 {
			flags = append(flags, "no security flags set")
		}

		summaries = append(summaries, fmt.Sprintf("%s=<redacted> [%s]", name, strings.Join(flags, ", ")))
	}

	return strings.Join(summaries, ", ")
}