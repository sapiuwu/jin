package service

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aliftech/jin/internal/domain"
)

var versionDisclosureRE = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

// AnalyzeSecurity derives a weighted security report from a scan result.
// It reuses signals already computed by the scanner (HasCSP, HasHSTS,
// HasXFrameOptions, CSPWarnings, CookieWarnings) and adds checks against
// raw response headers that aren't otherwise surfaced.
func AnalyzeSecurity(info *domain.ServerInfo) *domain.SecurityReport {
	checks := analyzeChecks(info)
	score, grade := scoreChecks(checks)
	return &domain.SecurityReport{Score: score, Grade: grade, Checks: checks}
}

func analyzeChecks(info *domain.ServerInfo) []domain.CheckResult {
	var checks []domain.CheckResult

	// --- Transport security -------------------------------------------------
	checks = append(checks, domain.CheckResult{
		Name: "TLS", Passed: info.TLSVersion != "", Weight: 15,
		Severity: domain.SeverityCritical,
		Detail:   pick(info.TLSVersion != "", "Serving over "+info.TLSVersion, "No TLS detected"),
	})

	checks = append(checks, domain.CheckResult{
		Name: "HSTS", Passed: info.HasHSTS, Weight: 10,
		Severity: domain.SeverityHigh,
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
	checks = append(checks, domain.CheckResult{
		Name: "Content-Security-Policy", Passed: cspOK, Weight: 20,
		Severity: domain.SeverityHigh, Detail: cspDetail,
	})

	// --- Clickjacking ---------------------------------------------------------
	checks = append(checks, domain.CheckResult{
		Name: "X-Frame-Options", Passed: info.HasXFrameOptions, Weight: 10,
		Severity: domain.SeverityMedium,
		Detail:   pick(info.HasXFrameOptions, "Clickjacking protection enforced", "Missing X-Frame-Options (or frame-ancestors in CSP)"),
	})

	// --- MIME sniffing ----------------------------------------------------
	xcto := getHeader(info.Headers, "X-Content-Type-Options")
	checks = append(checks, domain.CheckResult{
		Name: "X-Content-Type-Options", Passed: strings.EqualFold(xcto, "nosniff"), Weight: 10,
		Severity: domain.SeverityMedium,
		Detail:   pick(strings.EqualFold(xcto, "nosniff"), "nosniff set", "Missing or misconfigured (MIME sniffing possible)"),
	})

	// --- Referrer & permissions policies -------------------------------------
	refPolicy := getHeader(info.Headers, "Referrer-Policy")
	checks = append(checks, domain.CheckResult{
		Name: "Referrer-Policy", Passed: refPolicy != "", Weight: 5,
		Severity: domain.SeverityLow,
		Detail:   pick(refPolicy != "", "Set to "+refPolicy, "Not set (defaults may leak referrer data)"),
	})

	permPolicy := getHeader(info.Headers, "Permissions-Policy")
	checks = append(checks, domain.CheckResult{
		Name: "Permissions-Policy", Passed: permPolicy != "", Weight: 5,
		Severity: domain.SeverityLow,
		Detail:   pick(permPolicy != "", "Restricting browser features", "Not set"),
	})

	// --- Cookies --------------------------------------------------------------
	checks = append(checks, domain.CheckResult{
		Name: "Cookie Flags", Passed: len(info.CookieWarnings) == 0, Weight: 10,
		Severity: domain.SeverityHigh,
		Detail: pick(len(info.CookieWarnings) == 0, "No obvious cookie issues",
			strings.Join(info.CookieWarnings, "; ")),
	})

	// --- CORS -------------------------------------------------------------
	acao := getHeader(info.Headers, "Access-Control-Allow-Origin")
	acac := getHeader(info.Headers, "Access-Control-Allow-Credentials")
	corsWildcardWithCreds := acao == "*" && strings.EqualFold(acac, "true")
	checks = append(checks, domain.CheckResult{
		Name: "CORS", Passed: !corsWildcardWithCreds, Weight: 10,
		Severity: domain.SeverityCritical,
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
	checks = append(checks, domain.CheckResult{
		Name: "Version Disclosure", Passed: !discloses, Weight: 5,
		Severity: domain.SeverityLow,
		Detail:   pick(!discloses, "No version numbers exposed in Server/X-Powered-By", "Server/X-Powered-By header reveals version info"),
	})

	return checks
}

// scoreChecks turns weighted pass/fail checks into a 0-100 score and letter
// grade.
func scoreChecks(checks []domain.CheckResult) (int, string) {
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
