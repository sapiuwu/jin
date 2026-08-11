package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/in"
)

// serverInfoResponse is the JSON shape for the server-info data payload.
type serverInfoResponse struct {
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	Server         string            `json:"server"`
	PoweredBy      string            `json:"powered_by"`
	ContentType    string            `json:"content_type"`
	TLSVersion     string            `json:"tls_version,omitempty"`
	TLSCipherSuite string            `json:"tls_cipher_suite,omitempty"`
	Headers        map[string]string `json:"headers"`
	Error          string            `json:"error,omitempty"`
}

// infoEnvelope wraps the payload with metadata.
type infoEnvelope struct {
	Data       any                    `json:"data"`
	Security   *domain.SecurityReport `json:"security"`
	ScannedAt  time.Time              `json:"scanned_at"`
	DurationMs int64                  `json:"duration_ms"`
}

func (a *App) renderInfo(res *in.ServerInfoResult, outputJSON bool) error {
	if outputJSON {
		return a.renderInfoJSON(res)
	}
	return a.renderInfoHuman(res)
}

func (a *App) renderInfoJSON(res *in.ServerInfoResult) error {
	data := &serverInfoResponse{
		URL:            res.Info.URL,
		StatusCode:     res.Info.StatusCode,
		Server:         res.Info.Server,
		PoweredBy:      res.Info.PoweredBy,
		ContentType:    res.Info.ContentType,
		TLSVersion:     res.Info.TLSVersion,
		TLSCipherSuite: res.Info.TLSCipherSuite,
		Headers:        res.Info.Headers,
	}
	env := infoEnvelope{
		Data:       data,
		Security:   res.Security,
		ScannedAt:  time.Now(),
		DurationMs: res.Duration.Milliseconds(),
	}
	return writeJSON(a.out, env)
}

func (a *App) renderInfoHuman(res *in.ServerInfoResult) error {
	info := res.Info

	fmt.Fprintf(a.out, "🌐 URL:          %s\n", info.URL)
	if info.RootDomain != "" && info.RootDomain != info.Domain {
		fmt.Fprintf(a.out, "🗃️  Base Domain:  %s\n", info.RootDomain)
	}
	if info.CloudProvider != "" && info.CloudProvider != "Unknown" {
		fmt.Fprintf(a.out, "☁️  Cloud:        %s\n", info.CloudProvider)
	}
	fmt.Fprintf(a.out, "✅ Status:       %d\n", info.StatusCode)
	if info.Server != "" {
		fmt.Fprintf(a.out, "🖥️  Server:      %s\n", info.Server)
	}
	if info.PoweredBy != "" {
		fmt.Fprintf(a.out, "⚡ Powered By:   %s\n", info.PoweredBy)
	}
	fmt.Fprintf(a.out, "📄 Content-Type: %s\n", info.ContentType)
	fmt.Fprintf(a.out, "⏱️  Scan Time:    %s\n", res.Duration.Round(time.Millisecond))

	if info.TLSVersion != "" {
		fmt.Fprintf(a.out, "🔒 TLS Version:  %s\n", info.TLSVersion)
		fmt.Fprintf(a.out, "🔐 Cipher Suite: %s\n", info.TLSCipherSuite)
	}

	a.printSecurity(res.Security)
	a.printHeaders(info)
	return nil
}

func (a *App) printSecurity(report *domain.SecurityReport) {
	if report == nil {
		return
	}
	fmt.Fprintf(a.out, "\n🛡️  Security Insights: %s\n", a.colorGrade(report.Grade, report.Score))

	for _, c := range report.Checks {
		icon := "✅"
		switch {
		case !c.Passed && c.Severity == domain.SeverityCritical:
			icon = "🛑"
		case !c.Passed && (c.Severity == domain.SeverityHigh || c.Severity == domain.SeverityMedium):
			icon = "⚠️"
		case !c.Passed && c.Severity == domain.SeverityLow:
			icon = "ℹ️"
		}
		fmt.Fprintf(a.out, "  %s %-28s %s\n", icon, c.Name+":", c.Detail)
	}
}

// colorGrade renders "B+ (82/100)" with an ANSI color keyed to the score,
// when color output is enabled.
func (a *App) colorGrade(grade string, score int) string {
	text := fmt.Sprintf("%s (%d/100)", grade, score)
	code := 32 // green
	switch {
	case score < 50:
		code = 31 // red
	case score < 80:
		code = 33 // yellow
	}
	return a.paint(code, text)
}

func (a *App) printHeaders(info *domain.ServerInfo) {
	fmt.Fprintln(a.out, "\n📋 Headers:")

	keys := make([]string, 0, len(info.Headers))
	for k := range info.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	tw := tabwriter.NewWriter(a.out, 2, 4, 1, ' ', 0)
	for _, key := range keys {
		value := info.Headers[key]
		if strings.EqualFold(key, "Set-Cookie") {
			value = summarizeCookies(value)
		}
		fmt.Fprintf(tw, "  %s:\t%s\n", key, value)
	}
	tw.Flush()
}

// writeJSON marshals v with the project's standard JSON formatting.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// summarizeCookies redacts cookie values while preserving the security-
// relevant attributes (Secure / HttpOnly / SameSite).
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
