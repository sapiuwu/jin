// Package scanner implements the driven (out) ports for Jin's network
// reconnaissance. Each file is a self-contained adapter behind one of the
// interfaces in internal/port/out.
package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// HTTPServerScanner is an out.ServerScanner adapter that fetches a target
// over HTTP(S) and extracts server + security metadata from the response.
type HTTPServerScanner struct {
	client *http.Client
}

// NewHTTPServerScanner builds the adapter with the given request budget and
// optional upstream proxy ("" for a direct connection).
func NewHTTPServerScanner(timeout time.Duration, proxy string) *HTTPServerScanner {
	return &HTTPServerScanner{client: newHTTPClient(timeout, proxy)}
}

// Scan implements out.ServerScanner.
func (s *HTTPServerScanner) Scan(ctx context.Context, rawURL string) (*domain.ServerInfo, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}

	// Attempt primary request
	info, err := s.doRequest(ctx, parsed)
	if err != nil {
		// Fallback to HTTP only if original was HTTPS
		if parsed.Scheme == "https" {
			parsed.Scheme = "http"
			if info2, err2 := s.doRequest(ctx, parsed); err2 == nil {
				return info2, nil
			}
		}
		return nil, err
	}

	return info, nil
}

func (s *HTTPServerScanner) doRequest(ctx context.Context, u *url.URL) (*domain.ServerInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Jin-OSINT-Bot/2.1; +https://github.com/aliftech/jin)")

	resp, err := s.client.Do(req)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "no such host") {
			return nil, fmt.Errorf("DNS resolution failed")
		} else if strings.Contains(errStr, "connection refused") {
			return nil, fmt.Errorf("connection refused")
		} else if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "i/o timeout") {
			return nil, fmt.Errorf("request timeout")
		} else if strings.Contains(errStr, "x509") {
			return nil, fmt.Errorf("TLS certificate error")
		}
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	domainName := u.Hostname()
	rootDomain := extractRootDomain(domainName)

	info := &domain.ServerInfo{
		URL:         u.String(),
		Domain:      domainName,
		RootDomain:  rootDomain,
		StatusCode:  resp.StatusCode,
		Server:      strings.TrimSpace(resp.Header.Get("Server")),
		PoweredBy:   strings.TrimSpace(resp.Header.Get("X-Powered-By")),
		ContentType: strings.TrimSpace(resp.Header.Get("Content-Type")),
		Headers:     make(map[string]string),
	}

	for name, values := range resp.Header {
		key := http.CanonicalHeaderKey(name)
		info.Headers[key] = strings.Join(values, ", ")
	}

	if resp.TLS != nil {
		info.TLSVersion = tlsVersionName(resp.TLS.Version)
		info.TLSCipherSuite = tls.CipherSuiteName(resp.TLS.CipherSuite)
	}

	// Enrich with security and cloud insights
	s.enrichSecurityInfo(info, resp)
	info.CloudProvider = detectCloudProvider(info.Headers, domainName)

	return info, nil
}

func (s *HTTPServerScanner) enrichSecurityInfo(info *domain.ServerInfo, resp *http.Response) {
	headers := resp.Header

	// Security header presence
	info.HasHSTS = headers.Get("Strict-Transport-Security") != ""
	info.HasXFrameOptions = headers.Get("X-Frame-Options") != ""
	info.HasCSP = headers.Get("Content-Security-Policy") != ""
	info.HasCSPReportOnly = headers.Get("Content-Security-Policy-Report-Only") != ""

	// CSP analysis
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		info.CSPWarnings = analyzeCSP(csp, false)
	} else if cspRo := headers.Get("Content-Security-Policy-Report-Only"); cspRo != "" {
		info.CSPWarnings = analyzeCSP(cspRo, true)
	}

	// Cookie analysis — iterate over actual cookie lines
	for _, cookieLine := range headers["Set-Cookie"] {
		parts := strings.SplitN(cookieLine, ";", 2)
		namePart := strings.SplitN(parts[0], "=", 2)[0]
		cookieName := strings.TrimSpace(namePart)

		var attrs string
		if len(parts) > 1 {
			attrs = strings.ToLower(strings.Join(parts[1:], ";"))
		}

		if !strings.Contains(attrs, "secure") {
			info.CookieWarnings = append(info.CookieWarnings,
				fmt.Sprintf("cookie '%s' missing Secure flag", cookieName))
		}
		if !strings.Contains(attrs, "httponly") {
			info.CookieWarnings = append(info.CookieWarnings,
				fmt.Sprintf("cookie '%s' missing HttpOnly flag", cookieName))
		}
	}
}

// Simple root domain extractor (assumes public suffix is 2 parts for simplicity)
// For production, consider using github.com/weppos/publicsuffix-go
func extractRootDomain(host string) string {
	host = strings.ToLower(host)
	if i := strings.Index(host, ":"); i != -1 {
		host = host[:i]
	}

	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// detectCloudProvider attempts to identify the cloud/hosting provider
// based on HTTP response headers and domain clues.
func detectCloudProvider(headers map[string]string, domain string) string {
	// Normalize headers to lowercase keys for safe access
	lowerHeaders := make(map[string]string)
	for k, v := range headers {
		lowerHeaders[strings.ToLower(k)] = v
	}

	// --- Alibaba Cloud ---
	if _, exists := lowerHeaders["ga-ap"]; exists {
		return "Alibaba Cloud"
	}
	if cookie, exists := lowerHeaders["set-cookie"]; exists {
		if strings.Contains(cookie, "acw_tc") || strings.Contains(cookie, "cna") {
			return "Alibaba Cloud (WAF/CDN)"
		}
	}
	if strings.Contains(domain, ".aliyuncs.com") ||
		strings.Contains(domain, ".alicdn.com") ||
		strings.Contains(domain, ".aliyun.com") {
		return "Alibaba Cloud"
	}

	// --- Amazon AWS ---
	if _, exists := lowerHeaders["x-amz-cf-id"]; exists {
		return "AWS (CloudFront)"
	}
	if _, exists := lowerHeaders["x-amz-request-id"]; exists {
		return "AWS (S3 or API Gateway)"
	}
	if _, exists := lowerHeaders["x-amz-id-2"]; exists {
		return "AWS (S3)"
	}
	if strings.Contains(domain, ".cloudfront.net") {
		return "AWS (CloudFront)"
	}
	if strings.Contains(domain, ".s3.amazonaws.com") ||
		strings.Contains(domain, ".s3-") ||
		strings.Contains(domain, ".execute-api.") {
		return "AWS"
	}

	// --- Google Cloud Platform (GCP) ---
	if server, exists := lowerHeaders["server"]; exists {
		if server == "gws" {
			return "Google Cloud (Google Web Server)"
		}
		if server == "GSE" || server == "Google Frontend" {
			return "Google Cloud (App Engine)"
		}
	}
	if _, exists := lowerHeaders["x-google-gfe-service"]; exists {
		return "Google Cloud (GFE)"
	}
	if _, exists := lowerHeaders["x-goog-hash"]; exists {
		return "Google Cloud (Cloud Storage)"
	}
	if strings.Contains(domain, ".googleusercontent.com") ||
		strings.Contains(domain, ".appspot.com") ||
		strings.Contains(domain, ".gstatic.com") {
		return "Google Cloud"
	}

	// --- Cloudflare ---
	if _, exists := lowerHeaders["cf-ray"]; exists {
		return "Cloudflare"
	}
	if _, exists := lowerHeaders["cf-cache-status"]; exists {
		return "Cloudflare"
	}
	if cookie, exists := lowerHeaders["set-cookie"]; exists {
		if strings.Contains(cookie, "__cf_bm") || strings.Contains(cookie, "__cfduid") {
			return "Cloudflare"
		}
	}
	if strings.Contains(domain, ".cloudflare.com") {
		return "Cloudflare"
	}

	// --- Microsoft Azure ---
	if _, exists := lowerHeaders["x-ms-request-id"]; exists {
		return "Microsoft Azure"
	}
	if _, exists := lowerHeaders["x-ms-version"]; exists {
		return "Microsoft Azure"
	}
	if server, exists := lowerHeaders["server"]; exists {
		if strings.Contains(server, "Microsoft-HTTPAPI") ||
			strings.Contains(server, "Azure") {
			return "Microsoft Azure"
		}
	}
	if strings.Contains(domain, ".azurewebsites.net") ||
		strings.Contains(domain, ".blob.core.windows.net") ||
		strings.Contains(domain, ".cloudapp.azure.com") {
		return "Microsoft Azure"
	}

	// --- Others (optional extension) ---
	// Fastly: x-fastly-request-id, Fastly-SSL
	// Akamai: x-akamai-transformed, akamai-origin-hop
	// Vercel: x-vercel-id
	// Netlify: x-nf-request-id

	return "Unknown"
}

func analyzeCSP(csp string, isReportOnly bool) []string {
	var issues []string

	if isReportOnly {
		issues = append(issues, "CSP is in report-only mode (not enforced)")
	}

	lower := strings.ToLower(csp)
	if strings.Contains(lower, "'unsafe-inline'") {
		issues = append(issues, "allows 'unsafe-inline'")
	}
	if strings.Contains(lower, "'unsafe-eval'") {
		issues = append(issues, "allows 'unsafe-eval'")
	}
	if strings.Contains(lower, " http:") || strings.Contains(lower, " https:") {
		// Note: space before http/https avoids matching 'https://...'
		issues = append(issues, "uses overly broad 'http:' or 'https:' source")
	}

	return issues
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}
