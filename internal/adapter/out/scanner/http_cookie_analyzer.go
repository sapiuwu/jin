package scanner

import (
	"context"
	"net/http"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/out"
)

// HTTPCookieAnalyzer is an out.CookieAnalyzer adapter that fetches a target
// and inspects its Set-Cookie attributes for missing security flags.
type HTTPCookieAnalyzer struct {
	client *http.Client
}

// NewHTTPCookieAnalyzer builds the adapter with the given request budget and
// optional upstream proxy ("" for a direct connection).
func NewHTTPCookieAnalyzer(timeout time.Duration, proxy string) out.CookieAnalyzer {
	return &HTTPCookieAnalyzer{client: newHTTPClient(timeout, proxy)}
}

// Analyze implements out.CookieAnalyzer.
func (a *HTTPCookieAnalyzer) Analyze(ctx context.Context, rawURL string) (*domain.CookieAnalysis, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; jin-cookie-scanner/1.0)")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	res := &domain.CookieAnalysis{URL: resp.Request.URL.String()}
	for _, c := range resp.Cookies() {
		cookie := domain.Cookie{
			Name:     c.Name,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			SameSite: sameSiteName(c.SameSite),
			Domain:   c.Domain,
			Path:     c.Path,
			HasFlags: c.Secure || c.HttpOnly,
		}
		if !c.Expires.IsZero() {
			cookie.Expires = c.Expires.UTC().Format(time.RFC3339)
		}
		res.Cookies = append(res.Cookies, cookie)

		if !c.Secure {
			res.Warnings = append(res.Warnings, "cookie '"+c.Name+"' missing Secure flag (sent over plain HTTP)")
		}
		if !c.HttpOnly {
			res.Warnings = append(res.Warnings, "cookie '"+c.Name+"' missing HttpOnly flag (readable by JS)")
		}
		if c.SameSite == http.SameSiteNoneMode && !c.Secure {
			res.Warnings = append(res.Warnings, "cookie '"+c.Name+"' uses SameSite=None without Secure (ignored by browsers)")
		}
	}

	return res, nil
}

// sameSiteName maps an http.SameSite constant to its canonical name.
func sameSiteName(s http.SameSite) string {
	switch s {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteNoneMode:
		return "None"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	default:
		return ""
	}
}
