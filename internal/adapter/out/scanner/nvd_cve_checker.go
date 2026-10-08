package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/out"
	appversion "github.com/aliftech/jin/internal/version"
)

const (
	nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	// nvdRateWindow is the fixed window NVD enforces its request budget on.
	nvdRateWindow = 30 * time.Second
	// nvdMaxRetries is how many additional attempts are made after a 403/429.
	nvdMaxRetries = 2
	// nvdMaxRate caps a configured requests-per-window override so a typo
	// cannot produce a microsecond ticker.
	nvdMaxRate = 10000
)

// NVDChecker is an out.CVEChecker adapter that queries the NIST National
// Vulnerability Database (NVD) 2.0 REST API for a given technology. It
// paces itself through a token-bucket rate limiter (5 req/30s unauthenticated,
// 50 with an API key), retries throttled responses with exponential backoff
// while honoring Retry-After, and memoizes answers in a two-layer cache so
// repeated technology+version pairs hit NVD at most once per TTL. When NVD
// throttles for good, Check returns an error wrapping out.ErrRateLimited.
type NVDChecker struct {
	client     *http.Client
	endpoint   string // overridable for tests
	apiKey     string
	ratePer30s int // 0 = automatic (5 without key, 50 with)
	limiter    *rateLimiter
	cache      *Cache // optional; nil disables caching
	backoff    time.Duration
}

// NVDOption configures optional behaviour of the adapter.
type NVDOption func(*NVDChecker)

// WithNVDAPIKey sends the NVD API key in the required `apiKey` header
// (never as a query parameter) and raises the rate budget to 50 req/30s.
func WithNVDAPIKey(key string) NVDOption {
	return func(c *NVDChecker) { c.apiKey = strings.TrimSpace(key) }
}

// WithNVDRateLimit overrides the requests-per-30s budget (0 = automatic:
// 5 unauthenticated, 50 with an API key).
func WithNVDRateLimit(perWindow int) NVDOption {
	return func(c *NVDChecker) { c.ratePer30s = perWindow }
}

// WithNVDCache attaches the two-layer result cache. A nil cache disables
// caching entirely.
func WithNVDCache(cache *Cache) NVDOption {
	return func(c *NVDChecker) { c.cache = cache }
}

// NewNVDChecker builds the adapter, routed through an optional upstream
// proxy ("" for a direct connection).
func NewNVDChecker(timeout time.Duration, proxy string, opts ...NVDOption) out.CVEChecker {
	c := &NVDChecker{
		client:   newHTTPClient(timeout, proxy),
		endpoint: nvdBaseURL,
		backoff:  time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	c.limiter = newNVDRateLimiter(c.apiKey, c.ratePer30s)
	return c
}

// newNVDRateLimiter maps the effective requests-per-window budget onto a
// token bucket: burst equals the window budget (NVD grants the window up
// front) and one token is replenished every window/budget.
func newNVDRateLimiter(apiKey string, ratePer30s int) *rateLimiter {
	perWindow := nvdRatePerWindow(apiKey, ratePer30s)
	return newRateLimiter(nvdRateWindow/time.Duration(perWindow), perWindow)
}

// nvdRatePerWindow resolves how many NVD requests are allowed per 30s
// window: an explicit override wins, otherwise an API key grants the
// authenticated budget of 50, and the public budget is 5.
func nvdRatePerWindow(apiKey string, override int) int {
	switch {
	case override > nvdMaxRate:
		return nvdMaxRate
	case override > 0:
		return override
	case apiKey != "":
		return 50
	default:
		return 5
	}
}

// cpeTriplet maps a detected technology name to its NVD CPE
// vendor:product pair. Only populated entries are checked.
var cpeTriplet = map[string][2]string{
	"WordPress":        {"wordpress", "wordpress"},
	"Drupal":           {"drupal", "drupal"},
	"Joomla":           {"joomla", "joomla"},
	"Magento":          {"magento", "magento"},
	"Shopify":          {"shopify", "shopify"},
	"Wix":              {"wix", "wix"},
	"Nginx":            {"nginx", "nginx"},
	"Apache":           {"apache", "http_server"},
	"Microsoft IIS":    {"microsoft", "internet_information_server"},
	"LiteSpeed":        {"litespeed", "litespeed"},
	"PHP":              {"php", "php"},
	"ASP.NET":          {"microsoft", "asp.net"},
	"Express":          {"openjsf", "express"},
	"Laravel":          {"laravel", "laravel"},
	"Django":           {"djangoproject", "django"},
	"Ruby on Rails":    {"rubyonrails", "ruby_on_rails"},
	"jQuery":           {"jquery", "jquery"},
	"Bootstrap":        {"twbs", "bootstrap"},
	"React":            {"facebook", "react"},
	"Vue.js":           {"vuejs", "vue"},
	"Angular":          {"angular", "angular"},
	"Tailwind CSS":     {"tailwindlabs", "tailwindcss"},
	"Tomcat":           {"apache", "tomcat"},
	"Jetty":            {"eclipse", "jetty"},
	"Kestrel":          {"microsoft", "asp.net_core"},
	"Google reCAPTCHA": {"google", "recaptcha"},
	"Google Analytics": {"google", "analytics"},
}

type cveMetrics struct {
	V31 []struct {
		CVSSData     struct{ BaseScore float64 } `json:"cvssData"`
		BaseSeverity string                      `json:"baseSeverity"`
	} `json:"cvssMetricV31"`
	V30 []struct {
		CVSSData     struct{ BaseScore float64 } `json:"cvssData"`
		BaseSeverity string                      `json:"baseSeverity"`
	} `json:"cvssMetricV30"`
	V2 []struct {
		CVSSData     struct{ BaseScore float64 } `json:"cvssData"`
		BaseSeverity string                      `json:"baseSeverity"`
	} `json:"cvssMetricV2"`
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID      string     `json:"id"`
			Metrics cveMetrics `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Check implements out.CVEChecker. Answers are served from the cache when
// fresh; otherwise the request is paced through the rate limiter before
// hitting NVD.
func (c *NVDChecker) Check(ctx context.Context, name, version string) ([]domain.CVE, error) {
	triplet, ok := cpeTriplet[name]
	if !ok || version == "" {
		return nil, nil
	}
	version = strings.TrimSpace(version)

	// cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
	cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
		strings.ToLower(triplet[0]),
		strings.ToLower(triplet[1]),
		url.QueryEscape(version))

	if c.cache != nil {
		if raw, found := c.cache.Get(cpe); found {
			var cached []domain.CVE
			if err := json.Unmarshal(raw, &cached); err == nil {
				return cached, nil
			}
		}
	}

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	cves, err := c.fetch(ctx, cpe)
	if err != nil {
		return nil, err
	}

	if c.cache != nil {
		if raw, err := json.Marshal(cves); err == nil {
			c.cache.Set(cpe, raw)
		}
	}
	return cves, nil
}

// fetch performs the actual NVD query, retrying throttling responses
// (403/429 — NVD signals abuse detection with 403) up to nvdMaxRetries
// times with exponential backoff, preferring the server's Retry-After
// hint. When the retries are exhausted (or the hint does not fit into the
// remaining scan budget) the error wraps out.ErrRateLimited so callers can
// distinguish "throttled" from "no CVEs". Other status codes and transport
// failures are returned as-is without retrying.
func (c *NVDChecker) fetch(ctx context.Context, cpe string) ([]domain.CVE, error) {
	apiURL := c.endpoint + "?resultsPerPage=20&cpeName=" + cpe

	var wait time.Duration
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				// We were still throttled when the budget ran out: report
				// the throttling, not the deadline.
				return nil, fmt.Errorf("%w: interrupted while backing off: %v", out.ErrRateLimited, ctx.Err())
			case <-time.After(wait):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "jin-cve-checker/"+appversion.Version)
		if c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, err
			}
			return decodeNVDCVEs(body)
		}
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
			return nil, fmt.Errorf("nvd returned status %d", resp.StatusCode)
		}
		if attempt >= nvdMaxRetries {
			return nil, fmt.Errorf("%w: nvd returned status %d after %d attempts",
				out.ErrRateLimited, resp.StatusCode, attempt+1)
		}

		// Exponential backoff (base, 2×base, …) escalated to whatever the
		// server asked for, but never beyond the remaining budget — waiting
		// for a retry that cannot happen would only hide the throttle.
		wait = c.backoff << attempt
		if retryAfter > wait {
			wait = retryAfter
		}
		if deadline, ok := ctx.Deadline(); ok && time.Now().Add(wait).After(deadline) {
			return nil, fmt.Errorf("%w: nvd returned status %d (retry-after %s exceeds the scan budget)",
				out.ErrRateLimited, resp.StatusCode, wait)
		}
	}
}

// decodeNVDCVEs converts an NVD 2.0 response body into domain.CVE values.
func decodeNVDCVEs(body []byte) ([]domain.CVE, error) {
	var r nvdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	cves := make([]domain.CVE, 0, len(r.Vulnerabilities))
	for _, v := range r.Vulnerabilities {
		cves = append(cves, domain.CVE{
			ID:       v.CVE.ID,
			Severity: nvdSeverity(v.CVE.Metrics),
			URL:      "https://nvd.nist.gov/vuln/detail/" + v.CVE.ID,
		})
	}
	return cves, nil
}

// parseRetryAfter interprets a Retry-After header, which is either a delay
// in seconds or an HTTP date. Unparseable or past values yield 0.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func nvdSeverity(m cveMetrics) string {
	for _, x := range m.V31 {
		if x.BaseSeverity != "" {
			return x.BaseSeverity
		}
	}
	for _, x := range m.V30 {
		if x.BaseSeverity != "" {
			return x.BaseSeverity
		}
	}
	for _, x := range m.V2 {
		if x.BaseSeverity != "" {
			return x.BaseSeverity
		}
	}
	return ""
}
