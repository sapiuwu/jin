package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/out"
)

// NVDChecker is an out.CVEChecker adapter that queries the NIST National
// Vulnerability Database (NVD) 2.0 REST API for a given technology. It is
// best-effort: transient errors return an empty list rather than failing
// the whole scan.
type NVDChecker struct {
	client *http.Client
}

// NewNVDChecker builds the adapter, routed through an optional upstream
// proxy ("" for a direct connection).
func NewNVDChecker(timeout time.Duration, proxy string) out.CVEChecker {
	return &NVDChecker{client: newHTTPClient(timeout, proxy)}
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

// Check implements out.CVEChecker.
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
	apiURL := "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20&cpeName=" + cpe

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "jin-cve-checker/2.4.1")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
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
