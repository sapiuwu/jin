// internal/scrape/techstack.go
package scrape

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/core"
)

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

type httpTechStackDetector struct {
	client *http.Client
}

// NewHTTPTechStackDetector returns a core.TechStackDetector that fetches the
// target page once and matches response headers, HTML markup, cookies, and
// script URLs against a built-in signature set.
func NewHTTPTechStackDetector(timeout time.Duration) core.TechStackDetector {
	return &httpTechStackDetector{
		client: &http.Client{Timeout: timeout},
	}
}

// maxBodyBytes caps how much HTML we read/scan, to avoid pulling huge pages
// into memory just to look for a handful of patterns near the top.
const maxBodyBytes = 2 << 20 // 2 MiB

func (d *httpTechStackDetector) Detect(ctx context.Context, target string) (*core.TechStackInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; jin-techstack-scanner/1.0)")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}

	data := &scanData{
		headers: resp.Header,
		body:    string(bodyBytes),
		cookies: resp.Cookies(),
	}

	techs := runSignatures(data)

	return &core.TechStackInfo{
		URL:          target,
		Technologies: techs,
	}, nil
}

// ---------------------------------------------------------------------------
// Scan data & matcher helpers
// ---------------------------------------------------------------------------

type scanData struct {
	headers http.Header
	body    string
	cookies []*http.Cookie
}

// headerRegex checks a header's value against a regex. If the regex has a
// capture group, its first match is returned as the detected version.
func headerRegex(d *scanData, header string, re *regexp.Regexp) (matched bool, version, evidence string) {
	val := d.headers.Get(header)
	if val == "" {
		return false, "", ""
	}
	m := re.FindStringSubmatch(val)
	if m == nil {
		return false, "", ""
	}
	if len(m) > 1 {
		version = m[1]
	}
	return true, version, "Header: " + header + ": " + val
}

// headerHas checks whether a header is simply present (value irrelevant).
func headerHas(d *scanData, header string) (matched bool, evidence string) {
	val := d.headers.Get(header)
	if val == "" {
		return false, ""
	}
	return true, "Header present: " + header + ": " + val
}

// bodyRegex checks the HTML body against a regex. If the regex has a
// capture group, its first match is returned as the detected version.
func bodyRegex(d *scanData, re *regexp.Regexp) (matched bool, version, evidence string) {
	m := re.FindStringSubmatch(d.body)
	if m == nil {
		return false, "", ""
	}
	if len(m) > 1 {
		version = m[1]
	}
	snippet := m[0]
	if len(snippet) > 120 {
		snippet = snippet[:120] + "…"
	}
	return true, version, "Markup: " + snippet
}

// cookieHas checks whether any cookie name contains the given substring.
func cookieHas(d *scanData, substr string) (matched bool, evidence string) {
	for _, c := range d.cookies {
		if strings.Contains(strings.ToLower(c.Name), strings.ToLower(substr)) {
			return true, "Cookie: " + c.Name
		}
	}
	return false, ""
}

// ---------------------------------------------------------------------------
// Signature set
// ---------------------------------------------------------------------------

// signature describes one technology and however many independent checks
// can identify it. All matching checks contribute evidence; the technology
// is reported once per scan with combined evidence and the version from
// whichever check found one.
type signature struct {
	name       string
	category   string
	confidence string // default confidence when at least one check matches
	checks     []func(d *scanData) (matched bool, version, evidence string)
}

func runSignatures(d *scanData) []core.Technology {
	var results []core.Technology

	for _, sig := range signatures {
		var (
			matched  bool
			version  string
			evidence []string
		)
		for _, check := range sig.checks {
			ok, v, ev := check(d)
			if !ok {
				continue
			}
			matched = true
			if v != "" && version == "" {
				version = v
			}
			evidence = append(evidence, ev)
		}
		if !matched {
			continue
		}
		results = append(results, core.Technology{
			Name:       sig.name,
			Category:   sig.category,
			Version:    version,
			Confidence: confidenceFor(sig.confidence, len(evidence)),
			Evidence:   evidence,
		})
	}

	return results
}

// confidenceFor bumps the base confidence up a notch when multiple
// independent signals agree (e.g. both a header and a cookie matched).
func confidenceFor(base string, signalCount int) string {
	if signalCount >= 2 && base != "Very High" {
		switch base {
		case "Medium":
			return "High"
		case "Low":
			return "Medium"
		default:
			return "Very High"
		}
	}
	return base
}

// Precompiled patterns used below.
var (
	reNginxServer   = regexp.MustCompile(`(?i)nginx/?([\d.]*)`)
	reApacheServer  = regexp.MustCompile(`(?i)apache/?([\d.]*)`)
	reIISServer     = regexp.MustCompile(`(?i)Microsoft-IIS/?([\d.]*)`)
	reLiteSpeed     = regexp.MustCompile(`(?i)LiteSpeed`)
	rePHPPowered    = regexp.MustCompile(`(?i)PHP/?([\d.]*)`)
	reAspNet        = regexp.MustCompile(`(?i)ASP\.NET`)
	reExpress       = regexp.MustCompile(`(?i)Express`)
	reGenWordPress  = regexp.MustCompile(`(?i)<meta name=["']generator["'] content=["']WordPress ?([\d.]*)`)
	reGenDrupal     = regexp.MustCompile(`(?i)<meta name=["']generator["'] content=["']Drupal ?([\d.]*)`)
	reGenJoomla     = regexp.MustCompile(`(?i)<meta name=["']generator["'] content=["']Joomla!? ?([\d.]*)`)
	reWPContent     = regexp.MustCompile(`(?i)/wp-content/|/wp-includes/`)
	reShopify       = regexp.MustCompile(`(?i)cdn\.shopify\.com|Shopify\.theme`)
	reMagento       = regexp.MustCompile(`(?i)/skin/frontend/|Mage\.Cookies`)
	reWix           = regexp.MustCompile(`(?i)static\.wixstatic\.com|wix\.com`)
	reSquarespace   = regexp.MustCompile(`(?i)squarespace\.com|static1\.squarespace\.com`)
	reJQuery        = regexp.MustCompile(`(?i)jquery(?:-|\.)([\d.]+)?(?:\.min)?\.js`)
	reReact         = regexp.MustCompile(`(?i)react(?:-dom)?(?:\.production)?(?:\.min)?\.js|data-reactroot`)
	reVue           = regexp.MustCompile(`(?i)vue(?:\.global)?(?:\.min)?\.js|__VUE__`)
	reAngular       = regexp.MustCompile(`(?i)ng-version=["']([\d.]+)["']|angular(?:\.min)?\.js`)
	reBootstrap     = regexp.MustCompile(`(?i)bootstrap(?:\.min)?\.css|bootstrap(?:\.bundle)?(?:\.min)?\.js`)
	reTailwind      = regexp.MustCompile(`(?i)tailwind(?:\.min)?\.css`)
	reGoogleAnalytics = regexp.MustCompile(`(?i)www\.google-analytics\.com/analytics\.js|gtag\(['"]config['"]`)
	reGTM           = regexp.MustCompile(`(?i)googletagmanager\.com/gtm\.js`)
	reFontAwesome   = regexp.MustCompile(`(?i)font-awesome|fontawesome`)
	reGoogleFonts   = regexp.MustCompile(`(?i)fonts\.googleapis\.com`)
	reRecaptcha     = regexp.MustCompile(`(?i)google\.com/recaptcha`)
	rePython        = regexp.MustCompile(`(?i)Werkzeug/?([\d.]*)|Python/?([\d.]*)`)
	reGunicorn      = regexp.MustCompile(`(?i)gunicorn/?([\d.]*)`)
	reUwsgi         = regexp.MustCompile(`(?i)uWSGI`)
	reTomcat        = regexp.MustCompile(`(?i)Apache-Coyote/?([\d.]*)|Tomcat`)
	reJetty         = regexp.MustCompile(`(?i)Jetty\(?([\d.]*)`)
	reKestrel       = regexp.MustCompile(`(?i)Kestrel`)
	reGoHTTP        = regexp.MustCompile(`(?i)^Go-http-server`)
	reAkamai        = regexp.MustCompile(`(?i)AkamaiGHost`)
	reSucuri        = regexp.MustCompile(`(?i)Sucuri/Cloudproxy`)
	reIncapsula     = regexp.MustCompile(`(?i)incap_ses|visid_incap`)
	reAWSWAF        = regexp.MustCompile(`(?i)awselb|AWSALB`)
	reKong          = regexp.MustCompile(`(?i)kong`)
	reEnvoy         = regexp.MustCompile(`(?i)envoy`)
	reTraefik       = regexp.MustCompile(`(?i)Traefik`)
	reHAProxy       = regexp.MustCompile(`(?i)haproxy`)
	reVarnish       = regexp.MustCompile(`(?i)Varnish`)
)

var signatures = []signature{
	// --- Web servers ---------------------------------------------------
	{
		name: "Nginx", category: "Web Server", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return headerRegex(d, "Server", reNginxServer) },
		},
	},
	{
		name: "Apache", category: "Web Server", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return headerRegex(d, "Server", reApacheServer) },
		},
	},
	{
		name: "Microsoft IIS", category: "Web Server", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return headerRegex(d, "Server", reIISServer) },
		},
	},
	{
		name: "LiteSpeed", category: "Web Server", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				matched, ev := false, ""
				if reLiteSpeed.MatchString(d.headers.Get("Server")) {
					matched, ev = true, "Header: Server: "+d.headers.Get("Server")
				}
				return matched, "", ev
			},
		},
	},

	// --- Languages / backend frameworks --------------------------------
	{
		name: "PHP", category: "Programming Language", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return headerRegex(d, "X-Powered-By", rePHPPowered) },
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "PHPSESSID")
				return m, "", ev
			},
		},
	},
	{
		name: "ASP.NET", category: "Web Framework", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m := reAspNet.MatchString(d.headers.Get("X-Powered-By")) || reAspNet.MatchString(d.headers.Get("X-AspNet-Version"))
				if !m {
					return false, "", ""
				}
				return true, d.headers.Get("X-AspNet-Version"), "Header: X-Powered-By/X-AspNet-Version"
			},
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "ASP.NET_SessionId")
				return m, "", ev
			},
		},
	},
	{
		name: "Express", category: "Web Framework", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reExpress.MatchString(d.headers.Get("X-Powered-By")) {
					return false, "", ""
				}
				return true, "", "Header: X-Powered-By: " + d.headers.Get("X-Powered-By")
			},
		},
	},
	{
		name: "Laravel", category: "Web Framework", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "laravel_session")
				return m, "", ev
			},
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "XSRF-TOKEN")
				return m, "", ev
			},
		},
	},
	{
		name: "Django", category: "Web Framework", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "csrftoken")
				return m, "", ev
			},
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "sessionid")
				return m, "", ev
			},
		},
	},
	{
		name: "Ruby on Rails", category: "Web Framework", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "_session_id")
				return m, "", ev
			},
			func(d *scanData) (bool, string, string) {
				if !strings.Contains(strings.ToLower(d.headers.Get("X-Powered-By")), "phusion passenger") {
					return false, "", ""
				}
				return true, "", "Header: X-Powered-By: " + d.headers.Get("X-Powered-By")
			},
		},
	},

	// --- CMS / platforms ------------------------------------------------
	{
		name: "WordPress", category: "CMS", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reGenWordPress) },
			func(d *scanData) (bool, string, string) {
				if !reWPContent.MatchString(d.body) {
					return false, "", ""
				}
				return true, "", "Markup: /wp-content/ or /wp-includes/ path reference"
			},
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "wordpress_logged_in")
				return m, "", ev
			},
		},
	},
	{
		name: "Drupal", category: "CMS", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reGenDrupal) },
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "Drupal.visitor")
				return m, "", ev
			},
		},
	},
	{
		name: "Joomla", category: "CMS", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reGenJoomla) },
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "joomla_user_state")
				return m, "", ev
			},
		},
	},
	{
		name: "Shopify", category: "CMS", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reShopify.MatchString(d.body) {
					return false, "", ""
				}
				return true, "", "Markup: Shopify CDN/theme reference"
			},
			func(d *scanData) (bool, string, string) {
				m, ev := headerHas(d, "X-ShopId")
				return m, "", ev
			},
		},
	},
	{
		name: "Magento", category: "CMS", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reMagento.MatchString(d.body) {
					return false, "", ""
				}
				return true, "", "Markup: Magento skin path or cookie reference"
			},
		},
	},
	{
		name: "Wix", category: "CMS", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reWix.MatchString(d.body) {
					return false, "", ""
				}
				return true, "", "Markup: Wix static asset reference"
			},
		},
	},
	{
		name: "Squarespace", category: "CMS", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reSquarespace.MatchString(d.body) {
					return false, "", ""
				}
				return true, "", "Markup: Squarespace asset reference"
			},
		},
	},

	// --- JS frameworks / libraries --------------------------------------
	{
		name: "jQuery", category: "JavaScript Library", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reJQuery) },
		},
	},
	{
		name: "React", category: "JavaScript Framework", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reReact) },
		},
	},
	{
		name: "Vue.js", category: "JavaScript Framework", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reVue) },
		},
	},
	{
		name: "Angular", category: "JavaScript Framework", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reAngular) },
		},
	},

	// --- CSS frameworks ---------------------------------------------------
	{
		name: "Bootstrap", category: "CSS Framework", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reBootstrap) },
		},
	},
	{
		name: "Tailwind CSS", category: "CSS Framework", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reTailwind) },
		},
	},

	// --- Analytics / marketing -------------------------------------------
	{
		name: "Google Analytics", category: "Analytics", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reGoogleAnalytics) },
		},
	},
	{
		name: "Google Tag Manager", category: "Analytics", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reGTM) },
		},
	},
	{
		name: "Google reCAPTCHA", category: "Security", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reRecaptcha) },
		},
	},

	// --- Fonts / misc -------------------------------------------------
	{
		name: "Font Awesome", category: "Other", confidence: "Low",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reFontAwesome) },
		},
	},
	{
		name: "Google Fonts", category: "Other", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return bodyRegex(d, reGoogleFonts) },
		},
	},

	// --- CDN / infrastructure -------------------------------------------
	{
		name: "Cloudflare", category: "CDN", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m, ev := headerHas(d, "CF-Ray")
				return m, "", ev
			},
			func(d *scanData) (bool, string, string) {
				if !strings.Contains(strings.ToLower(d.headers.Get("Server")), "cloudflare") {
					return false, "", ""
				}
				return true, "", "Header: Server: " + d.headers.Get("Server")
			},
		},
	},
	{
		name: "Fastly", category: "CDN", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m, ev := headerHas(d, "X-Served-By")
				return m, "", ev
			},
		},
	},
	{
		name: "Amazon CloudFront", category: "CDN", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m, ev := headerHas(d, "X-Amz-Cf-Id")
				return m, "", ev
			},
		},
	},

	// --- Backend runtimes / app servers ---------------------------------
	{
		name: "Python (Werkzeug)", category: "Backend Runtime", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return headerRegex(d, "Server", rePython) },
		},
	},
	{
		name: "Gunicorn", category: "Backend Runtime", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return headerRegex(d, "Server", reGunicorn) },
		},
	},
	{
		name: "uWSGI", category: "Backend Runtime", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reUwsgi.MatchString(d.headers.Get("Server")) {
					return false, "", ""
				}
				return true, "", "Header: Server: " + d.headers.Get("Server")
			},
		},
	},
	{
		name: "Apache Tomcat", category: "Backend Runtime", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return headerRegex(d, "Server", reTomcat) },
		},
	},
	{
		name: "Jetty", category: "Backend Runtime", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) { return headerRegex(d, "Server", reJetty) },
		},
	},
	{
		name: "Kestrel (.NET)", category: "Backend Runtime", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reKestrel.MatchString(d.headers.Get("Server")) {
					return false, "", ""
				}
				return true, "", "Header: Server: " + d.headers.Get("Server")
			},
		},
	},
	{
		name: "Go (net/http)", category: "Backend Runtime", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reGoHTTP.MatchString(d.headers.Get("Server")) {
					return false, "", ""
				}
				return true, "", "Header: Server: " + d.headers.Get("Server")
			},
		},
	},

	// --- WAF / reverse proxy / load balancer -----------------------------
	{
		name: "Akamai", category: "WAF / Reverse Proxy", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reAkamai.MatchString(d.headers.Get("Server")) {
					return false, "", ""
				}
				return true, "", "Header: Server: " + d.headers.Get("Server")
			},
		},
	},
	{
		name: "Sucuri", category: "WAF / Reverse Proxy", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reSucuri.MatchString(d.headers.Get("Server")) {
					return false, "", ""
				}
				return true, "", "Header: Server: " + d.headers.Get("Server")
			},
			func(d *scanData) (bool, string, string) {
				m, ev := headerHas(d, "X-Sucuri-ID")
				return m, "", ev
			},
		},
	},
	{
		name: "Imperva Incapsula", category: "WAF / Reverse Proxy", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "incap_ses")
				return m, "", ev
			},
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "visid_incap")
				return m, "", ev
			},
		},
	},
	{
		name: "AWS Elastic Load Balancer", category: "WAF / Reverse Proxy", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m, ev := cookieHas(d, "AWSALB")
				return m, "", ev
			},
		},
	},
	{
		name: "Kong Gateway", category: "WAF / Reverse Proxy", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m, ev := headerHas(d, "Via")
				if m && reKong.MatchString(d.headers.Get("Via")) {
					return true, "", ev
				}
				m, ev = headerHas(d, "X-Kong-Upstream-Latency")
				return m, "", ev
			},
		},
	},
	{
		name: "Envoy", category: "WAF / Reverse Proxy", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reEnvoy.MatchString(d.headers.Get("Server")) {
					return false, "", ""
				}
				return true, "", "Header: Server: " + d.headers.Get("Server")
			},
			func(d *scanData) (bool, string, string) {
				m, ev := headerHas(d, "X-Envoy-Upstream-Service-Time")
				return m, "", ev
			},
		},
	},
	{
		name: "Traefik", category: "WAF / Reverse Proxy", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reTraefik.MatchString(d.headers.Get("Server")) {
					return false, "", ""
				}
				return true, "", "Header: Server: " + d.headers.Get("Server")
			},
		},
	},
	{
		name: "HAProxy", category: "WAF / Reverse Proxy", confidence: "Medium",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				if !reHAProxy.MatchString(d.headers.Get("Server")) {
					return false, "", ""
				}
				return true, "", "Header: Server: " + d.headers.Get("Server")
			},
		},
	},
	{
		name: "Varnish", category: "WAF / Reverse Proxy", confidence: "High",
		checks: []func(*scanData) (bool, string, string){
			func(d *scanData) (bool, string, string) {
				m, ev := headerHas(d, "X-Varnish")
				return m, "", ev
			},
			func(d *scanData) (bool, string, string) {
				if !reVarnish.MatchString(d.headers.Get("Via")) {
					return false, "", ""
				}
				return true, "", "Header: Via: " + d.headers.Get("Via")
			},
		},
	},
}