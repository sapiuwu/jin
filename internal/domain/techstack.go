package domain

// TechStackInfo is the result of a tech-stack fingerprinting scan. When a
// deep scan is requested, it also carries discovered subdomains (each with
// their own independently fingerprinted stack) and DNS records for the
// root domain.
type TechStackInfo struct {
	URL          string          `json:"url"`
	Technologies []Technology    `json:"technologies"`
	Subdomains   []SubdomainInfo `json:"subdomains,omitempty"`
	DNS          *DNSInfo        `json:"dns,omitempty"`
}

// SubdomainInfo captures the fingerprinting result for a single discovered
// subdomain. Reachable is false and Error is set when the subdomain
// resolves but the scan itself failed (timeout, connection refused, etc.).
type SubdomainInfo struct {
	Host         string       `json:"host"`
	Reachable    bool         `json:"reachable"`
	Technologies []Technology `json:"technologies,omitempty"`
	Error        string       `json:"error,omitempty"`
}

// DNSInfo holds a domain's nameserver, mail exchange, and TXT records —
// useful for spotting mail providers, SPF/DKIM/DMARC posture, and hosting
// infrastructure at a glance.
type DNSInfo struct {
	NameServers []string `json:"name_servers,omitempty"`
	MXRecords   []string `json:"mx_records,omitempty"`
	TXTRecords  []string `json:"txt_records,omitempty"`
}

// Technology represents a single identified technology and the signal
// that led to its detection.
type Technology struct {
	// Name is the technology's display name, e.g. "WordPress", "Nginx", "React".
	Name string `json:"name"`

	// Category groups related technologies, e.g. "CMS", "Web Server",
	// "Programming Language", "JavaScript Framework", "JavaScript Library",
	// "CSS Framework", "Analytics", "CDN", "Security". Detectors should
	// use "Other" when no better category applies.
	Category string `json:"category"`

	// Version is the detected version string, if any. Empty when unknown.
	Version string `json:"version,omitempty"`

	// Confidence indicates how certain the detection is. Accepts either
	// a qualitative label ("High" / "Medium" / "Low") or a percentage
	// string ("92%") — the presentation layer normalizes either form.
	Confidence string `json:"confidence"`

	// Evidence lists the concrete signals that led to this detection,
	// e.g. "Header: X-Powered-By: WordPress", "Meta tag: generator=WordPress 6.5".
	Evidence []string `json:"evidence,omitempty"`

	// CVEs is populated when a CVE cross-reference runs and the detected
	// version has known advisories. Empty otherwise.
	CVEs []CVE `json:"cves,omitempty"`
}
