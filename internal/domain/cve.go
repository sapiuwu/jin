package domain

// CVE is a single known vulnerability (e.g. from the NVD) tied to a detected
// technology version.
type CVE struct {
	ID       string `json:"id"`
	Severity string `json:"severity,omitempty"`
	URL      string `json:"url"`
}

// CVEResult aggregates the CVE findings for one technology name+version
// pair, used by the top-level tech-stack report.
type CVEResult struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	CVEs    []CVE  `json:"cves,omitempty"`
}

// WhoisInfo holds registration data for a domain, retrieved passively via
// RDAP (no WHOIS protocol, no API key).
type WhoisInfo struct {
	Domain      string   `json:"domain"`
	Status      []string `json:"status,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	Registrar   string   `json:"registrar,omitempty"`
	CreatedDate string   `json:"created_date,omitempty"`
	UpdatedDate string   `json:"updated_date,omitempty"`
	ExpiresDate string   `json:"expires_date,omitempty"`
}
