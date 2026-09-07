package domain

// CDNResult reports whether a target sits behind a CDN/WAF and whether its
// origin server appears to be directly reachable (a common leak that lets an
// attacker bypass the CDN's protections by hitting the origin IP directly).
type CDNResult struct {
	Domain        string
	Detected      bool
	Provider      string
	Indicators    []string
	OriginExposed bool
	Notes         []string
}
