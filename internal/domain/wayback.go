package domain

// WaybackResult is the set of historic snapshots discovered for a domain via
// the Internet Archive's Wayback Machine CDX API. It is a purely passive
// source of URLs that may no longer be linked from the live site.
type WaybackResult struct {
	Domain    string
	Count     int
	Snapshots []WaybackSnapshot
}

// WaybackSnapshot is a single archived URL capture.
type WaybackSnapshot struct {
	URL       string
	Timestamp string
	Status    string
	MimeType  string
}
