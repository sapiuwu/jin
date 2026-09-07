package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/port/out"
)

// CTSubdomainEnumerator is an out.SubdomainEnumerator adapter that
// discovers subdomains by querying certificate transparency logs via
// crt.sh. This is a purely passive technique: it only reads public CT log
// data and never sends traffic to the target itself, so enumeration
// carries no scanning footprint on its own.
type CTSubdomainEnumerator struct {
	client *http.Client
}

// NewCTSubdomainEnumerator builds the adapter backed by crt.sh, routed
// through an optional upstream proxy ("" for a direct connection).
func NewCTSubdomainEnumerator(timeout time.Duration, proxy string) out.SubdomainEnumerator {
	return &CTSubdomainEnumerator{client: newHTTPClient(timeout, proxy)}
}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// Enumerate implements out.SubdomainEnumerator.
func (e *CTSubdomainEnumerator) Enumerate(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; jin-subdomain-scanner/1.0)")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response: %w", err)
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		for _, line := range strings.Split(entry.NameValue, "\n") {
			host := strings.ToLower(strings.TrimSpace(line))
			if host == "" {
				continue
			}
			// Wildcard certs show up as "*.example.com" — the wildcard
			// itself isn't a real host, so normalize it away but keep
			// the base name it points at.
			host = strings.TrimPrefix(host, "*.")
			if !strings.HasSuffix(host, domain) {
				continue
			}
			seen[host] = true
		}
	}

	subdomains := make([]string, 0, len(seen))
	for h := range seen {
		subdomains = append(subdomains, h)
	}
	sort.Strings(subdomains)
	return subdomains, nil
}
