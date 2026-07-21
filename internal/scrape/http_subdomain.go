// internal/scrape/subdomain.go
package scrape

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/core"
)

// ctSubdomainEnumerator discovers subdomains by querying certificate
// transparency logs via crt.sh. This is a purely passive technique: it
// only reads public CT log data and never sends traffic to the target
// itself, so enumeration carries no scanning footprint on its own.
type ctSubdomainEnumerator struct {
	client *http.Client
}

// NewCTSubdomainEnumerator returns a core.SubdomainEnumerator backed by
// crt.sh's certificate transparency search.
func NewCTSubdomainEnumerator(timeout time.Duration) core.SubdomainEnumerator {
	return &ctSubdomainEnumerator{client: &http.Client{Timeout: timeout}}
}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

func (e *ctSubdomainEnumerator) Enumerate(ctx context.Context, domain string) ([]string, error) {
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