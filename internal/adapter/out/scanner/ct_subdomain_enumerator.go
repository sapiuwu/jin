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

const (
	crtShBaseURL = "https://crt.sh/"
	// crtShMaxRetries is how many additional attempts are made after a
	// transient failure (503 or a timeout — crt.sh is famously overloaded).
	crtShMaxRetries = 2
)

// CTSubdomainEnumerator is an out.SubdomainEnumerator adapter that
// discovers subdomains by querying certificate transparency logs via
// crt.sh. This is a purely passive technique: it only reads public CT log
// data and never sends traffic to the target itself, so enumeration
// carries no scanning footprint on its own. Transient crt.sh failures are
// retried with exponential backoff, and answers are memoized in a
// two-layer cache so a domain is enumerated at most once per TTL.
type CTSubdomainEnumerator struct {
	client   *http.Client
	endpoint string // overridable for tests
	cache    *Cache // optional; nil disables caching
	backoff  time.Duration
	retries  int
}

// CTOption configures optional behaviour of the adapter.
type CTOption func(*CTSubdomainEnumerator)

// WithCTCache attaches the two-layer result cache. A nil cache disables
// caching entirely.
func WithCTCache(cache *Cache) CTOption {
	return func(e *CTSubdomainEnumerator) { e.cache = cache }
}

// NewCTSubdomainEnumerator builds the adapter backed by crt.sh, routed
// through an optional upstream proxy ("" for a direct connection).
func NewCTSubdomainEnumerator(timeout time.Duration, proxy string, opts ...CTOption) out.SubdomainEnumerator {
	e := &CTSubdomainEnumerator{
		client:   newHTTPClient(timeout, proxy),
		endpoint: crtShBaseURL,
		backoff:  500 * time.Millisecond,
		retries:  crtShMaxRetries,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

type crtShEntry struct {
	NameValue string `json:"name_value"`
}

// Enumerate implements out.SubdomainEnumerator. It serves a cached answer
// when one exists, otherwise queries crt.sh, retrying transient failures
// (503 / timeouts) with exponential backoff before giving up.
func (e *CTSubdomainEnumerator) Enumerate(ctx context.Context, domain string) ([]string, error) {
	if e.cache != nil {
		if raw, found := e.cache.Get(domain); found {
			var cached []string
			if err := json.Unmarshal(raw, &cached); err == nil {
				return cached, nil
			}
		}
	}

	target := fmt.Sprintf("%s?q=%%25.%s&output=json", e.endpoint, domain)

	var lastErr error
	for attempt := 0; attempt <= e.retries; attempt++ {
		if attempt > 0 {
			wait := e.backoff << (attempt - 1) // base, 2×base, …
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("crt.sh request aborted after %d attempts: %w", attempt, lastErr)
			case <-time.After(wait):
			}
		}

		subdomains, retryable, err := e.fetchOnce(ctx, target, domain)
		if err == nil {
			if e.cache != nil {
				if raw, mErr := json.Marshal(subdomains); mErr == nil {
					e.cache.Set(domain, raw)
				}
			}
			return subdomains, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}
	return nil, lastErr
}

// fetchOnce performs a single crt.sh query. The second return value
// reports whether the failure is worth retrying: 503 (crt.sh shedding
// load), other gateway errors, and transport timeouts are, while client
// errors and a broken response body are not.
func (e *CTSubdomainEnumerator) fetchOnce(ctx context.Context, target, domain string) ([]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; jin-subdomain-scanner/1.0)")

	resp, err := e.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, fmt.Errorf("crt.sh request failed: %w", err)
		}
		return nil, true, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// handled below
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		return nil, true, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	default:
		return nil, false, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, false, fmt.Errorf("failed to parse crt.sh response: %w", err)
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
	return subdomains, false, nil
}
