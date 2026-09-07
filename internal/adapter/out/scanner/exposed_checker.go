package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/out"
)

// ExposedChecker is an out.ExposedChecker adapter that probes a target for
// commonly-misconfigured files and paths that may leak source, credentials,
// or metadata when left publicly accessible.
type ExposedChecker struct {
	client *http.Client
}

// NewExposedChecker builds the adapter with the given request budget and
// optional upstream proxy ("" for a direct connection).
func NewExposedChecker(timeout time.Duration, proxy string) out.ExposedChecker {
	return &ExposedChecker{client: newHTTPClient(timeout, proxy)}
}

// defaultExposedPaths lists the sensitive paths probed and a short note
// describing what each typically leaks when found.
var defaultExposedPaths = []struct {
	path string
	note string
}{
	{"/robots.txt", "crawl rules — may reveal admin/hidden paths"},
	{"/sitemap.xml", "URL enumeration"},
	{"/.well-known/security.txt", "security contact policy"},
	{"/security.txt", "security contact policy"},
	{"/.git/HEAD", "git repository exposed — full source may be recoverable"},
	{"/.git/config", "git config exposed"},
	{"/.env", "environment file — secrets/credentials may leak"},
	{"/.env.backup", "environment backup — secrets may leak"},
	{"/wp-config.php.bak", "WordPress config backup — DB credentials"},
	{"/phpinfo.php", "PHP info page — environment disclosure"},
	{"/backup.zip", "site backup archive"},
	{"/admin", "common admin panel path"},
}

// Check implements out.ExposedChecker.
func (c *ExposedChecker) Check(ctx context.Context, rawURL string) (*domain.ExposedResult, error) {
	origin := originOf(rawURL)
	res := &domain.ExposedResult{URL: origin}

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, p := range defaultExposedPaths {
		wg.Add(1)
		go func(p struct {
			path string
			note string
		}) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			full := strings.TrimRight(origin, "/") + p.path
			file := c.probe(ctx, full, p.note)

			mu.Lock()
			res.Files = append(res.Files, file)
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	// Stable ordering by path.
	sortFiles(res.Files)
	return res, nil
}

// probe issues a HEAD (falling back to GET) request and classifies the path.
func (c *ExposedChecker) probe(ctx context.Context, full, note string) domain.ExposedFile {
	file := domain.ExposedFile{Path: full, FullURL: full}

	do := func(method string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, full, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; jin-exposed-scanner/1.0)")
		return c.client.Do(req)
	}

	resp, err := do(http.MethodHead)
	if err != nil {
		// Fall back to GET when HEAD is rejected/unsupported.
		resp, err = do(http.MethodGet)
	}
	if err != nil {
		file.Note = "request failed: " + err.Error()
		return file
	}
	defer resp.Body.Close()

	file.Status = resp.StatusCode
	if cl := resp.ContentLength; cl > 0 {
		file.Size = cl
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		file.Found = true
		file.Note = note
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		file.Found = true
		file.Note = fmt.Sprintf("exists but access-restricted (%d) — %s", resp.StatusCode, note)
	default:
		file.Note = "not found"
	}
	return file
}

// originOf returns scheme://host[:port] for a target URL.
func originOf(rawURL string) string {
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}

func sortFiles(files []domain.ExposedFile) {
	// Simple insertion sort to avoid importing sort in this file's deps.
	for i := 1; i < len(files); i++ {
		for j := i; j > 0 && files[j-1].Path > files[j].Path; j-- {
			files[j-1], files[j] = files[j], files[j-1]
		}
	}
}
