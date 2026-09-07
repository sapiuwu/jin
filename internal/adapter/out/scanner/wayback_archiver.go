package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/out"
)

// WaybackLister is an out.WaybackLister adapter that queries the Internet
// Archive's Wayback Machine CDX API for historic captures of a domain. This
// is a purely passive source of URLs no longer linked from the live site.
type WaybackLister struct {
	client *http.Client
}

// NewWaybackLister builds the adapter with the given request budget and
// optional upstream proxy ("" for a direct connection).
func NewWaybackLister(timeout time.Duration, proxy string) out.WaybackLister {
	return &WaybackLister{client: newHTTPClient(timeout, proxy)}
}

// List implements out.WaybackLister.
func (w *WaybackLister) List(ctx context.Context, domainName string) (*domain.WaybackResult, error) {
	dom := strings.TrimPrefix(domainName, "https://")
	dom = strings.TrimPrefix(dom, "http://")
	if i := strings.Index(dom, "/"); i != -1 {
		dom = dom[:i]
	}

	apiURL := "https://web.archive.org/cdx/search/cdx?url=" + url.QueryEscape(dom) +
		"&output=json&collapse=urlkey&fl=original,timestamp,statuscode,mimetype&filter=statuscode:200"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; jin-wayback/1.0)")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback returned status %d", resp.StatusCode)
	}

	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("failed to parse wayback response: %w", err)
	}

	res := &domain.WaybackResult{Domain: dom}
	for _, row := range rows {
		if len(row) < 4 {
			continue
		}
		if row[0] == "original" { // header row
			continue
		}
		res.Snapshots = append(res.Snapshots, domain.WaybackSnapshot{
			URL:       row[0],
			Timestamp: row[1],
			Status:    row[2],
			MimeType:  row[3],
		})
	}
	res.Count = len(res.Snapshots)
	return res, nil
}
