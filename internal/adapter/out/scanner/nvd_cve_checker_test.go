package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aliftech/jin/internal/port/out"
)

const nvdTestBody = `{"vulnerabilities":[{"cve":{"id":"CVE-2024-1234","metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8},"baseSeverity":"CRITICAL"}]}}}]}`

// newTestNVDChecker builds a checker pointed at srv with test-friendly
// retry pacing (1ms backoff instead of the production 1s).
func newTestNVDChecker(t *testing.T, srv *httptest.Server, opts ...NVDOption) *NVDChecker {
	t.Helper()
	opts = append(opts, func(c *NVDChecker) {
		c.endpoint = srv.URL
		c.backoff = time.Millisecond
	})
	return NewNVDChecker(time.Second, "", opts...).(*NVDChecker)
}

func TestNVDCheckerSendsAPIKeyHeaderAndParsesCVEs(t *testing.T) {
	keyCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyCh <- r.Header.Get("apiKey")
		fmt.Fprint(w, nvdTestBody)
	}))
	defer srv.Close()

	c := newTestNVDChecker(t, srv, WithNVDAPIKey("secret-key"))
	cves, err := c.Check(context.Background(), "Nginx", "1.2.3")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got := <-keyCh; got != "secret-key" {
		t.Errorf("apiKey header = %q, want %q", got, "secret-key")
	}
	if len(cves) != 1 {
		t.Fatalf("Check() returned %d CVEs, want 1", len(cves))
	}
	if cves[0].ID != "CVE-2024-1234" || cves[0].Severity != "CRITICAL" {
		t.Errorf("Check() = %+v, want CVE-2024-1234/CRITICAL", cves[0])
	}
	wantURL := "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
	if cves[0].URL != wantURL {
		t.Errorf("CVE URL = %q, want %q", cves[0].URL, wantURL)
	}
}

func TestNVDCheckerRetriesThrottledRequestThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, nvdTestBody)
	}))
	defer srv.Close()

	c := newTestNVDChecker(t, srv)
	cves, err := c.Check(context.Background(), "Nginx", "1.2.3")
	if err != nil {
		t.Fatalf("Check() error = %v, want success after retry", err)
	}
	if len(cves) != 1 {
		t.Errorf("Check() returned %d CVEs, want 1", len(cves))
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("server saw %d requests, want 2 (initial + 1 retry)", n)
	}
}

func TestNVDCheckerReportsRateLimitAfterRetriesExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestNVDChecker(t, srv)
	_, err := c.Check(context.Background(), "Nginx", "1.2.3")
	if err == nil {
		t.Fatal("Check() error = nil, want a rate-limit error")
	}
	if !errors.Is(err, out.ErrRateLimited) {
		t.Errorf("Check() error = %v, want it to wrap out.ErrRateLimited", err)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("server saw %d requests, want 3 (1 + max 2 retries)", n)
	}
}

func TestNVDCheckerDoesNotRetryServerErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestNVDChecker(t, srv)
	_, err := c.Check(context.Background(), "Nginx", "1.2.3")
	if err == nil {
		t.Fatal("Check() error = nil, want an error")
	}
	if errors.Is(err, out.ErrRateLimited) {
		t.Errorf("Check() error = %v, a plain 500 must not be reported as rate limiting", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("server saw %d requests, want 1 (500 is not retried)", n)
	}
}

func TestNVDCheckerHonorsRetryAfterHeader(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, nvdTestBody)
	}))
	defer srv.Close()

	c := newTestNVDChecker(t, srv)
	c.backoff = 0 // only the server's hint may cause a delay

	start := time.Now()
	if _, err := c.Check(context.Background(), "Nginx", "1.2.3"); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed < 500*time.Millisecond {
		t.Errorf("Check() returned after %v, want it to wait for Retry-After (1s)", elapsed)
	}
}

func TestNVDCheckerFailsFastWhenRetryAfterExceedsBudget(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	c := newTestNVDChecker(t, srv)
	start := time.Now()
	_, err := c.Check(ctx, "Nginx", "1.2.3")
	if !errors.Is(err, out.ErrRateLimited) {
		t.Fatalf("Check() error = %v, want it to wrap out.ErrRateLimited", err)
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Errorf("Check() took %v, want an immediate failure instead of sleeping 30s", elapsed)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("server saw %d requests, want 1", n)
	}
}

func TestNVDCheckerCachesWithinARun(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, nvdTestBody)
	}))
	defer srv.Close()

	c := newTestNVDChecker(t, srv, WithNVDCache(NewCache("", "nvd", time.Hour)))
	for i := 0; i < 3; i++ {
		if _, err := c.Check(context.Background(), "Nginx", "1.2.3"); err != nil {
			t.Fatalf("Check() #%d error = %v", i+1, err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("server saw %d requests for 3 identical checks, want 1", n)
	}
}

func TestNVDCheckerCachesAcrossRunsOnDisk(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, nvdTestBody)
	}))
	defer srv.Close()

	dir := t.TempDir()

	first := newTestNVDChecker(t, srv, WithNVDCache(NewCache(dir, "nvd", time.Hour)))
	if _, err := first.Check(context.Background(), "Nginx", "1.2.3"); err != nil {
		t.Fatalf("first Check() error = %v", err)
	}

	// A fresh checker with a fresh cache instance simulates a later run
	// reading the persisted store.
	second := newTestNVDChecker(t, srv, WithNVDCache(NewCache(dir, "nvd", time.Hour)))
	cves, err := second.Check(context.Background(), "Nginx", "1.2.3")
	if err != nil {
		t.Fatalf("second Check() error = %v", err)
	}
	if len(cves) != 1 {
		t.Errorf("cached Check() returned %d CVEs, want 1", len(cves))
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("server saw %d requests across two runs, want 1", n)
	}
}

func TestNVDCheckerSkipsUnmappedTechnologies(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, nvdTestBody)
	}))
	defer srv.Close()

	c := newTestNVDChecker(t, srv)
	tests := []struct {
		name    string
		tech    string
		version string
	}{
		{"no CPE mapping", "SomeUnknownTool", "1.0"},
		{"no version", "Nginx", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cves, err := c.Check(context.Background(), tt.tech, tt.version)
			if err != nil || cves != nil {
				t.Errorf("Check(%q, %q) = (%v, %v), want (nil, nil)", tt.tech, tt.version, cves, err)
			}
		})
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("server saw %d requests, want 0 for unmapped lookups", n)
	}
}
