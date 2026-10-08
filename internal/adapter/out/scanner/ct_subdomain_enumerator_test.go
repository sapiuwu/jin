package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

const crtShTestBody = `[{"name_value":"a.example.com\nb.example.com"},{"name_value":"*.example.com\nother.org"}]`

// newTestCTEnumerator builds an enumerator pointed at srv with
// test-friendly retry pacing.
func newTestCTEnumerator(t *testing.T, srv *httptest.Server, opts ...CTOption) *CTSubdomainEnumerator {
	t.Helper()
	opts = append(opts, func(e *CTSubdomainEnumerator) {
		e.endpoint = srv.URL
		e.backoff = time.Millisecond
	})
	return NewCTSubdomainEnumerator(time.Second, "", opts...).(*CTSubdomainEnumerator)
}

func TestCTEnumeratorRetriesOn503AndNormalizesResults(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("q"); got != "%.example.com" {
			t.Errorf("query q = %q, want %q", got, "%.example.com")
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(crtShTestBody))
	}))
	defer srv.Close()

	e := newTestCTEnumerator(t, srv)
	subs, err := e.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Enumerate() error = %v, want success after retry", err)
	}
	want := []string{"a.example.com", "b.example.com", "example.com"}
	if !reflect.DeepEqual(subs, want) {
		t.Errorf("Enumerate() = %v, want %v", subs, want)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("server saw %d requests, want 2 (initial + 1 retry)", n)
	}
}

func TestCTEnumeratorFailsAfterRetriesExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	e := newTestCTEnumerator(t, srv)
	if _, err := e.Enumerate(context.Background(), "example.com"); err == nil {
		t.Fatal("Enumerate() error = nil, want an error after retries are exhausted")
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("server saw %d requests, want 3 (1 + max 2 retries)", n)
	}
}

func TestCTEnumeratorDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	e := newTestCTEnumerator(t, srv)
	if _, err := e.Enumerate(context.Background(), "example.com"); err == nil {
		t.Fatal("Enumerate() error = nil, want an error")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("server saw %d requests, want 1 (404 is not retried)", n)
	}
}

func TestCTEnumeratorCachesWithinARun(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(crtShTestBody))
	}))
	defer srv.Close()

	e := newTestCTEnumerator(t, srv, WithCTCache(NewCache("", "crtsh", time.Hour)))
	for i := 0; i < 3; i++ {
		if _, err := e.Enumerate(context.Background(), "example.com"); err != nil {
			t.Fatalf("Enumerate() #%d error = %v", i+1, err)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("server saw %d requests for 3 identical queries, want 1", n)
	}
}

func TestCTEnumeratorCachesAcrossRunsOnDisk(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(crtShTestBody))
	}))
	defer srv.Close()

	dir := t.TempDir()

	first := newTestCTEnumerator(t, srv, WithCTCache(NewCache(dir, "crtsh", time.Hour)))
	if _, err := first.Enumerate(context.Background(), "example.com"); err != nil {
		t.Fatalf("first Enumerate() error = %v", err)
	}

	second := newTestCTEnumerator(t, srv, WithCTCache(NewCache(dir, "crtsh", time.Hour)))
	subs, err := second.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("second Enumerate() error = %v", err)
	}
	if len(subs) != 3 {
		t.Errorf("cached Enumerate() returned %d subdomains, want 3", len(subs))
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("server saw %d requests across two runs, want 1", n)
	}
}
