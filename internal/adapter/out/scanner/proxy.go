package scanner

import (
	"fmt"
	"net/http"
	"net/url"
)

// newProxyFunc parses a proxy URL string (http/https/socks5) and returns a
// resolver compatible with http.Transport.Proxy. An invalid scheme yields an
// error so callers can fall back to a direct connection.
func newProxyFunc(raw string) (func(*http.Request) (*url.URL, error), error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
		// Go's transport supports these schemes natively.
		return func(*http.Request) (*url.URL, error) { return u, nil }, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https, or socks5)", u.Scheme)
	}
}
