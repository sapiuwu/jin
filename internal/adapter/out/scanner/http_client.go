package scanner

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// newHTTPClient builds an *http.Client honoring an overall request budget and
// an optional upstream proxy. The proxy, when set, is passed verbatim to
// Go's proxy machinery, so "http://", "https://", and "socks5://" schemes
// all work — useful for routing recon traffic through Tor or a corporate
// proxy for privacy.
func newHTTPClient(timeout time.Duration, proxy string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For recon only; user assumes risk
		},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	if proxy != "" {
		if p, err := newProxyFunc(proxy); err == nil {
			transport.Proxy = p
		}
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}
