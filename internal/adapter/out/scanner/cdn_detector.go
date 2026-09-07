package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/out"
)

// CDNDetector is an out.CDNDetector adapter that determines whether a target
// is fronted by a CDN/WAF and whether its origin server appears directly
// reachable (bypassing the CDN).
type CDNDetector struct {
	client  *http.Client
	timeout time.Duration
}

// NewCDNDetector builds the adapter with the given request budget and
// optional upstream proxy ("" for a direct connection).
func NewCDNDetector(timeout time.Duration, proxy string) out.CDNDetector {
	return &CDNDetector{client: newHTTPClient(timeout, proxy), timeout: timeout}
}

// cdnMarkers maps a header (case-insensitive) to a CDN/WAF provider name.
var cdnMarkers = []struct {
	header string
	value  string
	provider string
}{
	{"CF-Ray", "", "Cloudflare"},
	{"CF-Cache-Status", "", "Cloudflare"},
	{"Server", "cloudflare", "Cloudflare"},
	{"X-Amz-Cf-Id", "", "Amazon CloudFront"},
	{"X-Served-By", "fastly", "Fastly"},
	{"X-Fastly-Request-Id", "", "Fastly"},
	{"X-Vercel-Id", "", "Vercel"},
	{"X-NF-Request-Id", "", "Netlify"},
	{"Server", "akamai", "Akamai"},
	{"X-Akamai-Transformed", "", "Akamai"},
	{"X-CDN", "", "Unknown CDN"},
	{"X-Cache", "", "Caching proxy/CDN"},
	{"Via", "varnish", "Varnish"},
	{"Server", "sucuri", "Sucuri"},
	{"X-Sucuri-ID", "", "Sucuri"},
}

// Detect implements out.CDNDetector.
func (d *CDNDetector) Detect(ctx context.Context, domainName string) (*domain.CDNResult, error) {
	res := &domain.CDNResult{Domain: tlsHost(domainName)}

	// 1) Passive header-based detection. Also capture the leaf certificate
	// presented by the (CDN-fronted) response so we can later tell whether a
	// direct-to-IP connection reaches a *different* server (the real
	// origin) or just the same CDN edge.
	var edgeFP string
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+res.Domain, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; jin-cdn-detector/1.0)")
		if resp, err := d.client.Do(req); err == nil {
			detectFromHeaders(resp.Header, res)
			if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
				edgeFP = certFingerprint(resp.TLS.PeerCertificates[0])
			}
			resp.Body.Close()
		}
	}

	if !res.Detected {
		res.Notes = append(res.Notes, "no CDN/WAF indicators detected in response headers")
		return res, nil
	}

	// 2) Origin exposure: resolve A records and attempt a direct TLS
	// handshake with the domain as SNI. The origin is "exposed" only when it
	// serves a certificate that DIFFERS from the CDN edge's — i.e. a distinct
	// backend server an attacker could hit directly to bypass the CDN.
	if ips, err := net.DefaultResolver.LookupIPAddr(ctx, res.Domain); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if exposed, note := d.tryOrigin(ctx, res.Domain, ip.IP.String(), edgeFP); exposed {
				res.OriginExposed = true
				res.Notes = append(res.Notes, note)
				break
			}
		}
		if !res.OriginExposed {
			res.Notes = append(res.Notes, "direct-to-IP connections reach the same CDN edge (origin masked)")
		}
	}

	return res, nil
}

func detectFromHeaders(h http.Header, res *domain.CDNResult) {
	lower := map[string][]string{}
	for k, v := range h {
		lower[strings.ToLower(k)] = v
	}
	for _, m := range cdnMarkers {
		vals, ok := lower[strings.ToLower(m.header)]
		if !ok {
			continue
		}
		for _, v := range vals {
			if m.value == "" || strings.Contains(strings.ToLower(v), m.value) {
				if !res.Detected {
					res.Detected = true
					res.Provider = m.provider
				}
				ind := m.header + ": " + v
				if !containsStr(res.Indicators, ind) {
					res.Indicators = append(res.Indicators, ind)
				}
			}
		}
	}
}

// tryOrigin attempts a direct TLS connection to ip:443 with SNI set to the
// domain. It returns true only when the presented certificate both covers the
// domain AND differs from the CDN edge certificate (edgeFP) — meaning a
// distinct origin server is reachable directly.
func (d *CDNDetector) tryOrigin(ctx context.Context, domainName, ip, edgeFP string) (bool, string) {
	dialer := &net.Dialer{Timeout: d.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domainName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false, ""
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return false, ""
	}
	cert := state.PeerCertificates[0]
	if err := cert.VerifyHostname(domainName); err != nil {
		return false, ""
	}
	fp := certFingerprint(cert)
	if fp == edgeFP {
		// Same certificate the CDN edge serves — not a separate origin.
		return false, ""
	}
	return true, "origin " + ip + " serves a different certificate than the CDN edge (likely the real origin)"
}

// certFingerprint returns the hex SHA-256 of a certificate's raw DER.
func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func containsStr(slice []string, s string) bool {
	for _, x := range slice {
		if x == s {
			return true
		}
	}
	return false
}
