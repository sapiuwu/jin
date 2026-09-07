package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/out"
)

// TLSInspector is an out.TLSInspector adapter that performs a raw TLS
// handshake against a host and reports the negotiated parameters, the
// certificate chain, and any posture issues.
type TLSInspector struct {
	timeout time.Duration
}

// NewTLSInspector builds the adapter with a per-handshake budget.
func NewTLSInspector(timeout time.Duration) out.TLSInspector {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &TLSInspector{timeout: timeout}
}

// Inspect implements out.TLSInspector.
func (i *TLSInspector) Inspect(ctx context.Context, host string) (*domain.TLSReport, error) {
	host = tlsHost(host)
	dialer := &net.Dialer{Timeout: i.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, fmt.Errorf("cannot connect to %s:443: %w", host, err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // recon: we inspect the cert regardless of trust
		MinVersion:         tls.VersionSSL30,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake failed: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	report := &domain.TLSReport{
		Host:        host,
		TLSVersion:  tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		OCSPStapled: len(state.OCSPResponse) > 0,
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		cert := certToInfo(leaf)
		report.Cert = &cert
		for _, c := range state.PeerCertificates[1:] {
			report.CertChain = append(report.CertChain, certToInfo(c))
		}
		now := time.Now()
		if now.After(leaf.NotAfter) {
			report.Issues = append(report.Issues, "certificate has expired")
		}
		if now.Before(leaf.NotBefore) {
			report.Issues = append(report.Issues, "certificate is not yet valid")
		}
	}
	if state.Version < tls.VersionTLS12 {
		report.Issues = append(report.Issues, "negotiated a deprecated TLS version (< TLS 1.2)")
	}
	if !report.OCSPStapled {
		report.Issues = append(report.Issues, "no OCSP stapling observed")
	}

	return report, nil
}

func certToInfo(cert *x509.Certificate) domain.CertInfo {
	sum := sha256.Sum256(cert.Raw)
	return domain.CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           cert.NotAfter.UTC().Format(time.RFC3339),
		DNSNames:           cert.DNSNames,
		FingerprintSHA256: "sha256:" + hex.EncodeToString(sum[:]),
	}
}

// tlsHost strips a scheme, path, and port from a target so it can be used as
// the TLS ServerName.
func tlsHost(input string) string {
	if u, err := url.Parse(input); err == nil && u.Host != "" {
		host := u.Hostname()
		if host != "" {
			return host
		}
	}
	host := strings.ToLower(input)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.Index(host, "/"); i != -1 {
		host = host[:i]
	}
	if i := strings.Index(host, ":"); i != -1 {
		host = host[:i]
	}
	return host
}
