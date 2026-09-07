package cli

import (
	"fmt"

	"github.com/aliftech/jin/internal/port/in"
)

func (a *App) renderTLS(res *in.TLSResult) {
	r := res.Report
	fmt.Fprintf(a.out, "🔒 TLS inspection for %s:\n", r.Host)
	fmt.Fprintf(a.out, "  Protocol:    %s\n", orNone(r.TLSVersion))
	fmt.Fprintf(a.out, "  Cipher:      %s\n", orNone(r.CipherSuite))
	fmt.Fprintf(a.out, "  OCSP staple: %s\n", boolYes(r.OCSPStapled))

	if r.Cert != nil {
		fmt.Fprintln(a.out, "\n📜 Leaf certificate:")
		fmt.Fprintf(a.out, "  Subject:  %s\n", r.Cert.Subject)
		fmt.Fprintf(a.out, "  Issuer:   %s\n", r.Cert.Issuer)
		fmt.Fprintf(a.out, "  Valid:    %s → %s\n", r.Cert.NotBefore, r.Cert.NotAfter)
		fmt.Fprintf(a.out, "  SHA-256:  %s\n", r.Cert.FingerprintSHA256)
		if len(r.Cert.DNSNames) > 0 {
			fmt.Fprintf(a.out, "  SANs:     %v\n", r.Cert.DNSNames)
		}
	}

	if len(r.CertChain) > 0 {
		fmt.Fprintf(a.out, "\n🔗 Chain (%d intermediate(s)):\n", len(r.CertChain))
		for i, c := range r.CertChain {
			fmt.Fprintf(a.out, "  %d. %s (issued by %s)\n", i+1, c.Subject, c.Issuer)
		}
	}

	if len(r.Issues) == 0 {
		fmt.Fprintf(a.out, "\n%s No TLS posture issues found.\n", a.green("✓"))
		return
	}
	fmt.Fprintf(a.out, "\n%s TLS posture issues (%d):\n", a.yellow("⚠️"), len(r.Issues))
	for _, issue := range r.Issues {
		fmt.Fprintf(a.out, "  %s %s\n", a.red("✗"), issue)
	}
}

func orNone(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

func boolYes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
