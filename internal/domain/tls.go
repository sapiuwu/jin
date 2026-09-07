package domain

// TLSReport holds the result of a deep TLS inspection of a host: the
// negotiated protocol and cipher, the leaf certificate, the verified chain,
// and any posture issues (expired cert, weak protocol, no OCSP stapling).
type TLSReport struct {
	Host         string
	TLSVersion   string
	CipherSuite  string
	Cert         *CertInfo
	CertChain    []CertInfo
	OCSPStapled  bool
	Issues       []string
}

// CertInfo is a flattened view of an x509 certificate.
type CertInfo struct {
	Subject             string
	Issuer              string
	SerialNumber        string
	NotBefore           string
	NotAfter            string
	DNSNames           []string
	FingerprintSHA256  string
}
