// Package domain holds the pure domain models for Jin. It depends on
// nothing but the standard library and knows nothing about adapters,
// ports, or how the application is driven.
package domain

// ServerInfo holds the data gathered about a target web server.
type ServerInfo struct {
	URL            string
	Domain         string // e.g. "chat.qwen.ai"
	RootDomain     string // e.g. "qwen.ai"
	StatusCode     int
	Server         string
	PoweredBy      string
	ContentType    string
	TLSVersion     string
	TLSCipherSuite string
	Headers        map[string]string

	// Security metadata
	HasHSTS          bool
	HasXFrameOptions bool
	HasCSP           bool
	HasCSPReportOnly bool
	CSPWarnings      []string
	CookieWarnings   []string
	CloudProvider    string
}
