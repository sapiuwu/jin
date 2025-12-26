// internal/core/server_scanner.go
package core

import "context"

// ServerScanner is the port for gathering web server info
type ServerScanner interface {
	Scan(ctx context.Context, url string) (*ServerInfo, error)
}

// ServerInfo holds the gathered data
type ServerInfo struct {
	URL            string
	Domain         string // e.g., "chat.qwen.ai"
	RootDomain     string // e.g., "qwen.ai"
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
