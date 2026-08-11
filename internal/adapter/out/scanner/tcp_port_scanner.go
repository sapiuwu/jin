package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// TCPPortScanner is an out.PortScanner adapter that performs a TCP connect
// scan against a host.
type TCPPortScanner struct {
	timeout time.Duration
}

// NewTCPPortScanner builds the adapter with a per-connection timeout.
func NewTCPPortScanner(timeout time.Duration) *TCPPortScanner {
	return &TCPPortScanner{timeout: timeout}
}

// Scan implements out.PortScanner.
func (s *TCPPortScanner) Scan(ctx context.Context, host string, ports []int) ([]domain.PortInfo, error) {
	results := make([]domain.PortInfo, 0, len(ports))

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", host, port)
		service := portToService(port)

		dialer := net.Dialer{Timeout: s.timeout}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			conn.Close()
			results = append(results, domain.PortInfo{
				Port:    port,
				Service: service,
				Status:  "open",
			})
		} else {
			results = append(results, domain.PortInfo{
				Port:    port,
				Service: service,
				Status:  "closed",
			})
		}
	}

	return results, nil
}

// portToService maps common ports to service names
func portToService(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	default:
		return "unknown"
	}
}
