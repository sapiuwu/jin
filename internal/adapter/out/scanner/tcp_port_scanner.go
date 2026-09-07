package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// TCPPortScanner is an out.PortScanner adapter that performs a TCP connect
// scan against a host. Probes run concurrently (bounded by a worker pool)
// and each probe retries with a short backoff to absorb transient network
// blips before a port is declared closed.
type TCPPortScanner struct {
	timeout     time.Duration
	concurrency int
	retries     int
	backoff     time.Duration
}

// NewTCPPortScanner builds the adapter. connectTimeout bounds each dial
// attempt, concurrency bounds how many ports are probed in parallel, and
// retries (with backoff) are applied per port.
func NewTCPPortScanner(connectTimeout time.Duration, concurrency int) *TCPPortScanner {
	if concurrency <= 0 {
		concurrency = 50
	}
	return &TCPPortScanner{
		timeout:     connectTimeout,
		concurrency: concurrency,
		retries:     2,
		backoff:     100 * time.Millisecond,
	}
}

// Scan implements out.PortScanner.
func (s *TCPPortScanner) Scan(ctx context.Context, host string, ports []int) ([]domain.PortInfo, error) {
	results := make([]domain.PortInfo, len(ports))

	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup

	for i, port := range ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info := s.probe(ctx, host, port)
			select {
			case <-ctx.Done():
			default:
			}
			results[i] = info
		}(i, port)
	}

	wg.Wait()
	return results, nil
}

// probe dials a single port, retrying with backoff. A port is reported
// "open" only if at least one attempt succeeds.
func (s *TCPPortScanner) probe(ctx context.Context, host string, port int) domain.PortInfo {
	address := fmt.Sprintf("%s:%d", host, port)
	service := portToService(port)

	for attempt := 0; attempt < s.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return domain.PortInfo{Port: port, Service: service, Status: "closed"}
			case <-time.After(s.backoff):
			}
		}

		dialer := net.Dialer{Timeout: s.timeout}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			conn.Close()
			return domain.PortInfo{Port: port, Service: service, Status: "open"}
		}
	}

	return domain.PortInfo{Port: port, Service: service, Status: "closed"}
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
