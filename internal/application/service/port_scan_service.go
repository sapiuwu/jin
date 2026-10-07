package service

import (
	"context"
	"strconv"
	"time"

	"github.com/aliftech/jin/internal/hostutil"
	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// PortScanService is the port-scan use case.
type PortScanService struct {
	scanner      out.PortScanner
	timeout      time.Duration
	defaultPorts []int
}

// NewPortScanService builds the use case with its driven port, an overall
// scan budget, and the default port set used when none is supplied.
func NewPortScanService(scanner out.PortScanner, timeout time.Duration, defaultPorts []int) *PortScanService {
	return &PortScanService{scanner: scanner, timeout: timeout, defaultPorts: defaultPorts}
}

var _ in.PortScanService = (*PortScanService)(nil)

// Scan probes target for open ports. target may be a bare host, a
// host:port pair, a bracketed IPv6 address, or a full URL — the host is
// extracted here so every caller (the ports command and the full scan)
// shares the same parsing. Port selection precedence: an explicit ports
// argument, then a port embedded in target, then the default port set.
func (s *PortScanService) Scan(ctx context.Context, target string, ports []int) (*in.PortScanResult, error) {
	host, targetPort := hostutil.Split(target)
	if host == "" {
		host = target
	}
	if len(ports) == 0 {
		if n, ok := validPort(targetPort); ok {
			ports = []int{n}
		} else {
			ports = s.defaultPorts
		}
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	results, err := s.scanner.Scan(ctx, host, ports)
	if err != nil {
		return nil, err
	}
	return &in.PortScanResult{Results: results, Duration: time.Since(start)}, nil
}

// validPort reports whether raw is a syntactically valid TCP port number.
// Anything else (empty, non-numeric, out of 1-65535 range) is ignored so
// the scan falls back to the default port set.
func validPort(raw string) (int, bool) {
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}
