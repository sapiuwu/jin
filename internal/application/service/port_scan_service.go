package service

import (
	"context"
	"time"

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

// Scan probes the given ports (falling back to the default set) on a host.
func (s *PortScanService) Scan(ctx context.Context, host string, ports []int) (*in.PortScanResult, error) {
	if len(ports) == 0 {
		ports = s.defaultPorts
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
