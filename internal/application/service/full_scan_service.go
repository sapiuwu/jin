package service

import (
	"context"
	"strings"
	"time"

	"github.com/aliftech/jin/internal/port/in"
)

// FullScanService is the combined recon use case. It runs the server-info,
// port, and tech-stack scans together and returns one consolidated result.
type FullScanService struct {
	info      in.ServerInfoService
	ports     in.PortScanService
	techstack in.TechStackService
}

// NewFullScanService builds the use case from its driving ports.
func NewFullScanService(info in.ServerInfoService, ports in.PortScanService, techstack in.TechStackService) *FullScanService {
	return &FullScanService{info: info, ports: ports, techstack: techstack}
}

var _ in.FullScanService = (*FullScanService)(nil)

// Scan runs all three modules against target and merges their results.
func (s *FullScanService) Scan(ctx context.Context, target string, opts in.FullScanOptions) (*in.FullScanResult, error) {
	start := time.Now()
	res := &in.FullScanResult{Target: target}

	info, err := s.info.Scan(ctx, target)
	if err == nil {
		res.Info = info
	}

	host := target
	if i := strings.Index(host, "://"); i != -1 {
		host = host[i+3:]
	}
	if i := strings.IndexByte(host, '/'); i != -1 {
		host = host[:i]
	}
	if i := strings.IndexByte(host, ':'); i != -1 {
		host = host[:i]
	}
	ports, err := s.ports.Scan(ctx, host, opts.CustomPorts)
	if err == nil {
		res.Ports = ports
	}

	tech, err := s.techstack.Scan(ctx, target, in.TechStackOptions{Deep: opts.Deep, CVE: opts.CVE})
	if err == nil {
		res.TechStack = tech
	}

	res.Duration = time.Since(start)
	return res, nil
}
