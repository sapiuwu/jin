package in

import (
	"context"
	"time"
)

// FullScanResult is the consolidated outcome of a combined recon pass.
type FullScanResult struct {
	Target    string
	Info      *ServerInfoResult
	Ports     *PortScanResult
	TechStack *TechStackResult
	Duration  time.Duration
}

// FullScanOptions controls a combined scan.
type FullScanOptions struct {
	Deep        bool
	CVE         bool
	CustomPorts []int
}

// FullScanService runs a server-info, port, and tech-stack scan together and
// returns a single consolidated result.
type FullScanService interface {
	Scan(ctx context.Context, target string, opts FullScanOptions) (*FullScanResult, error)
}
