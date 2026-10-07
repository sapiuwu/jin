package in

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// PortScanResult is the outcome of a port-scan use case.
type PortScanResult struct {
	Results  []domain.PortInfo
	Duration time.Duration
}

// PortScanService probes a target for open ports. The target may be a
// bare host, a host:port pair, a bracketed IPv6 address, or a URL; the
// implementation extracts the host and decides which ports to probe
// (explicit list vs. target-embedded port vs. defaults).
type PortScanService interface {
	Scan(ctx context.Context, target string, ports []int) (*PortScanResult, error)
}
