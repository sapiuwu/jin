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

// PortScanService probes a host for open ports.
type PortScanService interface {
	Scan(ctx context.Context, host string, ports []int) (*PortScanResult, error)
}
