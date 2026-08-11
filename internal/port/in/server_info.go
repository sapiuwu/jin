// Package in defines the primary (driving) ports: the use-case interfaces
// the application exposes to its driving adapters (e.g. the CLI). Adapters
// depend on these contracts; they never see the implementations.
package in

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// ServerInfoResult is the outcome of a server-info use case.
type ServerInfoResult struct {
	Info     *domain.ServerInfo
	Security *domain.SecurityReport
	Duration time.Duration
}

// ServerInfoService gathers full server information plus a security report.
type ServerInfoService interface {
	Scan(ctx context.Context, target string) (*ServerInfoResult, error)
}
