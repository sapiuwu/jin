// Package service implements the application layer: the use cases of the
// system. Services orchestrate the driven (out) ports and expose
// themselves through the driving (in) ports. They know nothing about CLI,
// JSON, HTTP clients, or any adapter.
package service

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// ServerInfoService is the server-reconnaissance use case.
type ServerInfoService struct {
	scanner out.ServerScanner
	timeout time.Duration
}

// NewServerInfoService builds the use case with its driven port and an
// overall scan budget.
func NewServerInfoService(scanner out.ServerScanner, timeout time.Duration) *ServerInfoService {
	return &ServerInfoService{scanner: scanner, timeout: timeout}
}

var _ in.ServerInfoService = (*ServerInfoService)(nil)

// Scan fetches the server info and derives its security report.
func (s *ServerInfoService) Scan(ctx context.Context, target string) (*in.ServerInfoResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	info, err := s.scanner.Scan(ctx, target)
	if err != nil {
		return nil, err
	}
	return &in.ServerInfoResult{
		Info:     info,
		Security: AnalyzeSecurity(info),
		Duration: time.Since(start),
	}, nil
}
