package service

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// TLSService is the deep TLS inspection use case.
type TLSService struct {
	inspector out.TLSInspector
	timeout   time.Duration
}

// NewTLSService builds the use case.
func NewTLSService(inspector out.TLSInspector, timeout time.Duration) *TLSService {
	return &TLSService{inspector: inspector, timeout: timeout}
}

var _ in.TLSService = (*TLSService)(nil)

// Inspect performs a deep TLS inspection of a host.
func (s *TLSService) Inspect(ctx context.Context, host string) (*in.TLSResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	report, err := s.inspector.Inspect(ctx, host)
	if err != nil {
		return nil, err
	}
	return &in.TLSResult{Report: report, Duration: time.Since(start)}, nil
}
