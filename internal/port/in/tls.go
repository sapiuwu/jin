package in

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// TLSResult is the outcome of a deep TLS inspection use case.
type TLSResult struct {
	Report   *domain.TLSReport
	Duration time.Duration
}

// TLSService inspects the TLS configuration of a host.
type TLSService interface {
	Inspect(ctx context.Context, host string) (*TLSResult, error)
}
