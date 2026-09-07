package in

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/domain"
)

// CookieResult is the outcome of a cookie-analysis use case.
type CookieResult struct {
	Analysis *domain.CookieAnalysis
	Duration time.Duration
}

// CookieService analyzes a target's Set-Cookie attributes.
type CookieService interface {
	Analyze(ctx context.Context, target string) (*CookieResult, error)
}
