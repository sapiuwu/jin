package service

import (
	"context"
	"time"

	"github.com/aliftech/jin/internal/port/in"
	"github.com/aliftech/jin/internal/port/out"
)

// CookieService is the cookie-analysis use case.
type CookieService struct {
	analyzer out.CookieAnalyzer
	timeout  time.Duration
}

// NewCookieService builds the use case.
func NewCookieService(analyzer out.CookieAnalyzer, timeout time.Duration) *CookieService {
	return &CookieService{analyzer: analyzer, timeout: timeout}
}

var _ in.CookieService = (*CookieService)(nil)

// Analyze inspects a target's Set-Cookie attributes.
func (s *CookieService) Analyze(ctx context.Context, target string) (*in.CookieResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	start := time.Now()
	analysis, err := s.analyzer.Analyze(ctx, target)
	if err != nil {
		return nil, err
	}
	return &in.CookieResult{Analysis: analysis, Duration: time.Since(start)}, nil
}
