package scanner

import (
	"context"
	"sync"
	"time"
)

// rateLimiter is a ticker-based token bucket with no third-party
// dependencies: a time.Ticker replenishes one token per interval into a
// buffered channel of at most burst tokens, and Wait blocks until one is
// taken. This paces requests to upstream services that enforce a fixed
// window budget (e.g. NVD's 5 requests per 30 seconds without an API key)
// while still allowing the initial burst the window permits.
type rateLimiter struct {
	tokens chan struct{}
	stop   chan struct{}
	once   sync.Once
}

// newRateLimiter starts a limiter that grants the first burst requests
// immediately and then refills one token every perToken, never exceeding
// burst tokens in reserve. Call Stop when the limiter is no longer needed
// (application-lifetime limiters may simply outlive it).
func newRateLimiter(perToken time.Duration, burst int) *rateLimiter {
	if burst < 1 {
		burst = 1
	}
	if perToken <= 0 {
		perToken = time.Millisecond
	}

	l := &rateLimiter{
		tokens: make(chan struct{}, burst),
		stop:   make(chan struct{}),
	}
	for i := 0; i < burst; i++ {
		l.tokens <- struct{}{}
	}

	go func() {
		ticker := time.NewTicker(perToken)
		defer ticker.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-ticker.C:
				select {
				case l.tokens <- struct{}{}:
				default: // bucket is full; the window's burst budget is spent elsewhere
				}
			}
		}
	}()

	return l
}

// Wait blocks until a token is available or ctx is done. Waiters return in
// arrival order per token; a token reserved but abandoned through context
// cancellation stays in the bucket for the next caller.
func (l *rateLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.tokens:
		return nil
	}
}

// Stop releases the replenishment goroutine.
func (l *rateLimiter) Stop() {
	l.once.Do(func() { close(l.stop) })
}
