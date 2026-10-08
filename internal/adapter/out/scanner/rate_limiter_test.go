package scanner

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRateLimiterGrantsBurstThenBlocks(t *testing.T) {
	// A refill interval far beyond the test's lifetime isolates the burst
	// behaviour: the first `burst` waits must succeed immediately.
	l := newRateLimiter(time.Hour, 3)
	defer l.Stop()

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("Wait() #%d error = %v, want nil (burst token)", i+1, err)
		}
	}

	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := l.Wait(short); err == nil {
		t.Fatal("Wait() beyond the burst succeeded, want a context deadline error")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	l := newRateLimiter(10*time.Millisecond, 1)
	defer l.Stop()

	ctx := context.Background()
	if err := l.Wait(ctx); err != nil {
		t.Fatalf("first Wait() error = %v, want nil", err)
	}

	start := time.Now()
	if err := l.Wait(ctx); err != nil {
		t.Fatalf("second Wait() error = %v, want nil after refill", err)
	}
	if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
		t.Errorf("second Wait() returned after %v, want it to block until a token was replenished", elapsed)
	}
}

func TestRateLimiterWaitHonorsContextCancellation(t *testing.T) {
	l := newRateLimiter(time.Hour, 1)
	defer l.Stop()

	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("draining Wait() error = %v, want nil", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := l.Wait(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Wait() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestNVDRatePerWindow(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   string
		override int
		want     int
	}{
		{"public default", "", 0, 5},
		{"api key default", "key", 0, 50},
		{"override wins with key", "key", 10, 10},
		{"override wins without key", "", 20, 20},
		{"negative override falls back to default", "", -1, 5},
		{"override is capped", "", 999999, nvdMaxRate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nvdRatePerWindow(tt.apiKey, tt.override); got != tt.want {
				t.Errorf("nvdRatePerWindow(%q, %d) = %d, want %d", tt.apiKey, tt.override, got, tt.want)
			}
		})
	}
}
