package service

import (
	"context"
	"testing"
	"time"

	"github.com/aliftech/jin/internal/domain"
	"github.com/aliftech/jin/internal/port/out"
)

// fakePortScanner records the host and port set it was asked to probe.
type fakePortScanner struct {
	host  string
	ports []int
}

func (f *fakePortScanner) Scan(_ context.Context, host string, ports []int) ([]domain.PortInfo, error) {
	f.host = host
	f.ports = ports
	return nil, nil
}

var _ out.PortScanner = (*fakePortScanner)(nil)

func TestPortScanServiceScanHostExtraction(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"bare hostname", "example.com", "example.com"},
		{"host with port", "example.com:8080", "example.com"},
		{"url", "https://example.com/path", "example.com"},
		{"ipv4 with port", "127.0.0.1:18080", "127.0.0.1"},
		{"bracketed ipv6 with port", "[::1]:8080", "::1"},
		{"bare ipv6", "2001:db8::1", "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakePortScanner{}
			s := NewPortScanService(fake, time.Second, []int{80, 443})
			if _, err := s.Scan(context.Background(), tt.target, []int{8080}); err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if fake.host != tt.want {
				t.Errorf("Scan(%q) probed host %q, want %q", tt.target, fake.host, tt.want)
			}
		})
	}
}

func TestPortScanServiceScanPortPrecedence(t *testing.T) {
	defaults := []int{80, 443}
	tests := []struct {
		name        string
		target      string
		customPorts []int
		wantPorts   []int
	}{
		{"custom ports win over target port", "example.com:8080", []int{443}, []int{443}},
		{"custom ports win over defaults", "example.com", []int{22, 8080}, []int{22, 8080}},
		{"target port used when no custom ports", "example.com:8080", nil, []int{8080}},
		{"empty custom ports falls through to target port", "example.com:8080", []int{}, []int{8080}},
		{"defaults when neither custom nor target port", "example.com", nil, defaults},
		{"out of range target port falls back to defaults", "example.com:70000", nil, defaults},
		{"non numeric target port falls back to defaults", "example.com:http", nil, defaults},
		{"ipv6 target port honored", "[2001:db8::1]:8443", nil, []int{8443}},
		{"url without port uses defaults", "https://example.com/x", nil, defaults},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakePortScanner{}
			s := NewPortScanService(fake, time.Second, defaults)
			if _, err := s.Scan(context.Background(), tt.target, tt.customPorts); err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if len(fake.ports) != len(tt.wantPorts) {
				t.Fatalf("Scan(%q) probed ports %v, want %v", tt.target, fake.ports, tt.wantPorts)
			}
			for i := range tt.wantPorts {
				if fake.ports[i] != tt.wantPorts[i] {
					t.Fatalf("Scan(%q) probed ports %v, want %v", tt.target, fake.ports, tt.wantPorts)
				}
			}
		})
	}
}

func TestPortScanServiceScanPropagatesScannerError(t *testing.T) {
	s := NewPortScanService(&erroringPortScanner{}, time.Second, []int{80})
	if _, err := s.Scan(context.Background(), "example.com", nil); err == nil {
		t.Fatal("Scan() error = nil, want scanner error")
	}
}

type erroringPortScanner struct{}

func (erroringPortScanner) Scan(context.Context, string, []int) ([]domain.PortInfo, error) {
	return nil, context.DeadlineExceeded
}
