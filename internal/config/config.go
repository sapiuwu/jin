// Package config centralizes the tunable knobs of the application so that
// the composition root can build every adapter from a single source of
// truth.
package config

import "time"

// Config holds every tunable value used to construct the application.
type Config struct {
	HTTPTimeout          time.Duration
	PortScanTimeout      time.Duration
	PortConnectTimeout   time.Duration
	TechStackTimeout     time.Duration
	SubdomainTimeout     time.Duration
	WhoisTimeout         time.Duration
	CVETimeout           time.Duration
	DefaultPorts         []int
	MaxSubdomains        int
	SubdomainConcurrency int
}

// Default returns the production configuration.
func Default() Config {
	return Config{
		HTTPTimeout:          10 * time.Second,
		PortScanTimeout:      10 * time.Second,
		PortConnectTimeout:   3 * time.Second,
		TechStackTimeout:     10 * time.Second,
		SubdomainTimeout:     15 * time.Second,
		WhoisTimeout:         15 * time.Second,
		CVETimeout:           15 * time.Second,
		DefaultPorts:         []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379, 27017},
		MaxSubdomains:        25,
		SubdomainConcurrency: 8,
	}
}
