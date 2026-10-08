// Package config centralizes the tunable knobs of the application so that
// the composition root can build every adapter from a single source of
// truth. Values are resolved with the precedence:
//
//	explicit CLI flags  >  environment variables (JIN_*)  >  config file  >  built-in defaults
//
// The config file is optional JSON at $JIN_CONFIG (default ~/.jin.json).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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
	PortConcurrency      int
	Proxy                string        // optional upstream proxy (http/https/socks5), empty = direct
	Format               string        // default output format: "table" or "json"
	NVDAPIKey            string        // NVD API key (sent via the apiKey header), empty = unauthenticated
	NVDRateLimit         int           // NVD requests per 30s window; 0 = automatic (5 unauth / 50 with key)
	CacheDir             string        // on-disk cache directory; "" disables disk caching
	NVDCacheTTL          time.Duration // TTL for cached NVD CVE lookups
	CTCacheTTL           time.Duration // TTL for cached crt.sh enumerations
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
		PortConcurrency:      50,
		Proxy:                "",
		Format:               "table",
		NVDAPIKey:            "",
		NVDRateLimit:         0,
		CacheDir:             defaultCacheDir(),
		NVDCacheTTL:          24 * time.Hour,
		CTCacheTTL:           6 * time.Hour,
	}
}

// Load resolves the effective configuration by layering, in increasing
// priority: built-in defaults, an optional JSON config file, then
// environment variables. A malformed config file is ignored (with no error)
// so the tool still runs with defaults.
func Load() Config {
	cfg := Default()

	if path := configPath(); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var file struct {
				HTTPTimeout          string `json:"http_timeout"`
				PortScanTimeout      string `json:"port_scan_timeout"`
				PortConnectTimeout   string `json:"port_connect_timeout"`
				TechStackTimeout     string `json:"techstack_timeout"`
				SubdomainTimeout     string `json:"subdomain_timeout"`
				WhoisTimeout         string `json:"whois_timeout"`
				CVETimeout           string `json:"cve_timeout"`
				DefaultPorts         []int  `json:"default_ports"`
				MaxSubdomains        int    `json:"max_subdomains"`
				SubdomainConcurrency int    `json:"subdomain_concurrency"`
				PortConcurrency      int    `json:"port_concurrency"`
				Proxy                string `json:"proxy"`
				Format               string `json:"format"`
				NVDAPIKey            string `json:"nvd_api_key"`
				NVDRateLimit         int    `json:"nvd_rate_limit"`
				CacheDir             string `json:"cache_dir"`
				NVDCacheTTL          string `json:"nvd_cache_ttl"`
				CTCacheTTL           string `json:"ct_cache_ttl"`
			}
			if err := json.Unmarshal(data, &file); err == nil {
				if d, err := time.ParseDuration(file.HTTPTimeout); err == nil {
					cfg.HTTPTimeout = d
				}
				if d, err := time.ParseDuration(file.PortScanTimeout); err == nil {
					cfg.PortScanTimeout = d
				}
				if d, err := time.ParseDuration(file.PortConnectTimeout); err == nil {
					cfg.PortConnectTimeout = d
				}
				if d, err := time.ParseDuration(file.TechStackTimeout); err == nil {
					cfg.TechStackTimeout = d
				}
				if d, err := time.ParseDuration(file.SubdomainTimeout); err == nil {
					cfg.SubdomainTimeout = d
				}
				if d, err := time.ParseDuration(file.WhoisTimeout); err == nil {
					cfg.WhoisTimeout = d
				}
				if d, err := time.ParseDuration(file.CVETimeout); err == nil {
					cfg.CVETimeout = d
				}
				if len(file.DefaultPorts) > 0 {
					cfg.DefaultPorts = file.DefaultPorts
				}
				if file.MaxSubdomains > 0 {
					cfg.MaxSubdomains = file.MaxSubdomains
				}
				if file.SubdomainConcurrency > 0 {
					cfg.SubdomainConcurrency = file.SubdomainConcurrency
				}
				if file.PortConcurrency > 0 {
					cfg.PortConcurrency = file.PortConcurrency
				}
				if file.Proxy != "" {
					cfg.Proxy = file.Proxy
				}
				if file.Format != "" {
					cfg.Format = file.Format
				}
				if file.NVDAPIKey != "" {
					cfg.NVDAPIKey = file.NVDAPIKey
				}
				if file.NVDRateLimit > 0 {
					cfg.NVDRateLimit = file.NVDRateLimit
				}
				if file.CacheDir != "" {
					cfg.CacheDir = file.CacheDir
				}
				if d, err := time.ParseDuration(file.NVDCacheTTL); err == nil && d > 0 {
					cfg.NVDCacheTTL = d
				}
				if d, err := time.ParseDuration(file.CTCacheTTL); err == nil && d > 0 {
					cfg.CTCacheTTL = d
				}
			}
		}
	}

	applyEnv(&cfg)
	return cfg
}

// applyEnv overlays JIN_-prefixed environment variables onto cfg.
func applyEnv(cfg *Config) {
	if v := os.Getenv("JIN_HTTP_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.HTTPTimeout = d
		}
	}
	if v := os.Getenv("JIN_PORT_SCAN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.PortScanTimeout = d
		}
	}
	if v := os.Getenv("JIN_PORT_CONNECT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.PortConnectTimeout = d
		}
	}
	if v := os.Getenv("JIN_TECHSTACK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.TechStackTimeout = d
		}
	}
	if v := os.Getenv("JIN_SUBDOMAIN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.SubdomainTimeout = d
		}
	}
	if v := os.Getenv("JIN_WHOIS_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.WhoisTimeout = d
		}
	}
	if v := os.Getenv("JIN_CVE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.CVETimeout = d
		}
	}
	if v := os.Getenv("JIN_MAX_SUBDOMAINS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MaxSubdomains = n
		}
	}
	if v := os.Getenv("JIN_SUBDOMAIN_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.SubdomainConcurrency = n
		}
	}
	if v := os.Getenv("JIN_PORT_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.PortConcurrency = n
		}
	}
	if v := os.Getenv("JIN_PROXY"); v != "" {
		cfg.Proxy = v
	}
	if v := os.Getenv("JIN_FORMAT"); v != "" {
		cfg.Format = v
	}
	if v := os.Getenv("JIN_DEFAULT_PORTS"); v != "" {
		if ports, ok := parsePortsEnv(v); ok {
			cfg.DefaultPorts = ports
		}
	}
	if v := os.Getenv("JIN_NVD_API_KEY"); v != "" {
		cfg.NVDAPIKey = v
	}
	if v := os.Getenv("JIN_NVD_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.NVDRateLimit = n
		}
	}
	if v := os.Getenv("JIN_CACHE_DIR"); v != "" {
		cfg.CacheDir = v
	}
	if v := os.Getenv("JIN_NVD_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.NVDCacheTTL = d
		}
	}
	if v := os.Getenv("JIN_CT_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.CTCacheTTL = d
		}
	}
}

// ApplyArgs overlays the recognized startup flags onto cfg, giving them the
// highest precedence in the documented layering (flag > env > file >
// default). It is called once from main before the composition root is
// built; the CLI parser consumes the same flags so they never leak into
// positional arguments. Malformed values are ignored (the CLI parser
// reports them) so a partial flag list never breaks an otherwise valid run.
//
// Recognized flags:
//
//	--cache-dir <dir>       on-disk cache directory
//	--no-cache              disable the on-disk cache (memory layer stays)
//	--nvd-cache-ttl <dur>   TTL for cached NVD lookups (e.g. 24h)
//	--ct-cache-ttl <dur>    TTL for cached crt.sh enumerations (e.g. 6h)
//	--nvd-rate-limit <n>    NVD requests per 30s window
func ApplyArgs(cfg *Config, args []string) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--cache-dir":
			if i+1 < len(args) && args[i+1] != "" {
				i++
				cfg.CacheDir = args[i]
			}
		case "--no-cache":
			cfg.CacheDir = ""
		case "--nvd-cache-ttl":
			if i+1 < len(args) {
				i++
				if d, err := time.ParseDuration(args[i]); err == nil && d > 0 {
					cfg.NVDCacheTTL = d
				}
			}
		case "--ct-cache-ttl":
			if i+1 < len(args) {
				i++
				if d, err := time.ParseDuration(args[i]); err == nil && d > 0 {
					cfg.CTCacheTTL = d
				}
			}
		case "--nvd-rate-limit":
			if i+1 < len(args) {
				i++
				if n, err := strconv.Atoi(args[i]); err == nil && n > 0 {
					cfg.NVDRateLimit = n
				}
			}
		}
	}
}

// parsePortsEnv parses a comma-separated port list from an env var.
func parsePortsEnv(raw string) ([]int, bool) {
	var ports []int
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		ports = append(ports, n)
	}
	if len(ports) == 0 {
		return nil, false
	}
	return ports, true
}

// configPath resolves the config file location: $JIN_CONFIG if set,
// otherwise ~/.jin.json. It returns "" when the home directory is unknown.
func configPath() string {
	if p := os.Getenv("JIN_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".jin.json")
}

// defaultCacheDir resolves the on-disk cache directory (~/.jin/cache).
// It returns "" when the home directory is unknown, which simply disables
// disk caching — never an error.
func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".jin", "cache")
}
