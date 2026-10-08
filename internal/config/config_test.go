package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// isolate points the config file at a non-existent path and clears the
// Phase-2 environment knobs so the invoking user's real ~/.jin.json and
// JIN_* variables never leak into a test.
func isolate(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"JIN_NVD_API_KEY", "JIN_NVD_RATE_LIMIT", "JIN_CACHE_DIR",
		"JIN_NVD_CACHE_TTL", "JIN_CT_CACHE_TTL",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("JIN_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
}

func TestLoadDefaultsForNVDAndCache(t *testing.T) {
	isolate(t)

	cfg := Load()
	if cfg.NVDAPIKey != "" {
		t.Errorf("NVDAPIKey = %q, want empty by default", cfg.NVDAPIKey)
	}
	if cfg.NVDRateLimit != 0 {
		t.Errorf("NVDRateLimit = %d, want 0 (automatic)", cfg.NVDRateLimit)
	}
	if cfg.NVDCacheTTL != 24*time.Hour {
		t.Errorf("NVDCacheTTL = %v, want 24h", cfg.NVDCacheTTL)
	}
	if cfg.CTCacheTTL != 6*time.Hour {
		t.Errorf("CTCacheTTL = %v, want 6h", cfg.CTCacheTTL)
	}
	if cfg.CacheDir != "" && !strings.HasSuffix(filepath.ToSlash(cfg.CacheDir), ".jin/cache") {
		t.Errorf("CacheDir = %q, want it to point at ~/.jin/cache", cfg.CacheDir)
	}
}

func TestLoadAppliesConfigFile(t *testing.T) {
	isolate(t)
	path := filepath.Join(t.TempDir(), ".jin.json")
	data := `{"nvd_api_key":"file-key","nvd_rate_limit":20,"cache_dir":"/tmp/jincache",` +
		`"nvd_cache_ttl":"2h","ct_cache_ttl":"1h"}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}
	t.Setenv("JIN_CONFIG", path)

	cfg := Load()
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"nvd_api_key", cfg.NVDAPIKey, "file-key"},
		{"nvd_rate_limit", cfg.NVDRateLimit, 20},
		{"cache_dir", cfg.CacheDir, "/tmp/jincache"},
		{"nvd_cache_ttl", cfg.NVDCacheTTL, 2 * time.Hour},
		{"ct_cache_ttl", cfg.CTCacheTTL, time.Hour},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

func TestEnvOverridesConfigFileForNVDAndCache(t *testing.T) {
	isolate(t)
	path := filepath.Join(t.TempDir(), ".jin.json")
	data := `{"nvd_api_key":"file-key","nvd_rate_limit":20,"nvd_cache_ttl":"2h"}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("writing config file: %v", err)
	}
	t.Setenv("JIN_CONFIG", path)
	t.Setenv("JIN_NVD_API_KEY", "env-key")
	t.Setenv("JIN_NVD_RATE_LIMIT", "33")
	t.Setenv("JIN_NVD_CACHE_TTL", "45m")

	cfg := Load()
	if cfg.NVDAPIKey != "env-key" {
		t.Errorf("NVDAPIKey = %q, want env-key (env beats file)", cfg.NVDAPIKey)
	}
	if cfg.NVDRateLimit != 33 {
		t.Errorf("NVDRateLimit = %d, want 33 (env beats file)", cfg.NVDRateLimit)
	}
	if cfg.NVDCacheTTL != 45*time.Minute {
		t.Errorf("NVDCacheTTL = %v, want 45m (env beats file)", cfg.NVDCacheTTL)
	}
	if cfg.CTCacheTTL != 6*time.Hour {
		t.Errorf("CTCacheTTL = %v, want the 6h default", cfg.CTCacheTTL)
	}
}

func TestApplyArgsOverridesEnv(t *testing.T) {
	isolate(t)
	t.Setenv("JIN_NVD_RATE_LIMIT", "10")
	t.Setenv("JIN_CACHE_DIR", "/tmp/env-cache")
	t.Setenv("JIN_NVD_CACHE_TTL", "3h")

	cfg := Load()
	ApplyArgs(&cfg, []string{
		"tech-stack", "-t", "example.com",
		"--nvd-rate-limit", "25",
		"--cache-dir", "/tmp/flag-cache",
		"--nvd-cache-ttl", "90m",
		"--ct-cache-ttl", "30m",
	})

	if cfg.NVDRateLimit != 25 {
		t.Errorf("NVDRateLimit = %d, want 25 (flag beats env)", cfg.NVDRateLimit)
	}
	if cfg.CacheDir != "/tmp/flag-cache" {
		t.Errorf("CacheDir = %q, want /tmp/flag-cache (flag beats env)", cfg.CacheDir)
	}
	if cfg.NVDCacheTTL != 90*time.Minute {
		t.Errorf("NVDCacheTTL = %v, want 90m (flag beats env)", cfg.NVDCacheTTL)
	}
	if cfg.CTCacheTTL != 30*time.Minute {
		t.Errorf("CTCacheTTL = %v, want 30m (flag beats env)", cfg.CTCacheTTL)
	}
}

func TestApplyArgsNoCacheDisablesDiskLayer(t *testing.T) {
	isolate(t)
	t.Setenv("JIN_CACHE_DIR", "/tmp/env-cache")

	cfg := Load()
	ApplyArgs(&cfg, []string{"--no-cache"})
	if cfg.CacheDir != "" {
		t.Errorf("CacheDir = %q, want empty after --no-cache", cfg.CacheDir)
	}
}

func TestApplyArgsIgnoresMalformedValues(t *testing.T) {
	isolate(t)
	t.Setenv("JIN_NVD_RATE_LIMIT", "10")

	cfg := Load()
	ApplyArgs(&cfg, []string{"info", "--nvd-rate-limit", "abc", "--nvd-cache-ttl", "soon"})

	if cfg.NVDRateLimit != 10 {
		t.Errorf("NVDRateLimit = %d, want the env value 10 (malformed flag ignored)", cfg.NVDRateLimit)
	}
	if cfg.NVDCacheTTL != 24*time.Hour {
		t.Errorf("NVDCacheTTL = %v, want the 24h default (malformed flag ignored)", cfg.NVDCacheTTL)
	}
}
