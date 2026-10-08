package cli

import (
	"reflect"
	"testing"
)

func TestParseArgsConsumesStartupConfigFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantPos  []string
		wantJSON bool
	}{
		{
			"flags after the command",
			[]string{"tech-stack", "-t", "example.com", "--cache-dir", "/tmp/c", "--no-cache"},
			[]string{"tech-stack", "example.com"},
			false,
		},
		{
			"flags before the command",
			[]string{"--nvd-rate-limit", "25", "--nvd-cache-ttl", "2h", "tech-stack", "example.com"},
			[]string{"tech-stack", "example.com"},
			false,
		},
		{
			"startup flags mixed with regular flags",
			[]string{"scan", "example.com", "--cve", "--ct-cache-ttl", "30m", "-j"},
			[]string{"scan", "example.com"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parseArgs(tt.args)
			if err != nil {
				t.Fatalf("parseArgs(%v) error = %v", tt.args, err)
			}
			if !reflect.DeepEqual(p.positionals, tt.wantPos) {
				t.Errorf("parseArgs(%v) positionals = %v, want %v (config flags must not leak)", tt.args, p.positionals, tt.wantPos)
			}
			if p.json != tt.wantJSON {
				t.Errorf("parseArgs(%v) json = %v, want %v", tt.args, p.json, tt.wantJSON)
			}
		})
	}
}

func TestParseArgsStartupConfigFlagRequiresValue(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"missing cache dir", []string{"info", "--cache-dir"}},
		{"missing rate limit", []string{"info", "--nvd-rate-limit"}},
		{"missing nvd ttl", []string{"info", "--nvd-cache-ttl"}},
		{"missing ct ttl", []string{"info", "--ct-cache-ttl"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseArgs(tt.args); err == nil {
				t.Errorf("parseArgs(%v) error = nil, want a missing-value error", tt.args)
			}
		})
	}
}
