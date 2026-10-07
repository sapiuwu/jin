package hostutil

import "testing"

func TestSplit(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort string
	}{
		{"empty", "", "", ""},
		{"bare hostname", "example.com", "example.com", ""},
		{"hostname with port", "example.com:8080", "example.com", "8080"},
		{"hostname port 443", "example.com:443", "example.com", "443"},
		{"trailing whitespace", "  example.com:80  ", "example.com", "80"},
		{"https url", "https://example.com", "example.com", ""},
		{"http url with port and path", "http://example.com:8080/index.html", "example.com", "8080"},
		{"url with query", "https://example.com/a?b=c", "example.com", ""},
		{"url with port and query", "https://example.com:8443/a?b=c", "example.com", "8443"},
		{"url with credentials", "https://user:pass@example.com:9443/x", "example.com", "9443"},
		{"scheme-relative", "//example.com", "example.com", ""},
		{"path only", "example.com/path", "example.com", ""},
		{"ipv6 loopback bracketed", "[::1]", "::1", ""},
		{"ipv6 loopback with port", "[::1]:8080", "::1", "8080"},
		{"ipv6 literal with port", "[2001:db8::1]:443", "2001:db8::1", "443"},
		{"bare ipv6 literal", "2001:db8::1", "2001:db8::1", ""},
		{"ipv6 with zone", "[fe80::1%eth0]:80", "fe80::1%eth0", "80"},
		{"ipv4 with port", "127.0.0.1:22", "127.0.0.1", "22"},
		{"empty port after colon", "example.com:", "example.com", ""},
		{"non numeric port", "example.com:http", "example.com", "http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotPort := Split(tt.target)
			if gotHost != tt.wantHost || gotPort != tt.wantPort {
				t.Errorf("Split(%q) = (%q, %q), want (%q, %q)",
					tt.target, gotHost, gotPort, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestHost(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"", ""},
		{"example.com", "example.com"},
		{"example.com:8080", "example.com"},
		{"https://sub.example.com/path", "sub.example.com"},
		{"[::1]:8080", "::1"},
		{"2001:db8::1", "2001:db8::1"},
	}
	for _, tt := range tests {
		if got := Host(tt.target); got != tt.want {
			t.Errorf("Host(%q) = %q, want %q", tt.target, got, tt.want)
		}
	}
}

func TestDialAddress(t *testing.T) {
	tests := []struct {
		host string
		port int
		want string
	}{
		{"example.com", 80, "example.com:80"},
		{"127.0.0.1", 8080, "127.0.0.1:8080"},
		{"::1", 8080, "[::1]:8080"},
		{"[::1]", 443, "[::1]:443"},
		{"2001:db8::1", 443, "[2001:db8::1]:443"},
	}
	for _, tt := range tests {
		if got := DialAddress(tt.host, tt.port); got != tt.want {
			t.Errorf("DialAddress(%q, %d) = %q, want %q",
				tt.host, tt.port, got, tt.want)
		}
	}
}

func TestRootDomain(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"empty", "", ""},
		{"hostname", "example.com", "example.com"},
		{"subdomain", "sub.example.com", "example.com"},
		{"deep subdomain", "a.b.c.example.com", "example.com"},
		{"url", "https://sub.example.com/path", "example.com"},
		{"host with port", "api.example.com:8443", "example.com"},
		{"trailing dot", "example.com.", "example.com"},
		{"case insensitive", "SUB.Example.COM", "example.com"},
		{"single label", "localhost", "localhost"},
		{"ipv4", "192.168.1.1", ""},
		{"ipv4 with port", "192.168.1.1:8080", ""},
		{"ipv6", "::1", ""},
		{"ipv6 bracketed with port", "[2001:db8::1]:443", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RootDomain(tt.target); got != tt.want {
				t.Errorf("RootDomain(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}
