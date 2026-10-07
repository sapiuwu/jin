// Package hostutil centralizes target-string parsing for Jin. A user may
// supply a target as a bare hostname, a host:port pair, a bracketed IPv6
// address, a URL, or any of those with credentials. Every layer that needs
// a hostname, a port, or a dial address goes through this package so the
// IPv6 and host:port handling stays consistent.
package hostutil

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Split parses target into its host and port components. It accepts:
//
//	example.com            -> example.com, ""
//	example.com:8080       -> example.com, 8080
//	[::1]:8080             -> ::1, 8080
//	2001:db8::1            -> 2001:db8::1, "" (bare IPv6 has no port)
//	https://u:p@x.com:8443/p?q -> x.com, 8443
//
// The port is returned as a raw string; callers decide whether an invalid
// or out-of-range port is an error. Split never fails: an unparseable
// target yields the whole string as the host and an empty port.
func Split(target string) (host, port string) {
	s := strings.TrimSpace(target)
	if s == "" {
		return "", ""
	}

	// Strip a URL scheme, but only when "://" precedes any path so a
	// literal containing "://" later in the string is left alone.
	if i := strings.Index(s, "://"); i != -1 {
		if j := strings.IndexAny(s, "/?#"); j == -1 || j > i {
			s = s[i+3:]
		}
	}
	s = strings.TrimPrefix(s, "//")

	if i := strings.IndexAny(s, "/?#"); i != -1 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i != -1 {
		s = s[i+1:]
	}
	if s == "" {
		return "", ""
	}

	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end == -1 {
			return s, ""
		}
		rest := s[end+1:]
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return s[1:end], port
	}

	if strings.Count(s, ":") == 1 {
		if i := strings.LastIndex(s, ":"); i != -1 {
			return s[:i], s[i+1:]
		}
	}

	// A plain hostname or a bare IPv6 address (multiple colons, no
	// brackets): without brackets an IPv6 literal cannot carry a port.
	return s, ""
}

// Host returns just the host portion of target, without brackets,
// scheme, credentials, path, or port. It is the replacement for the old
// per-call-site cleanHost/tlsHost helpers.
func Host(target string) string {
	host, _ := Split(target)
	return host
}

// DialAddress builds a net.Dial-compatible address for host and port.
// IPv6 hosts are bracketed as required by the "host:port" dial syntax.
func DialAddress(host string, port int) string {
	return net.JoinHostPort(unbracket(host), strconv.Itoa(port))
}

// RootDomain reduces target to its registrable domain using a naive
// last-two-labels heuristic. It does not handle multi-part public
// suffixes correctly (e.g. "example.co.uk" would be truncated to
// "co.uk"); for full correctness, resolve against the public suffix
// list. IP literals yield "" since they have no root domain.
func RootDomain(target string) string {
	host := strings.ToLower(strings.TrimSuffix(Host(target), "."))
	if host == "" {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

func unbracket(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}
