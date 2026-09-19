// Package validate provides pure input validation functions ensuring paths,
// network addresses, and configuration parameters comply with security policies.
package validate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// Path validates that p is safe to use as an absolute filesystem path,
// preventing directory traversal and access to sensitive runtime paths.
func Path(p, name string) error {
	if p == "" {
		return fmt.Errorf("%s: path must not be empty", name)
	}

	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s: path must be absolute, got %q", name, p)
	}

	if strings.ContainsRune(p, 0x00) {
		return fmt.Errorf("%s: path contains null byte", name)
	}

	for i, r := range p {
		if r < 0x20 && r != 0x00 {
			return fmt.Errorf("%s: path contains control character at position %d (0x%02x)", name, i, r)
		}
	}

	cleaned := filepath.Clean(p)
	if cleaned != p && cleaned+"/" != p {
		return fmt.Errorf("%s: path contains traversal sequences: %q -> %q", name, p, cleaned)
	}

	if strings.ContainsAny(p, " \t\r\n") {
		return fmt.Errorf("%s: path contains whitespace: %q", name, p)
	}

	if len(p) > 4096 {
		return fmt.Errorf("%s: path exceeds maximum length (4096), got %d", name, len(p))
	}

	restricted := []string{
		"/proc", "/sys", "/dev",
		"/run",
		"/var/run/docker.sock",
		"/var/run/containerd",
		"/.dockerenv",
	}
	for _, rPath := range restricted {
		if cleaned == rPath || strings.HasPrefix(cleaned, rPath+"/") {
			return fmt.Errorf("%s: path targets restricted location: %q", name, cleaned)
		}
	}

	return nil
}

// IsRestrictedIP checks if an IP belongs to private, loopback, link-local,
// CGNAT, or special-purpose ranges to prevent SSRF vulnerabilities.
func IsRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	if ip.IsPrivate() || !ip.IsGlobalUnicast() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}

	if ip16 := ip.To16(); ip16 != nil && ip16[0] == 0xfe && ip16[1]&0xc0 == 0xc0 {
		return true
	}

	return false
}

func defaultLookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("lookup host: %w", err)
	}
	return addrs, nil
}

var lookupHost = defaultLookupHost

// ResolveAndValidate resolves a hostname to IPs and asserts that none resolve
// to restricted or private addresses to prevent SSRF attacks.
func ResolveAndValidate(hostname string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := lookupHost(ctx, hostname)
	if err != nil {
		return fmt.Errorf("DNS resolution failed for %q: %w", hostname, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no addresses resolved for %q", hostname)
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("DNS returned unparseable address %q for %q", addr, hostname)
		}
		if IsRestrictedIP(ip) {
			return fmt.Errorf("hostname %q resolves to restricted IP %s", hostname, addr)
		}
	}
	return nil
}

// AmneziaIParam validates the syntax and bounds of AmneziaWG v2 init-packet
// templates to prevent malformed directives in generated configurations.
func AmneziaIParam(name, val string) error {
	if val == "" {
		return nil
	}
	if len(val) > 10000 {
		return fmt.Errorf("%s: value too long (%d characters, max 10000)", name, len(val))
	}

	rest := val
	for rest != "" {
		switch {
		case strings.HasPrefix(rest, "<b 0x"):
			end := strings.Index(rest, ">")
			if end < 0 {
				return fmt.Errorf("%s: unclosed <b> tag in %q", name, truncate(rest))
			}
			hex := rest[len("<b 0x"):end]
			if err := validateHex(hex); err != nil {
				return fmt.Errorf("%s: <b> tag: %w", name, err)
			}
			rest = rest[end+1:]

		case strings.HasPrefix(rest, "<c>"):
			rest = rest[len("<c>"):]

		case strings.HasPrefix(rest, "<t>"):
			rest = rest[len("<t>"):]

		case strings.HasPrefix(rest, "<r "):
			tail, err := parseTagNumeric(rest, "<r ", 0, 1000)
			if err != nil {
				return fmt.Errorf("%s: <r> tag: %w", name, err)
			}
			rest = tail

		case strings.HasPrefix(rest, "<wt "):
			tail, err := parseTagNumeric(rest, "<wt ", 0, 5000)
			if err != nil {
				return fmt.Errorf("%s: <wt> tag: %w", name, err)
			}
			rest = tail

		default:
			return fmt.Errorf("%s: unrecognised token at %q", name, truncate(rest))
		}
	}
	return nil
}

func parseTagNumeric(s, prefix string, minVal, maxVal int) (tail string, err error) {
	inner, tail, ok := strings.Cut(s[len(prefix):], ">")
	if !ok {
		return "", fmt.Errorf("malformed %s tag (missing '>'): %s", prefix, truncate(s))
	}
	if err := parseTagInt(strings.TrimSpace(inner), minVal, maxVal); err != nil {
		return "", fmt.Errorf("invalid %s tag argument: %w", prefix, err)
	}
	return tail, nil
}

func parseTagInt(s string, minVal, maxVal int) error {
	if s == "" {
		return errors.New("missing numeric argument")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return fmt.Errorf("non-numeric character %q in argument %q", r, s)
		}
		n = n*10 + int(r-'0')
	}
	if n < minVal || n > maxVal {
		return fmt.Errorf("value %d out of range [%d, %d]", n, minVal, maxVal)
	}
	return nil
}

func validateHex(s string) error {
	if s == "" {
		return errors.New("empty hex value")
	}
	for i, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return fmt.Errorf("invalid hex character %q at position %d", r, i)
		}
	}
	return nil
}

func truncate(s string) string {
	const limit = 80
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
