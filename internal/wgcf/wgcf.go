// Package wgcf manages the Cloudflare WARP WireGuard configuration lifecycle
// via the wgcf binary, provisioning accounts and extracting profile details.
package wgcf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
)

func defaultExecuteWgcf(ctx context.Context, bin, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("execute wgcf: %w", err)
	}
	return out, nil
}

var (
	executeWgcf = defaultExecuteWgcf
	osMkdirAll  = os.MkdirAll
	osRemove    = os.Remove
	osOpen      = os.Open
	osOpenFile  = os.OpenFile
)

const maxWgcfFileSize = 64 * 1024

// Profile holds the WireGuard parameters extracted from wgcf-profile.conf
// that are needed to populate the mihomo proxy block.
type Profile struct {
	PrivateKey string
	PublicKey  string
	IPv4       string
	IPv6       string
}

// Setup ensures a valid wgcf account and WireGuard profile exist under
// cfg.Paths.WgcfData, creating or regenerating them as directed by configuration.
func Setup(cfg *config.Config, log *logging.Logger) error {
	if err := osMkdirAll(cfg.Paths.WgcfData, 0o750); err != nil {
		return fmt.Errorf("wgcf: create data directory %q: %w", cfg.Paths.WgcfData, err)
	}

	accountExists := fileExists(cfg.Paths.WgcfAccountFile)
	profileExists := fileExists(cfg.Paths.WgcfProfileFile)

	log.Debugf("wgcf: account exists=%v profile exists=%v regenerate=%v",
		accountExists, profileExists, cfg.Warp.Regenerate)

	if accountExists && profileExists && cfg.Warp.Regenerate {
		log.Debug("wgcf: WARP_REGENERATE=true, removing existing account and profile")
		if err := osRemove(cfg.Paths.WgcfAccountFile); err != nil {
			return fmt.Errorf("wgcf: remove account file: %w", err)
		}
		if err := osRemove(cfg.Paths.WgcfProfileFile); err != nil {
			return fmt.Errorf("wgcf: remove profile file: %w", err)
		}
		accountExists = false
		profileExists = false
	}

	if !accountExists {
		log.Debug("wgcf: registering new account")
		if err := register(cfg, log); err != nil {
			return err
		}
	}

	if cfg.Warp.PlusKey != "" {
		log.Debug("wgcf: applying WARP+ license key")
		if err := updateLicense(cfg, log); err != nil {
			log.Warnf("wgcf: WARP+ key update failed, continuing with free account: %v", err)
		}
	}

	if !profileExists || cfg.Warp.PlusKey != "" {
		log.Debug("wgcf: generating WireGuard profile")
		if err := generate(cfg, log); err != nil {
			return err
		}
	}

	if err := secureFiles(cfg); err != nil {
		return err
	}

	return nil
}

// ParseProfile reads cfg.Paths.WgcfProfileFile and returns the extracted
// WireGuard parameters required for mihomo proxy generation.
func ParseProfile(cfg *config.Config) (profile *Profile, retErr error) {
	path := cfg.Paths.WgcfProfileFile

	perms, err := filePermissions(path)
	if err != nil {
		return nil, fmt.Errorf("wgcf: stat profile %q: %w", path, err)
	}
	if perms != 0o600 && perms != 0o400 {
		return nil, fmt.Errorf("wgcf: profile %q has unsafe permissions %04o (want 0o600 or 0o400)", path, perms)
	}

	f, err := osOpen(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("wgcf: read profile %q: %w", path, err)
	}
	defer func() {
		if closeErr := fileClose(f); closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("wgcf: close profile %q: %w", path, closeErr)
		}
	}()

	data, err := fileReadAll(io.LimitReader(f, maxWgcfFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("wgcf: read profile %q: %w", path, err)
	}
	if len(data) > maxWgcfFileSize {
		return nil, fmt.Errorf("wgcf: profile %q exceeds 64KB limit", path)
	}

	p, err := parseINI(string(data))
	if err != nil {
		return nil, fmt.Errorf("wgcf: parse profile %q: %w", path, err)
	}

	if err := validateProfile(p); err != nil {
		return nil, fmt.Errorf("wgcf: invalid profile %q: %w", path, err)
	}

	return p, nil
}

func register(cfg *config.Config, log *logging.Logger) error {
	return runWgcf(cfg, log, "register", "--accept-tos")
}

func updateLicense(cfg *config.Config, log *logging.Logger) error {
	return runWgcf(cfg, log, "update", "--license-key", cfg.Warp.PlusKey)
}

func generate(cfg *config.Config, log *logging.Logger) error {
	return runWgcf(cfg, log, "generate")
}

func runWgcf(cfg *config.Config, log *logging.Logger, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := executeWgcf(ctx, cfg.Paths.WgcfBin, cfg.Paths.WgcfData, args...)
	if err != nil {
		return fmt.Errorf("wgcf %s: %w\noutput: %s",
			redactArgs(args), err, sanitizeOutput(out))
	}

	log.Debugf("wgcf %s: ok", redactArgs(args))
	return nil
}

func redactArgs(args []string) string {
	safe := make([]string, len(args))
	copy(safe, args)
	for i, arg := range safe {
		if arg == "--license-key" && i+1 < len(safe) {
			safe[i+1] = "***REDACTED***"
			break
		}
	}
	return strings.Join(safe, " ")
}

func secureFiles(cfg *config.Config) error {
	for _, path := range []string{cfg.Paths.WgcfAccountFile, cfg.Paths.WgcfProfileFile} {
		f, err := osOpenFile(path, os.O_RDONLY|oNoFollow, 0)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("wgcf: open %q: %w", path, err)
		}
		chmodErr := fileChmod(f, 0o600)
		closeErr := fileClose(f)
		if chmodErr != nil {
			return fmt.Errorf("wgcf: chmod %q: %w", path, chmodErr)
		}
		if closeErr != nil {
			return fmt.Errorf("wgcf: close %q: %w", path, closeErr)
		}
	}
	return nil
}

func parseINI(content string) (*Profile, error) {
	p := &Profile{}
	var currentSection string

	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line[1 : len(line)-1]
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch {
		case currentSection == "Interface" && key == "PrivateKey":
			p.PrivateKey = value

		case currentSection == "Interface" && key == "Address":
			ipv4, ipv6, err := splitAddresses(value)
			if err != nil {
				return nil, fmt.Errorf("parse Address %q: %w", value, err)
			}
			p.IPv4 = ipv4
			p.IPv6 = ipv6

		case currentSection == "Peer" && key == "PublicKey":
			p.PublicKey = value
		}
	}

	return p, nil
}

func splitAddresses(raw string) (ipv4, ipv6 string, err error) {
	for part := range strings.SplitSeq(raw, ",") {
		addr := strings.TrimSpace(part)
		if idx := strings.Index(addr, "/"); idx >= 0 {
			addr = addr[:idx]
		}
		if strings.Contains(addr, ":") {
			ipv6 = addr
		} else {
			ipv4 = addr
		}
	}
	if ipv4 == "" {
		return "", "", fmt.Errorf("no IPv4 address found in %q", raw)
	}
	if ipv6 == "" {
		return "", "", fmt.Errorf("no IPv6 address found in %q", raw)
	}
	return ipv4, ipv6, nil
}

func validateProfile(p *Profile) error {
	if len(p.PrivateKey) != 44 {
		return fmt.Errorf("PrivateKey must be 44 characters, got %d", len(p.PrivateKey))
	}
	if len(p.PublicKey) != 44 {
		return fmt.Errorf("PublicKey must be 44 characters, got %d", len(p.PublicKey))
	}
	if p.IPv4 == "" {
		return errors.New("IPv4 address missing")
	}
	if p.IPv6 == "" {
		return errors.New("IPv6 address missing")
	}
	for _, r := range p.PrivateKey {
		if !isBase64Char(r) {
			return fmt.Errorf("PrivateKey contains invalid character %q", r)
		}
	}
	for _, r := range p.PublicKey {
		if !isBase64Char(r) {
			return fmt.Errorf("PublicKey contains invalid character %q", r)
		}
	}
	return nil
}

func isBase64Char(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') || r == '+' || r == '/' || r == '='
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func filePermissions(path string) (os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat file %q: %w", path, err)
	}
	return info.Mode().Perm(), nil
}

func sanitizeOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	const limit = 512
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

// EndpointHost extracts the hostname component from the configured WARP endpoint.
func EndpointHost(cfg *config.Config) string {
	host, _, _ := strings.Cut(cfg.Warp.Endpoint, ":")
	return host
}

// EndpointPort extracts the port component from the configured WARP endpoint.
func EndpointPort(cfg *config.Config) string {
	_, port, _ := strings.Cut(cfg.Warp.Endpoint, ":")
	return port
}

// ProfilePath computes the absolute path to the WireGuard profile configuration.
func ProfilePath(cfg *config.Config) string {
	return filepath.Join(cfg.Paths.WgcfData, "wgcf-profile.conf")
}

func defaultFileClose(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}
	return nil
}

func defaultFileReadAll(r io.Reader) ([]byte, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return buf, nil
}

func defaultFileChmod(f *os.File, mode os.FileMode) error {
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod file: %w", err)
	}
	return nil
}

var (
	fileClose   = defaultFileClose
	fileReadAll = defaultFileReadAll
	fileChmod   = defaultFileChmod
)
