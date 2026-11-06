// Package config loads and validates all runtime configuration from environment
// variables and Docker secrets to enforce consistent parameters across packages.
package config

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/underhax/mihomo-warp-proxy/internal/contract"
	"github.com/underhax/mihomo-warp-proxy/internal/validate"
)

const defaultSecretsDir = "/run/secrets"

// Paths groups binary and data locations to enforce a deterministic filesystem layout.
type Paths struct {
	MihomoData       string
	MihomoConfigFile string
	WgcfData         string
	WgcfAccountFile  string
	WgcfProfileFile  string
	MihomoBin        string
	WgcfBin          string
}

// GeoURLs holds upstream download endpoints for geodata routing databases.
type GeoURLs struct {
	GeoIP   string
	GeoSite string
	MMDB    string
	ASN     string
}

// GeoConfig controls geodata download, authentication, and update behaviour.
type GeoConfig struct {
	URLs       GeoURLs
	AuthUser   string
	AuthPass   string
	Enabled    bool
	Redownload bool
	AutoUpdate bool
}

// AmneziaConfig holds AmneziaWG obfuscation parameters to mitigate DPI packet inspection.
type AmneziaConfig struct {
	I       [5]string
	JC      int
	JMin    int
	JMax    int
	Enabled bool
}

// WarpConfig controls Cloudflare WARP tunnel provisioning and WireGuard parameters.
type WarpConfig struct {
	DNS        []string
	PlusKey    string
	Endpoint   string
	Amnezia    AmneziaConfig
	Enabled    bool
	Regenerate bool
}

// Config represents fully validated runtime settings required to operate the proxy safely.
type Config struct {
	Paths         Paths
	LogLevelStr   string
	ProxyLogLevel string
	ProxyUser     string
	ProxyPass     string
	Version       string
	Geo           GeoConfig
	Warp          WarpConfig
	ProxyPort     uint16
	UseIP6        bool
}

func defaultGetPaths() Paths {
	return Paths{
		MihomoData:       "/app/mihomo",
		MihomoConfigFile: "/app/mihomo/config.yaml",
		WgcfData:         "/app/wgcf",
		WgcfAccountFile:  "/app/wgcf/wgcf-account.toml",
		WgcfProfileFile:  "/app/wgcf/wgcf-profile.conf",
		MihomoBin:        "/usr/local/bin/mihomo",
		WgcfBin:          "/usr/local/bin/wgcf",
	}
}

var getPaths = defaultGetPaths

type envResolver struct {
	secrets map[string]string
}

func (r *envResolver) get(key, def string) string {
	if val, ok := r.secrets[key]; ok {
		return val
	}
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func (r *envResolver) lookup(key string) (string, bool) {
	if val, ok := r.secrets[key]; ok {
		return val, true
	}
	return os.LookupEnv(key)
}

func (r *envResolver) parseBool(key string, def bool) (bool, error) {
	raw, ok := r.lookup(key)
	if !ok || raw == "" {
		return def, nil
	}

	normalized := strings.ToLower(strings.TrimSpace(raw))
	if isTrueBoolEnvValue(normalized) {
		return true, nil
	}
	if isFalseBoolEnvValue(normalized) {
		return false, nil
	}
	return false, fmt.Errorf("%s: invalid boolean value %q (accepted: true/false/1/0/yes/no/on/off)", key, raw)
}

func (r *envResolver) parseUint16(key, def string, minVal, maxVal uint16) (uint16, error) {
	raw := r.get(key, def)
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer value %q", key, raw)
	}
	if v > math.MaxUint16 || v < uint64(minVal) || v > uint64(maxVal) {
		return 0, fmt.Errorf("%s: value %d out of range [%d, %d]", key, v, minVal, maxVal)
	}
	return uint16(v), nil
}

func (r *envResolver) parseInt(key, def string, minVal, maxVal int) (int, error) {
	raw := r.get(key, def)
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer value %q", key, raw)
	}
	if v < minVal || v > maxVal {
		return 0, fmt.Errorf("%s: value %d out of range [%d, %d]", key, v, minVal, maxVal)
	}
	return v, nil
}

func defaultReadSecret(dir, filename string) (string, error) {
	const maxSecretSize = 4096

	path := filepath.Clean(filepath.Join(dir, filename))
	rel, err := filepath.Rel(dir, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("invalid secret path: %s", path)
	}

	info, err := osStat(path)
	if err != nil {
		return "", fmt.Errorf("stat secret %q: %w", filename, err)
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secret %q is not a regular file", filename)
	}

	if info.Size() > maxSecretSize {
		return "", fmt.Errorf("secret %q exceeds %d bytes", filename, maxSecretSize)
	}

	data, err := osReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret %q: %w", filename, err)
	}

	secret := strings.TrimSpace(string(data))
	if secret == "" {
		return "", fmt.Errorf("secret %q is empty", filename)
	}

	return secret, nil
}

func defaultLoadSecrets(dir string) (map[string]string, error) {
	entries, err := osReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string), nil
		}
		return nil, fmt.Errorf("read secrets directory: %w", err)
	}

	secrets := make(map[string]string, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		lowerName := strings.ToLower(name)
		if !strings.HasPrefix(lowerName, "mwp_") {
			continue
		}

		key := strings.ToUpper(strings.TrimPrefix(lowerName, "mwp_"))
		if key == "" {
			continue
		}

		val, err := readSecret(dir, name)
		if err != nil {
			return nil, err
		}
		secrets[key] = val
	}
	return secrets, nil
}

var (
	secretsDir  = defaultSecretsDir
	readSecret  = defaultReadSecret
	loadSecrets = defaultLoadSecrets
	osStat      = os.Stat
	osReadFile  = os.ReadFile
	osReadDir   = os.ReadDir
)

// Load parses environment variables and Docker secrets, validating boundaries to ensure safe service execution.
func Load(version string) (*Config, error) {
	secrets, err := loadSecrets(secretsDir)
	if err != nil {
		return nil, fmt.Errorf("load secrets: %w", err)
	}

	r := &envResolver{secrets: secrets}

	cfg := &Config{
		Paths:   getPaths(),
		Version: version,
	}

	if valErr := validatePaths(&cfg.Paths); valErr != nil {
		return nil, valErr
	}

	cfg.LogLevelStr = r.get(contract.EnvScriptLogLevel, contract.LogLevelWarn)
	if valErr := validateScriptLogLevel(cfg.LogLevelStr); valErr != nil {
		return nil, valErr
	}
	cfg.LogLevelStr = strings.ToUpper(strings.TrimSpace(cfg.LogLevelStr))

	cfg.ProxyLogLevel = r.get(contract.EnvProxyLogLevel, "info")
	if valErr := validateProxyLogLevel(cfg.ProxyLogLevel); valErr != nil {
		return nil, valErr
	}
	cfg.ProxyLogLevel = strings.ToLower(strings.TrimSpace(cfg.ProxyLogLevel))

	port, err := r.parseUint16(contract.EnvProxyPort, "7890", 1, 65535)
	if err != nil {
		return nil, err
	}
	cfg.ProxyPort = port

	cfg.ProxyUser = r.get(contract.EnvProxyUser, "")
	cfg.ProxyPass = r.get(contract.EnvProxyPass, "")
	if valErr := validateCredentialPair(cfg.ProxyUser, cfg.ProxyPass); valErr != nil {
		return nil, valErr
	}

	useIP6, err := r.parseBool(contract.EnvUseIP6, true)
	if err != nil {
		return nil, err
	}
	cfg.UseIP6 = useIP6

	geo, err := loadGeoConfig(r)
	if err != nil {
		return nil, err
	}
	cfg.Geo = geo

	warp, err := loadWarpConfig(r)
	if err != nil {
		return nil, err
	}
	cfg.Warp = warp

	return cfg, nil
}

func loadGeoConfig(r *envResolver) (GeoConfig, error) {
	var (
		g   GeoConfig
		err error
	)

	g.Enabled, err = r.parseBool(contract.EnvGeo, false)
	if err != nil {
		return g, err
	}

	g.Redownload, err = r.parseBool(contract.EnvGeoRedownload, false)
	if err != nil {
		return g, err
	}

	g.AutoUpdate, err = r.parseBool(contract.EnvGeoAutoUpdate, false)
	if err != nil {
		return g, err
	}

	g.URLs = GeoURLs{
		GeoIP:   r.get(contract.EnvGeoURLGeoIP, "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"),
		GeoSite: r.get(contract.EnvGeoURLGeoSite, "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"),
		MMDB:    r.get(contract.EnvGeoURLMMDB, "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"),
		ASN:     r.get(contract.EnvGeoURLASN, "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"),
	}

	for name, u := range map[string]string{
		contract.EnvGeoURLGeoIP:   g.URLs.GeoIP,
		contract.EnvGeoURLGeoSite: g.URLs.GeoSite,
		contract.EnvGeoURLMMDB:    g.URLs.MMDB,
		contract.EnvGeoURLASN:     g.URLs.ASN,
	} {
		if valErr := validateGeoURL(name, u); valErr != nil {
			return g, valErr
		}
	}

	g.AuthUser = r.get(contract.EnvGeoAuthUser, "")
	g.AuthPass = r.get(contract.EnvGeoAuth, "")

	if (g.AuthUser == "") != (g.AuthPass == "") {
		return g, errors.New(contract.EnvGeoAuthUser + " and " + contract.EnvGeoAuth + " must both be set or both be empty")
	}

	if g.AuthUser != "" {
		if err := validateGeoCredential(contract.EnvGeoAuthUser, g.AuthUser); err != nil {
			return g, err
		}
		if err := validateGeoCredential(contract.EnvGeoAuth, g.AuthPass); err != nil {
			return g, err
		}
	}

	return g, nil
}

func loadWarpConfig(r *envResolver) (WarpConfig, error) {
	var (
		w   WarpConfig
		err error
	)

	w.Enabled, err = r.parseBool(contract.EnvUseWarpConfig, true)
	if err != nil {
		return w, err
	}

	w.Regenerate, err = r.parseBool(contract.EnvWarpRegenerate, false)
	if err != nil {
		return w, err
	}

	w.PlusKey = r.get(contract.EnvWarpPlusKey, "")
	if w.PlusKey != "" {
		if valErr := validateWarpPlusKey(w.PlusKey); valErr != nil {
			return w, valErr
		}
	}

	w.Endpoint = r.get(contract.EnvWarpEndpoint, "engage.cloudflareclient.com:500")
	if valErr := validateWarpEndpoint(w.Endpoint); valErr != nil {
		return w, valErr
	}

	dns, err := parseDNSList(r.get(contract.EnvWarpDNS, "1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"))
	if err != nil {
		return w, err
	}
	w.DNS = dns

	amnezia, err := loadAmneziaConfig(r)
	if err != nil {
		return w, err
	}
	w.Amnezia = amnezia

	return w, nil
}

func loadAmneziaConfig(r *envResolver) (AmneziaConfig, error) {
	var (
		a   AmneziaConfig
		err error
	)

	a.Enabled, err = r.parseBool(contract.EnvWarpAmnezia, false)
	if err != nil {
		return a, err
	}

	if !a.Enabled {
		return a, nil
	}

	a.JC, err = r.parseInt(contract.EnvWarpAmneziaJC, "0", 0, 128)
	if err != nil {
		return a, err
	}

	a.JMin, err = r.parseInt(contract.EnvWarpAmneziaJMin, "0", 0, 1280)
	if err != nil {
		return a, err
	}

	a.JMax, err = r.parseInt(contract.EnvWarpAmneziaJMax, "0", 0, 1280)
	if err != nil {
		return a, err
	}

	if a.JMin >= a.JMax {
		return a, fmt.Errorf("%s (%d) must be less than %s (%d)", contract.EnvWarpAmneziaJMin, a.JMin, contract.EnvWarpAmneziaJMax, a.JMax)
	}

	for i := range a.I {
		name := fmt.Sprintf("%s%d", contract.EnvWarpAmneziaIPrefix, i+1)
		a.I[i] = r.get(name, "")
	}

	for i, val := range a.I {
		name := fmt.Sprintf("%s%d", contract.EnvWarpAmneziaIPrefix, i+1)
		if err := validate.AmneziaIParam(name, val); err != nil {
			return a, fmt.Errorf("%s: %w", name, err)
		}
	}

	return a, nil
}

func isTrueBoolEnvValue(v string) bool {
	return v == "true" || v == "1" || v == "yes" || v == "on"
}

func isFalseBoolEnvValue(v string) bool {
	return v == "false" || v == "0" || v == "no" || v == "off"
}

func validateScriptLogLevel(v string) error {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case contract.LogLevelDebug, contract.LogLevelInfo, contract.LogLevelWarn, contract.LogLevelError:
		return nil
	default:
		return fmt.Errorf("%s: invalid value %q (accepted: %s, %s, %s, %s)",
			contract.EnvScriptLogLevel,
			v,
			contract.LogLevelDebug,
			contract.LogLevelInfo,
			contract.LogLevelWarn,
			contract.LogLevelError,
		)
	}
}

func validateProxyLogLevel(v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "silent", "error", "warning", "info", "debug":
		return nil
	default:
		return fmt.Errorf("%s: invalid value %q (accepted: silent, error, warning, info, debug)", contract.EnvProxyLogLevel, v)
	}
}

func validateCredentialPair(user, pass string) error {
	userSet := user != ""
	passSet := pass != ""

	if !userSet && !passSet {
		return nil
	}
	if userSet && !passSet {
		return errors.New(contract.EnvProxyPass + " must be set when " + contract.EnvProxyUser + " is provided")
	}
	if !userSet && passSet {
		return errors.New(contract.EnvProxyUser + " must be set when " + contract.EnvProxyPass + " is provided")
	}

	if err := validateMinLength(contract.EnvProxyUser, user, 8); err != nil {
		return err
	}
	if err := validateMinLength(contract.EnvProxyPass, pass, 32); err != nil {
		return err
	}
	if err := validateCredential(contract.EnvProxyUser, user, 64); err != nil {
		return err
	}
	if err := validateCredential(contract.EnvProxyPass, pass, 128); err != nil {
		return err
	}
	return validatePasswordComplexity(pass)
}

func validateMinLength(name, value string, minVal int) error {
	if len(value) < minVal {
		return fmt.Errorf("%s: minimum length is %d characters, got %d", name, minVal, len(value))
	}
	return nil
}

func validateCredential(name, value string, maxLen int) error {
	if len(value) > maxLen {
		return fmt.Errorf("%s: value too long (max %d characters, got %d)", name, maxLen, len(value))
	}
	for i, r := range value {
		if err := checkCredentialRune(name, i, r); err != nil {
			return err
		}
	}
	return nil
}

func checkCredentialRune(name string, i int, r rune) error {
	switch {
	case r == ':':
		return fmt.Errorf("%s: colon not allowed (position %d)", name, i)
	case strings.ContainsRune("$`\"'\\!&;|<> ", r):
		return fmt.Errorf("%s: shell metacharacter or space %q not allowed (position %d)", name, r, i)
	case r == 0x00:
		return fmt.Errorf("%s: null byte not allowed (position %d)", name, i)
	case r < 0x20 || r == 0x7f:
		return fmt.Errorf("%s: control character not allowed (position %d, value 0x%02x)", name, i, r)
	default:
		return nil
	}
}

const passwordRequirements = contract.EnvProxyPass + " requirements: " +
	"min 32 characters; " +
	"at least one uppercase letter (A-Z); " +
	"at least one lowercase letter (a-z); " +
	"at least one digit (0-9); " +
	"no run of more than 3 identical consecutive characters; " +
	"at least 12 distinct characters; " +
	`no spaces or shell metacharacters ($, ` + "`" + `, ", ', \, !, &, ;, |, <, >). ` +
	"Generate with: pwgen -s 128 1"

func hasConsecutiveRun(runes []rune) bool {
	for i := 3; i < len(runes); i++ {
		if runes[i] == runes[i-1] && runes[i-1] == runes[i-2] && runes[i-2] == runes[i-3] {
			return true
		}
	}
	return false
}

func validatePasswordComplexity(pass string) error {
	runes := []rune(pass)
	if hasConsecutiveRun(runes) {
		return errors.New(passwordRequirements)
	}

	var hasUpper, hasLower, hasDigit bool
	unique := make(map[rune]struct{}, len(runes))
	for _, r := range runes {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
		unique[r] = struct{}{}
	}

	if !hasUpper || !hasLower || !hasDigit || len(unique) < 12 {
		return errors.New(passwordRequirements)
	}
	return nil
}

func validateWarpEndpoint(endpoint string) error {
	host, port, found := strings.CutLast(endpoint, ":")
	if !found {
		return fmt.Errorf("%s: missing port in %q", contract.EnvWarpEndpoint, endpoint)
	}

	const warpEndpointRequirements = contract.EnvWarpEndpoint + " requirements: host must be engage.cloudflareclient.com; port must be one of: 2408, 500, 1701, 4500"

	validPort := port == "2408" || port == "500" || port == "1701" || port == "4500"
	validHost := host == "engage.cloudflareclient.com"

	if !validHost || !validPort {
		return fmt.Errorf("%s — got host %q port %q", warpEndpointRequirements, host, port)
	}
	return nil
}

func parseDNSList(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New(contract.EnvWarpDNS + ": must not be empty")
	}

	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))

	for _, p := range parts {
		entry := strings.TrimSpace(p)
		if entry == "" {
			continue
		}
		if !isValidDNSEntry(entry) {
			return nil, fmt.Errorf("%s: invalid entry %q (accepted: IPv4, IPv6, tls://, https://, quic://)", contract.EnvWarpDNS, entry)
		}
		result = append(result, entry)
	}

	if len(result) == 0 {
		return nil, errors.New(contract.EnvWarpDNS + ": no valid entries found")
	}
	if len(result) > 8 {
		return nil, fmt.Errorf("%s: too many entries (max 8, got %d)", contract.EnvWarpDNS, len(result))
	}

	return result, nil
}

func isValidDNSEntry(s string) bool {
	switch {
	case strings.HasPrefix(s, "tls://"):
		return true
	case strings.HasPrefix(s, "https://"):
		return true
	case strings.HasPrefix(s, "quic://"):
		return true
	case strings.Contains(s, ":"):
		for _, r := range s {
			if !isHexOrColon(r) {
				return false
			}
		}
		return true
	default:
		return isIPv4(s)
	}
}

func isHexOrColon(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') ||
		(r >= 'A' && r <= 'F') || r == ':'
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

var warpPlusKeyRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{8}$`)

func validateWarpPlusKey(key string) error {
	if !warpPlusKeyRe.MatchString(key) {
		return fmt.Errorf("%s: invalid format %q (expected: xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx where x is a hex digit)", contract.EnvWarpPlusKey, key)
	}
	return nil
}

func validateGeoURL(name, rawURL string) error {
	if !strings.HasPrefix(strings.ToLower(rawURL), "https://") {
		return fmt.Errorf("%s: only HTTPS URLs are allowed, got %q", name, rawURL)
	}
	return nil
}

func validateGeoCredential(name, value string) error {
	if len(value) > 256 {
		return fmt.Errorf("%s: value too long (max 256 characters, got %d)", name, len(value))
	}
	for i, r := range value {
		switch {
		case r == ':' || r == '@':
			return fmt.Errorf("%s: character %q not allowed (position %d)", name, r, i)
		case r == 0x00:
			return fmt.Errorf("%s: null byte not allowed (position %d)", name, i)
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("%s: control character not allowed (position %d)", name, i)
		case r == ' ':
			return fmt.Errorf("%s: whitespace not allowed (position %d)", name, i)
		}
	}
	return nil
}

// FilterEnviron scrubs sensitive authentication credentials from environment variables
// to prevent credential leakage to child processes or diagnostic logs.
func FilterEnviron(environ []string) []string {
	clean := make([]string, 0, len(environ))
	for _, e := range environ {
		if key, _, ok := strings.Cut(e, "="); ok {
			switch key {
			case contract.EnvProxyPass, contract.EnvGeoAuthUser, contract.EnvGeoAuth, contract.EnvWarpPlusKey:
				continue
			}
		}
		clean = append(clean, e)
	}
	return clean
}

func validatePaths(p *Paths) error {
	paths := []struct {
		name string
		path string
	}{
		{"MihomoData", p.MihomoData},
		{"MihomoConfigFile", p.MihomoConfigFile},
		{"WgcfData", p.WgcfData},
		{"WgcfAccountFile", p.WgcfAccountFile},
		{"WgcfProfileFile", p.WgcfProfileFile},
		{"MihomoBin", p.MihomoBin},
		{"WgcfBin", p.WgcfBin},
	}
	for _, target := range paths {
		if err := validate.Path(target.path, target.name); err != nil {
			return fmt.Errorf("path validation: %w", err)
		}
	}
	return nil
}
