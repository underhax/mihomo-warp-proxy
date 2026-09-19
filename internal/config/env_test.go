package config

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/underhax/mihomo-warp-proxy/internal/contract"
)

func setEnv(t *testing.T, pairs ...string) {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatal("setEnv requires an even number of arguments (key, value pairs)")
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		t.Setenv(pairs[i], pairs[i+1])
	}
}

func testCreds() (user, pass string) {
	return "aaaaaaA1", "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
}

func TestParseBoolEnv(t *testing.T) {
	cases := []struct {
		key     string
		val     string
		def     bool
		want    bool
		wantErr bool
	}{
		{"K", "TRUE", false, true, false},
		{"K", "True", false, true, false},
		{"K", "TrUe", false, true, false},
		{"K", "1", false, true, false},
		{"K", "yes", false, true, false},
		{"K", "on", false, true, false},
		{"K", "FALSE", true, false, false},
		{"K", "0", true, false, false},
		{"K", "no", true, false, false},
		{"K", "off", true, false, false},
		{"K", "", true, true, false},
		{"K", "maybe", false, false, true},
		{"K", "yes please", false, false, true},
	}

	for _, tc := range cases {
		defaultLabel := strconv.FormatBool(tc.def)
		t.Run(tc.val+"_default_"+defaultLabel, func(t *testing.T) {
			t.Setenv(tc.key, tc.val)
			got, err := parseBoolEnv(tc.key, tc.def)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for value %q, got nil", tc.val)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("parseBoolEnv(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

func TestParseUint32Env(t *testing.T) {
	cases := []struct {
		val     string
		min     uint32
		max     uint32
		want    uint32
		wantErr bool
	}{
		{"911", 0, 65535, 911, false},
		{"0", 0, 65535, 0, false},
		{"65535", 0, 65535, 65535, false},
		{"65536", 0, 65535, 0, true},
		{"", 0, 65535, 0, false},
		{"-1", 0, 65535, 0, true},
		{"abc", 0, 65535, 0, true},
		{"7890", 1, 65535, 7890, false},
		{"0", 1, 65535, 0, true},
	}

	for _, tc := range cases {
		t.Run("val_"+tc.val, func(t *testing.T) {
			t.Setenv("TEST_UINT", tc.val)
			got, err := parseUint32Env("TEST_UINT", "0", tc.min, tc.max)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for value %q, got nil", tc.val)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestValidatePasswordComplexity(t *testing.T) {
	cases := []struct {
		name    string
		pass    string
		wantErr bool
	}{
		{"pwgen-style 32", "zYxWvUtSrQpOnMlKjIhGfEdCbA987654", false},
		{"pwgen-style 128", strings.Repeat("aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV", 4), false},
		{"with allowed special chars", "aB3dEfGhIjKlMn!opQrStUvWxYz01234", false},
		{"all lowercase + digit", strings.Repeat("abcdefghij", 3) + "12", true},
		{"all uppercase + digit", strings.Repeat("ABCDEFGHIJ", 3) + "12", true},
		{"upper + lower no digit", strings.Repeat("abcdefghij", 3) + "AB", true},
		{"only 3 distinct chars", strings.Repeat("aA1", 11), true},
		{"only 11 distinct chars", "aAbBcCdDeEf" + strings.Repeat("a", 21), true},
		{"12 distinct chars ok", "aAbBcCdDeEfFgG1HiIjJkKlLmMnNoP2r", false},
		{"run of 4 lowercase", "aBcDeFgHiJkLaaaa" + strings.Repeat("mN3", 6), true},
		{"run of 4 uppercase", "aBcDeFgHiJkLAAAA" + strings.Repeat("mn3", 6), true},
		{"run of 4 digits", "aBcDeFgHiJkL1111" + strings.Repeat("mn3", 6), true},
		{"run of 3 allowed", "aBcDeFgHiJkLaaa" + strings.Repeat("mN3", 6), false},
		{"32 identical lowercase", strings.Repeat("a", 32), true},
		{"32 identical uppercase", strings.Repeat("A", 32), true},
		{"32 identical digits", strings.Repeat("1", 32), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePasswordComplexity(tc.pass)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil (pass=%q)", tc.pass)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateCredentialPair(t *testing.T) {
	validUser, validPass := testCreds()

	cases := []struct {
		name    string
		user    string
		pass    string
		wantErr bool
	}{
		{"both empty — open proxy rejected", "", "", true},
		{"user only", validUser, "", true},
		{"pass only", "", validPass, true},
		{"valid pair", validUser, validPass, false},
		{"max length user", strings.Repeat("a", 63) + "A", validPass, false},
		{"max length pass", validUser, strings.Repeat("aB3cD4eF5gH6", 10) + "iJ7kL8mN", false},
		{"user too short (7)", "aaaAA12", validPass, true},
		{"user min length (8)", "aaaaaaA1", validPass, false},
		{"user too long (65)", strings.Repeat("a", 65), validPass, true},
		{"pass too short (31)", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234", true},
		{"pass min length (32)", validUser, "QwErTyUiOpAsDfGhJkLzXcVbNm123456", false},
		{"pass too long (129)", validUser, strings.Repeat("aBcDeFgHiJkL", 10) + "mNoPq", true},
		{"colon in user", validUser + ":", validPass, true},
		{"colon in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ01234:", true},
		{"control char in user", "aaaaaaA\x011", validPass, true},
		{"null byte in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123\x004", true},
		{"space in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123 4", true},
		{"dollar in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123$4", true},
		{"backtick in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123`4", true},
		{"doublequote in pass", validUser, `aBcDeFgHiJkLmNoPqRsTuVwXyZ0123"4`, true},
		{"singlequote in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123'4", true},
		{"backslash in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123\\4", true},
		{"ampersand in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123&4", true},
		{"semicolon in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123;4", true},
		{"pipe in pass", validUser, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123|4", true},
		{"pass all lowercase", validUser, strings.Repeat("a", 32), true},
		{"pass all uppercase", validUser, strings.Repeat("A", 32), true},
		{"pass only digits", validUser, strings.Repeat("1", 32), true},
		{"pass upper+lower no digit", validUser, strings.Repeat("a", 30) + "AB", true},
		{"pass upper+digit no lower", validUser, strings.Repeat("1", 30) + "AA", true},
		{"pass lower+digit no upper", validUser, strings.Repeat("a", 30) + "11", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCredentialPair(tc.user, tc.pass)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateWarpEndpoint(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
	}{
		{"engage.cloudflareclient.com:2408", false},
		{"engage.cloudflareclient.com:500", false},
		{"engage.cloudflareclient.com:1701", false},
		{"engage.cloudflareclient.com:4500", false},
		{"engage.cloudflareclient.com:9999", true},
		{"evil.example.com:2408", true},
		{"engage.cloudflareclient.com", true},
		{"", true},
		{":2408", true},
		{"engage.cloudflareclient.com:0", true},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			err := validateWarpEndpoint(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.input, err)
			}
		})
	}
}

func TestParseDNSList(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{"ipv4 only", "1.1.1.1,1.0.0.1", 2, false},
		{"mixed ipv4 ipv6", "1.1.1.1,2606:4700:4700::1111", 2, false},
		{"dot resolver", "tls://1.1.1.1", 1, false},
		{"doh resolver", "https://dns.example.com/dns-query", 1, false},
		{"doq resolver", "quic://dns.example.com", 1, false},
		{"spaces trimmed", "1.1.1.1, 1.0.0.1", 2, false},
		{"max entries (8)", "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6,7.7.7.7,8.8.8.8", 8, false},
		{"too many entries (9)", "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6,7.7.7.7,8.8.8.8,9.9.9.9", 0, true},
		{"empty string", "", 0, true},
		{"invalid entry", "1.1.1.1,notadns", 0, true},
		{"invalid ipv4 octet", "256.0.0.1", 0, true},
		{"single valid", "8.8.8.8", 1, false},
		{"trailing comma", "1.1.1.1,", 1, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDNSList(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if len(got) != tc.wantLen {
				t.Errorf("got %d entries, want %d", len(got), tc.wantLen)
			}
		})
	}
}

func TestIsIPv4(t *testing.T) {
	valid := []string{"1.1.1.1", "0.0.0.0", "255.255.255.255", "192.168.1.100"}
	invalid := []string{"", "256.0.0.1", "1.1.1", "1.1.1.1.1", "a.b.c.d", "1.1.1.-1"}

	for _, ip := range valid {
		if !isIPv4(ip) {
			t.Errorf("isIPv4(%q) = false, want true", ip)
		}
	}
	for _, ip := range invalid {
		if isIPv4(ip) {
			t.Errorf("isIPv4(%q) = true, want false", ip)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	user, pass := testCreds()
	for _, k := range []string{
		contract.EnvTZ, contract.EnvScriptLogLevel, contract.EnvProxyLogLevel,
		contract.EnvProxyUID, contract.EnvProxyGID, contract.EnvProxyPort,
		contract.EnvMultiUserMode, contract.EnvUseIP6,
		contract.EnvGeo, contract.EnvGeoRedownload,
		contract.EnvGeoURLGeoIP, contract.EnvGeoURLGeoSite, contract.EnvGeoURLMMDB, contract.EnvGeoURLASN,
		contract.EnvGeoAuthUser, contract.EnvGeoAuthSecret,
		contract.EnvUseWarpConfig, contract.EnvWarpRegenerate, contract.EnvWarpPlusKey,
		contract.EnvWarpEndpoint, contract.EnvWarpDNS, contract.EnvWarpAmnezia,
	} {
		t.Setenv(k, "")
	}
	setEnv(t, contract.EnvProxyUser, user, contract.EnvProxyPass, pass)

	cfg, err := Load("1.0.0")
	if err != nil {
		t.Fatalf("Load() with defaults failed: %v", err)
	}

	if cfg.ProxyUID != 911 {
		t.Errorf("ProxyUID: got %d, want 911", cfg.ProxyUID)
	}
	if cfg.ProxyGID != 911 {
		t.Errorf("ProxyGID: got %d, want 911", cfg.ProxyGID)
	}
	if cfg.ProxyPort != 7890 {
		t.Errorf("ProxyPort: got %d, want 7890", cfg.ProxyPort)
	}
	if !cfg.MultiUserMode {
		t.Error("MultiUserMode: got false, want true")
	}
	if !cfg.UseIP6 {
		t.Error("UseIP6: got false, want true")
	}
	if cfg.Geo.Enabled {
		t.Error("Geo.Enabled: got true, want false")
	}
	if cfg.Geo.Redownload {
		t.Error("Geo.Redownload: got true, want false")
	}
	if cfg.Geo.AutoUpdate {
		t.Error("Geo.AutoUpdate: got true, want false")
	}
	if !cfg.Warp.Enabled {
		t.Error("Warp.Enabled: got false, want true")
	}
	if cfg.Warp.Amnezia.Enabled {
		t.Error("Warp.Amnezia.Enabled: got true, want false")
	}
	if cfg.Version != "1.0.0" {
		t.Errorf("Version: got %q, want %q", cfg.Version, "1.0.0")
	}
}

func TestLoadEmptyCredentialsRejected(t *testing.T) {
	setEnv(t, contract.EnvProxyUser, "", contract.EnvProxyPass, "")
	_, err := Load("test")
	if err == nil {
		t.Error("expected error for empty credentials, got nil")
	}
}

func TestLoadAmneziaValidation(t *testing.T) {
	user, pass := testCreds()
	base := []string{
		contract.EnvProxyUser, user, contract.EnvProxyPass, pass,
		contract.EnvWarpAmnezia, "TRUE",
		contract.EnvWarpAmneziaJC, "5",
	}

	t.Run("jmin >= jmax rejected", func(t *testing.T) {
		setEnv(t, append(base, contract.EnvWarpAmneziaJMin, "15", contract.EnvWarpAmneziaJMax, "15")...)
		_, err := Load("test")
		if err == nil {
			t.Error("expected error for jmin == jmax, got nil")
		}
	})

	t.Run("jmin > jmax rejected", func(t *testing.T) {
		setEnv(t, append(base, contract.EnvWarpAmneziaJMin, "20", contract.EnvWarpAmneziaJMax, "10")...)
		_, err := Load("test")
		if err == nil {
			t.Error("expected error for jmin > jmax, got nil")
		}
	})

	t.Run("valid amnezia params accepted", func(t *testing.T) {
		setEnv(t, append(base, contract.EnvWarpAmneziaJMin, "7", contract.EnvWarpAmneziaJMax, "15")...)
		cfg, err := Load("test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Warp.Amnezia.JC != 5 {
			t.Errorf("JC: got %d, want 5", cfg.Warp.Amnezia.JC)
		}
		if cfg.Warp.Amnezia.JMin != 7 {
			t.Errorf("JMin: got %d, want 7", cfg.Warp.Amnezia.JMin)
		}
		if cfg.Warp.Amnezia.JMax != 15 {
			t.Errorf("JMax: got %d, want 15", cfg.Warp.Amnezia.JMax)
		}
	})
}

func TestLoadGeoAuthPartialCredentials(t *testing.T) {
	user, pass := testCreds()
	setEnv(t,
		contract.EnvProxyUser, user, contract.EnvProxyPass, pass,
		contract.EnvGeoAuthUser, "user",
		contract.EnvGeoAuthSecret, "",
	)
	_, err := Load("test")
	if err == nil {
		t.Error("expected error for partial GEO auth credentials, got nil")
	}
}

func TestLoadInvalidProxyLogLevel(t *testing.T) {
	user, pass := testCreds()
	setEnv(t,
		contract.EnvProxyUser, user, contract.EnvProxyPass, pass,
		contract.EnvProxyLogLevel, "verbose",
	)
	_, err := Load("test")
	if err == nil {
		t.Error("expected error for invalid PROXY_LOG_LEVEL, got nil")
	}
}

func TestLoadProxyUIDGIDValidation(t *testing.T) {
	user, pass := testCreds()
	base := []string{contract.EnvProxyUser, user, contract.EnvProxyPass, pass}

	cases := []struct {
		name    string
		uid     string
		gid     string
		wantErr bool
	}{
		{"default (911:911)", "", "", false},
		{"min allowed (1:1)", "1", "1", false},
		{"max allowed (65535:65535)", "65535", "65535", false},
		{"zero uid rejected", "0", "911", true},
		{"zero gid rejected", "911", "0", true},
		{"above max uid", "65536", "911", true},
		{"above max gid", "911", "65536", true},
		{"negative uid", "-1", "911", true},
		{"non-numeric uid", "abc", "911", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := make([]string, len(base), len(base)+4)
			copy(args, base)
			args = append(args, contract.EnvProxyUID, tc.uid, contract.EnvProxyGID, tc.gid)
			setEnv(t, args...)
			_, err := Load("test")
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestFilterEnviron(t *testing.T) {
	input := []string{
		"PATH=/usr/local/sbin:/usr/local/bin",
		contract.EnvProxyUser + "=admin",
		contract.EnvProxyPass + "=supersecret32chars!!!",
		contract.EnvGeoAuthUser + "=alice",
		contract.EnvGeoAuthSecret + "=bob",
		contract.EnvWarpPlusKey + "=1234-5678-90ab",
		contract.EnvTZ + "=UTC",
		"INVALID_ENV_VAR",
	}
	want := []string{
		"PATH=/usr/local/sbin:/usr/local/bin",
		contract.EnvProxyUser + "=admin",
		contract.EnvTZ + "=UTC",
		"INVALID_ENV_VAR",
	}

	got := FilterEnviron(input)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterEnviron() = %v, want %v", got, want)
	}
}

func TestValidateWarpPlusKey(t *testing.T) {
	valid := []string{
		"12345678-12345678-12345678-12345678",
		"abcdef01-23456789-abcdef01-23456789",
		"ABCDEF01-23456789-ABCDEF01-23456789",
	}
	invalid := []string{
		"",
		"1234-5678-90ab",
		"1234567g-12345678-12345678-12345678",
		"12345678-12345678-12345678-123456789",
		"12345678_12345678_12345678_12345678",
	}

	for _, key := range valid {
		if err := validateWarpPlusKey(key); err != nil {
			t.Errorf("validateWarpPlusKey(%q) unexpected error: %v", key, err)
		}
	}
	for _, key := range invalid {
		if err := validateWarpPlusKey(key); err == nil {
			t.Errorf("validateWarpPlusKey(%q) expected error, got nil", key)
		}
	}
}

func TestValidateGeoCredential(t *testing.T) {
	if err := validateGeoCredential("user", "validuser123"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	tooLong := strings.Repeat("a", 257)
	if err := validateGeoCredential("user", tooLong); err == nil {
		t.Error("expected error for credential > 256 chars, got nil")
	}

	withColon := "user:name"
	if err := validateGeoCredential("user", withColon); err == nil {
		t.Error("expected error for credential with colon, got nil")
	}

	withAt := "user@name"
	if err := validateGeoCredential("user", withAt); err == nil {
		t.Error("expected error for credential with @, got nil")
	}

	withControl := "user\x01name"
	if err := validateGeoCredential("user", withControl); err == nil {
		t.Error("expected error for credential with control char, got nil")
	}

	withNull := "user\x00name"
	if err := validateGeoCredential("user", withNull); err == nil {
		t.Error("expected error for credential with null byte, got nil")
	}

	withSpace := "user name"
	if err := validateGeoCredential("user", withSpace); err == nil {
		t.Error("expected error for credential with space, got nil")
	}
}

func TestValidateTZ(t *testing.T) {
	if err := validateTZ("UTC"); err != nil {
		t.Errorf("validateTZ(UTC) error: %v", err)
	}
	if err := validateTZ("Nonexistent/Invalid_Timezone"); err == nil {
		t.Error("expected error for invalid timezone, got nil")
	}
}

func TestParseUint16AndIntEnvErrors(t *testing.T) {
	t.Setenv("TEST_UINT16", "notanumber")
	if _, err := parseUint16Env("TEST_UINT16", "10", 1, 100); err == nil {
		t.Error("expected error for invalid uint16, got nil")
	}

	t.Setenv("TEST_INT", "notanumber")
	if _, err := parseIntEnv("TEST_INT", "10", 1, 100); err == nil {
		t.Error("expected error for invalid int, got nil")
	}

	if err := validateScriptLogLevel("INVALID_LEVEL"); err == nil {
		t.Error("expected error for invalid script log level, got nil")
	}
}

func TestLoadAmneziaConfigInvalid(t *testing.T) {
	user, pass := testCreds()
	base := []string{contract.EnvProxyUser, user, contract.EnvProxyPass, pass}
	args := make([]string, len(base), len(base)+8)
	copy(args, base)
	args = append(args,
		contract.EnvUseWarpConfig, "true",
		contract.EnvWarpAmnezia, "true",
		contract.EnvWarpAmneziaJMin, "500",
		contract.EnvWarpAmneziaJMax, "100",
	)
	setEnv(t, args...)
	if _, err := Load("test"); err == nil {
		t.Error("expected error when JMin >= JMax, got nil")
	}

	argsMax := make([]string, len(base), len(base)+8)
	copy(argsMax, base)
	argsMax = append(argsMax,
		contract.EnvUseWarpConfig, "true",
		contract.EnvWarpAmnezia, "true",
		contract.EnvWarpAmneziaJMin, "10",
		contract.EnvWarpAmneziaJMax, "2000",
	)
	setEnv(t, argsMax...)
	if _, err := Load("test"); err == nil {
		t.Error("expected error when JMax > 1280, got nil")
	}
}

func TestLoadConfigErrors(t *testing.T) {
	user, pass := testCreds()
	base := []string{contract.EnvProxyUser, user, contract.EnvProxyPass, pass}

	t.Run("invalid geo redownload", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvGeoRedownload, "not-bool")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid GEO_REDOWNLOAD, got nil")
		}
	})

	t.Run("invalid geo auto update", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvGeoAutoUpdate, "not-bool")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid GEO_AUTO_UPDATE, got nil")
		}
	})

	t.Run("invalid warp regenerate", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvWarpRegenerate, "not-bool")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid WARP_REGENERATE, got nil")
		}
	})

	t.Run("invalid warp endpoint", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvWarpEndpoint, "invalid:endpoint:extra")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid WARP_ENDPOINT, got nil")
		}
	})

	t.Run("invalid warp amnezia bool", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvWarpAmnezia, "not-bool")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid WARP_AMNEZIA, got nil")
		}
	})

	t.Run("invalid warp amnezia jc", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvWarpAmnezia, "true", contract.EnvWarpAmneziaJC, "invalid")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid WARP_AMNEZIA_JC, got nil")
		}
	})

	t.Run("uint16 out of range", func(t *testing.T) {
		t.Setenv("TEST_UINT16_RANGE", "200")
		if _, err := parseUint16Env("TEST_UINT16_RANGE", "10", 1, 100); err == nil {
			t.Error("expected error for uint16 out of range, got nil")
		}
	})

	t.Run("int out of range", func(t *testing.T) {
		t.Setenv("TEST_INT_RANGE", "200")
		if _, err := parseIntEnv("TEST_INT_RANGE", "10", 1, 100); err == nil {
			t.Error("expected error for int out of range, got nil")
		}
	})
}

func slicesClone(s []string) []string {
	res := make([]string, len(s))
	copy(res, s)
	return res
}

func TestValidateGeoURLDirect(t *testing.T) {
	if err := validateGeoURL("TEST", "http://example.com"); err == nil {
		t.Error("expected error for http URL, got nil")
	}
	if err := validateGeoURL("TEST", "https://example.com"); err != nil {
		t.Errorf("unexpected error for https URL: %v", err)
	}
}

func TestValidateGeoCredentialEdgeCases(t *testing.T) {
	if err := validateGeoCredential("TEST", strings.Repeat("a", 257)); err == nil {
		t.Error("expected error for too long credential, got nil")
	}
	if err := validateGeoCredential("TEST", "user:pass"); err == nil {
		t.Error("expected error for colon in credential, got nil")
	}
	if err := validateGeoCredential("TEST", "user@pass"); err == nil {
		t.Error("expected error for at sign in credential, got nil")
	}
	if err := validateGeoCredential("TEST", "user\x01pass"); err == nil {
		t.Error("expected error for control char in credential, got nil")
	}
	if err := validateGeoCredential("TEST", "user\x00pass"); err == nil {
		t.Error("expected error for null byte in credential, got nil")
	}
	if err := validateGeoCredential("TEST", "user pass"); err == nil {
		t.Error("expected error for space in credential, got nil")
	}
}

func TestIsIPv4AndDNSValidation(t *testing.T) {
	if isIPv4("1.2.3") {
		t.Error("expected false for 3 parts")
	}
	if isIPv4("1..3.4") {
		t.Error("expected false for empty part")
	}
	if isIPv4("1.2.3.4444") {
		t.Error("expected false for part length > 3")
	}
	if isIPv4("1.2.3.abc") {
		t.Error("expected false for non-numeric part")
	}
	if isIPv4("1.2.3.256") {
		t.Error("expected false for part > 255")
	}
	if !isValidDNSEntry("quic://dns.example.com") {
		t.Error("expected true for quic:// entry")
	}
	if isValidDNSEntry("2001:xyz::1") {
		t.Error("expected false for invalid IPv6 hex chars")
	}
	if _, err := parseDNSList(", , ,"); err == nil {
		t.Error("expected error for DNS list with no valid entries, got nil")
	}
	tooManyDNS := "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9,149.112.112.112,208.67.222.222,208.67.220.220,1.1.1.2"
	if _, err := parseDNSList(tooManyDNS); err == nil {
		t.Error("expected error for >8 DNS entries, got nil")
	}
}

func TestValidatePathsError(t *testing.T) {
	p := &Paths{
		MihomoData:       "/valid/path",
		MihomoConfigFile: "/valid/config.yaml",
		WgcfData:         "/valid/wgcf",
		WgcfAccountFile:  "/valid/account.toml",
		WgcfProfileFile:  "/valid/profile.conf",
		MihomoBin:        "/bin/../bin",
		WgcfBin:          "/valid/bin",
		SuExecBin:        "/valid/suexec",
		VersionFile:      "/valid/version",
	}
	if err := validatePaths(p); err == nil {
		t.Error("expected error for path traversal in MihomoBin, got nil")
	}
}

func TestLoadConfigGeoAndAmneziaErrors(t *testing.T) {
	user, pass := testCreds()
	base := []string{contract.EnvProxyUser, user, contract.EnvProxyPass, pass}

	t.Run("geo user set without pass", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvGeoAuthUser, "geouser", contract.EnvGeoAuthSecret, "")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error when geo user is set without secret, got nil")
		}
	})

	t.Run("geo invalid url", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvGeoURLGeoIP, "http://insecure.example.com")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for non-https geo url, got nil")
		}
	})

	t.Run("warp amnezia jmin not less than jmax", func(t *testing.T) {
		args := append(slicesClone(base),
			contract.EnvWarpAmnezia, "true",
			contract.EnvWarpAmneziaJMin, "50",
			contract.EnvWarpAmneziaJMax, "50",
		)
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error when jmin >= jmax, got nil")
		}
	})
}

func TestLoadRemainingValidationErrors(t *testing.T) {
	user, pass := testCreds()
	base := []string{contract.EnvProxyUser, user, contract.EnvProxyPass, pass}

	t.Run("invalid paths", func(t *testing.T) {
		origPaths := getPaths
		defer func() { getPaths = origPaths }()
		getPaths = func() Paths {
			p := defaultGetPaths()
			p.MihomoBin = "relative/path"
			return p
		}
		setEnv(t, base...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for relative MIHOMO_BIN, got nil")
		}
	})

	t.Run("invalid tz", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvTZ, "Bad/Timezone!")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid TZ, got nil")
		}
	})

	t.Run("invalid script log level", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvScriptLogLevel, "NONEXISTENT")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid SCRIPT_LOG_LEVEL, got nil")
		}
	})

	t.Run("invalid proxy port out of range", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvProxyPort, "70000")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for out of range PROXY_PORT, got nil")
		}
	})

	t.Run("invalid multi user mode bool", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvMultiUserMode, "not-a-bool")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid MULTI_USER_MODE, got nil")
		}
	})

	t.Run("invalid use ip6 bool", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvUseIP6, "not-a-bool")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid USE_IP6, got nil")
		}
	})

	t.Run("invalid geo bool", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvGeo, "not-a-bool")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid GEO, got nil")
		}
	})

	t.Run("invalid geo auth user credential", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvGeoAuthUser, "bad:user", contract.EnvGeoAuthSecret, "validpass")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid GEO_AUTH_USER, got nil")
		}
	})

	t.Run("invalid geo auth secret credential", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvGeoAuthUser, "validuser", contract.EnvGeoAuthSecret, "bad:pass")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid GEO_AUTH_PASS, got nil")
		}
	})

	t.Run("invalid use warp config bool", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvUseWarpConfig, "not-a-bool")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid USE_WARP_CONFIG, got nil")
		}
	})

	t.Run("invalid warp plus key", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvWarpPlusKey, "shortkey")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid WARP_PLUS_KEY, got nil")
		}
	})

	t.Run("invalid warp dns list", func(t *testing.T) {
		args := append(slicesClone(base), contract.EnvWarpDNS, "invalid.dns.entry")
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid WARP_DNS, got nil")
		}
	})

	t.Run("invalid warp amnezia jmin not numeric", func(t *testing.T) {
		args := append(slicesClone(base),
			contract.EnvWarpAmnezia, "true",
			contract.EnvWarpAmneziaJMin, "not_a_number",
		)
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid WARP_AMNEZIA_JMIN, got nil")
		}
	})

	t.Run("invalid warp amnezia I param", func(t *testing.T) {
		args := append(slicesClone(base),
			contract.EnvWarpAmnezia, "true",
			contract.EnvWarpAmneziaJMin, "10",
			contract.EnvWarpAmneziaJMax, "20",
			contract.EnvWarpAmneziaIPrefix+"1", "<b 0xZZ>",
		)
		setEnv(t, args...)
		if _, err := Load("test"); err == nil {
			t.Error("expected error for invalid Amnezia I-param, got nil")
		}
	})
}

func TestDefaultGetPaths(t *testing.T) {
	p := defaultGetPaths()
	if p.MihomoData != "/app/mihomo" {
		t.Errorf("unexpected MihomoData: %s", p.MihomoData)
	}
}
