package wgcf

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
)

func TestParseINI(t *testing.T) {
	profileContent := `[Interface]
PrivateKey = YH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZEEEE=
Address = 172.16.0.2/32,2606:4700:110:8949:fed8:548c:4603:5b00/128
DNS = 1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001
MTU = 1280

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = engage.cloudflareclient.com:2408
`

	p, err := parseINI(profileContent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.PrivateKey != "YH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZEEEE=" {
		t.Errorf("PrivateKey: got %q", p.PrivateKey)
	}
	if p.PublicKey != "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" {
		t.Errorf("PublicKey: got %q", p.PublicKey)
	}
	if p.IPv4 != "172.16.0.2" {
		t.Errorf("IPv4: got %q, want %q", p.IPv4, "172.16.0.2")
	}
	if p.IPv6 != "2606:4700:110:8949:fed8:548c:4603:5b00" {
		t.Errorf("IPv6: got %q, want %q", p.IPv6, "2606:4700:110:8949:fed8:548c:4603:5b00")
	}
}

func TestParseINICommentAndBlankLines(t *testing.T) {
	content := `
# This is a comment
[Interface]
# Another comment
PrivateKey = WJ2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZDDDD=
Address = 172.16.0.9/32,2606:4700:110:8949:fed8:548c:4603:5b09/128

[Peer]
PublicKey = cmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
`
	p, err := parseINI(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.PrivateKey == "" || p.PublicKey == "" {
		t.Error("keys not parsed when comments and blank lines present")
	}
}

func TestSplitAddresses(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantV4  string
		wantV6  string
		wantErr bool
	}{
		{
			name:   "standard wgcf output",
			input:  "172.16.0.10/32,2606:4700:110:8949:fed8:548c:4603:5b10/128",
			wantV4: "172.16.0.10",
			wantV6: "2606:4700:110:8949:fed8:548c:4603:5b10",
		},
		{
			name:   "addresses with spaces",
			input:  " 172.16.0.11/32 , 2606:4700::11/128 ",
			wantV4: "172.16.0.11",
			wantV6: "2606:4700::11",
		},
		{
			name:    "missing ipv4",
			input:   "2606:4700::12/128",
			wantErr: true,
		},
		{
			name:    "missing ipv6",
			input:   "172.16.0.12/32",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6, err := splitAddresses(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (v4=%q v6=%q)", v4, v6)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v4 != tc.wantV4 {
				t.Errorf("IPv4: got %q, want %q", v4, tc.wantV4)
			}
			if v6 != tc.wantV6 {
				t.Errorf("IPv6: got %q, want %q", v6, tc.wantV6)
			}
		})
	}
}

func TestValidateProfile(t *testing.T) {
	validPrivateKey := "QH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZAAAA="
	validPublicKey := "dmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	validIPv4 := "172.16.0.20"
	validIPv6 := "2606:4700::20"

	cases := []struct {
		name    string
		p       Profile
		wantErr bool
	}{
		{
			name: "valid profile",
			p: Profile{
				PrivateKey: validPrivateKey,
				PublicKey:  validPublicKey,
				IPv4:       validIPv4,
				IPv6:       validIPv6,
			},
		},
		{
			name: "private key too short",
			p: Profile{
				PrivateKey: "tooshort",
				PublicKey:  validPublicKey,
				IPv4:       validIPv4,
				IPv6:       validIPv6,
			},
			wantErr: true,
		},
		{
			name: "public key too short",
			p: Profile{
				PrivateKey: validPrivateKey,
				PublicKey:  "tooshort",
				IPv4:       validIPv4,
				IPv6:       validIPv6,
			},
			wantErr: true,
		},
		{
			name: "missing ipv4",
			p: Profile{
				PrivateKey: validPrivateKey,
				PublicKey:  validPublicKey,
				IPv4:       "",
				IPv6:       validIPv6,
			},
			wantErr: true,
		},
		{
			name: "missing ipv6",
			p: Profile{
				PrivateKey: validPrivateKey,
				PublicKey:  validPublicKey,
				IPv4:       validIPv4,
				IPv6:       "",
			},
			wantErr: true,
		},
		{
			name: "invalid character in key",
			p: Profile{
				PrivateKey: "YH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZ!!!!",
				PublicKey:  validPublicKey,
				IPv4:       validIPv4,
				IPv6:       validIPv6,
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProfile(&tc.p)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()

	existing := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !fileExists(existing) {
		t.Error("fileExists returned false for existing file")
	}
	if fileExists(filepath.Join(dir, "missing.txt")) {
		t.Error("fileExists returned true for missing file")
	}
	if fileExists(dir) {
		t.Error("fileExists returned true for directory")
	}
}

func TestSanitizeOutput(t *testing.T) {
	short := []byte("error: something failed")
	if sanitizeOutput(short) != "error: something failed" {
		t.Errorf("sanitizeOutput modified short output")
	}

	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	result := sanitizeOutput(long)
	if len(result) > 515 {
		t.Errorf("sanitizeOutput did not truncate long output, len=%d", len(result))
	}
}

func TestParseProfileUnsafePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wgcf-profile.conf")

	profileContent := `[Interface]
PrivateKey = ZH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZBBBB=
Address = 172.16.0.30/32,2606:4700:110:8949:fed8:548c:4603:5b30/128
DNS = 1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001
MTU = 1280

[Peer]
PublicKey = emXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = engage.cloudflareclient.com:2408
`

	if err := os.WriteFile(path, []byte(profileContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := minimalCfg(path)
	_, err := ParseProfile(cfg)
	if err == nil {
		t.Error("expected error for 0o644 permissions, got nil")
	}
}

func TestParseProfileValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wgcf-profile.conf")

	profileContent := `[Interface]
PrivateKey = TH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZCCCC=
Address = 172.16.0.40/32,2606:4700:110:8949:fed8:548c:4603:5b40/128
DNS = 1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001
MTU = 1280

[Peer]
PublicKey = fmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = engage.cloudflareclient.com:2408
`

	if err := os.WriteFile(path, []byte(profileContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := minimalCfg(path)
	p, err := ParseProfile(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.IPv4 == "" || p.IPv6 == "" {
		t.Error("profile parsed with empty IP addresses")
	}
}

func minimalCfg(profilePath string) *config.Config {
	return &config.Config{
		Paths: config.Paths{
			WgcfProfileFile: profilePath,
		},
	}
}

func mockExecuteWgcf(_ context.Context, _, dir string, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}
	switch args[0] {
	case "register":
		accountFile := filepath.Join(dir, "wgcf-account.toml")
		content := "account_id = \"mock-account\"\naccess_token = \"mock-token\"\ndevice_id = \"abcdef01-1234-5678-abcd-ef0123456789\"\n"
		if err := os.WriteFile(accountFile, []byte(content), 0o600); err != nil {
			return nil, err
		}
		return []byte("registered"), nil
	case "generate":
		profileFile := filepath.Join(dir, "wgcf-profile.conf")
		content := "[Interface]\n" +
			"PrivateKey = TH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZCCCC=\n" +
			"Address = 172.16.0.40/32,2606:4700:110:8949:fed8:548c:4603:5b40/128\n" +
			"DNS = 1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001\n" +
			"MTU = 1280\n\n" +
			"[Peer]\n" +
			"PublicKey = fmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n" +
			"AllowedIPs = 0.0.0.0/0,::/0\n" +
			"Endpoint = engage.cloudflareclient.com:2408\n"
		if err := os.WriteFile(profileFile, []byte(content), 0o600); err != nil {
			return nil, err
		}
		return []byte("generated"), nil
	case "update":
		return []byte("updated"), nil
	default:
		return []byte("ok"), nil
	}
}

func TestSetup(t *testing.T) {
	origExec := executeWgcf
	executeWgcf = mockExecuteWgcf
	t.Cleanup(func() {
		executeWgcf = origExec
	})

	dir := t.TempDir()
	accountFile := filepath.Join(dir, "wgcf-account.toml")
	profileFile := filepath.Join(dir, "wgcf-profile.conf")

	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData:        dir,
			WgcfAccountFile: accountFile,
			WgcfProfileFile: profileFile,
			WgcfBin:         "/bin/wgcf",
		},
		Warp: config.WarpConfig{
			PlusKey: "test-plus-key",
		},
	}

	log := logging.New(logging.LevelDebug, "test")

	if err := Setup(cfg, log); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	if !fileExists(accountFile) {
		t.Error("account file not created")
	}
	if !fileExists(profileFile) {
		t.Error("profile file not created")
	}

	cfg.Warp.Regenerate = true
	if err := Setup(cfg, log); err != nil {
		t.Fatalf("Setup with regenerate failed: %v", err)
	}
}

func TestEndpointHelpers(t *testing.T) {
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData: "/var/lib/wgcf",
		},
		Warp: config.WarpConfig{
			Endpoint: "162.159.192.1:2408",
		},
	}
	if got := EndpointHost(cfg); got != "162.159.192.1" {
		t.Errorf("got %q, want 162.159.192.1", got)
	}
	if got := EndpointPort(cfg); got != "2408" {
		t.Errorf("got %q, want 2408", got)
	}
	if got := ProfilePath(cfg); got != "/var/lib/wgcf/wgcf-profile.conf" {
		t.Errorf("got %q, want /var/lib/wgcf/wgcf-profile.conf", got)
	}
}

func TestParseProfileErrors(t *testing.T) {
	dir := t.TempDir()
	missingFile := filepath.Join(dir, "nonexistent.conf")
	cfg := minimalCfg(missingFile)
	if _, err := ParseProfile(cfg); err == nil {
		t.Error("expected error for missing profile, got nil")
	}

	invalidContent := filepath.Join(dir, "invalid.conf")
	if err := os.WriteFile(invalidContent, []byte("not ini"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgInvalid := minimalCfg(invalidContent)
	if _, err := ParseProfile(cfgInvalid); err == nil {
		t.Error("expected error for invalid profile content, got nil")
	}

	if _, err := filePermissions(missingFile); err == nil {
		t.Error("expected error from filePermissions on missing file, got nil")
	}
}

func mockFailingExecuteWgcf(_ context.Context, _, _ string, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "register" {
		return []byte("error: network failure"), errors.New("command failed")
	}
	return []byte("ok"), nil
}

func TestSetupRegisterError(t *testing.T) {
	origExec := executeWgcf
	executeWgcf = mockFailingExecuteWgcf
	t.Cleanup(func() {
		executeWgcf = origExec
	})

	dir := t.TempDir()
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData:        dir,
			WgcfAccountFile: filepath.Join(dir, "wgcf-account.toml"),
			WgcfProfileFile: filepath.Join(dir, "wgcf-profile.conf"),
			WgcfBin:         filepath.Join(dir, "bin-wgcf"),
		},
	}
	log := logging.New(logging.LevelDebug, "test")
	if err := Setup(cfg, log); err == nil {
		t.Error("expected error when wgcf register fails, got nil")
	} else if !strings.Contains(err.Error(), "error: network failure") {
		t.Errorf("expected diagnostic output in error message, got: %v", err)
	}
}

func mockUpdateFailExecuteWgcf(_ context.Context, _, _ string, args ...string) ([]byte, error) {
	if len(args) > 0 {
		switch args[0] {
		case "update":
			return []byte("error: invalid key"), errors.New("update error")
		case "generate":
			return []byte("error: generate failure"), errors.New("generate error")
		}
	}
	return []byte("ok"), nil
}

func TestSetupUpdateAndGenerateErrors(t *testing.T) {
	origExec := executeWgcf
	executeWgcf = mockUpdateFailExecuteWgcf
	t.Cleanup(func() {
		executeWgcf = origExec
	})

	dir := t.TempDir()
	accountFile := filepath.Join(dir, "wgcf-account.toml")
	if err := os.WriteFile(accountFile, []byte("account_id = \"a\"\naccess_token = \"t\"\ndevice_id = \"d\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData:        dir,
			WgcfAccountFile: accountFile,
			WgcfProfileFile: filepath.Join(dir, "wgcf-profile.conf"),
			WgcfBin:         filepath.Join(dir, "bin-wgcf"),
		},
		Warp: config.WarpConfig{
			PlusKey: "some-key",
		},
	}
	log := logging.New(logging.LevelDebug, "test")
	if err := Setup(cfg, log); err == nil {
		t.Error("expected error when wgcf generate fails, got nil")
	}
}

func TestDefaultExecuteWgcf(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := defaultExecuteWgcf(ctx, "/bin/echo", "/tmp", "test")
	if err == nil {
		t.Error("expected error with canceled context, got nil")
	}
}

func TestSecureFilesSymlinkAndChmod(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	symlinkPath := filepath.Join(dir, "symlink.conf")
	if err := os.Symlink(target, symlinkPath); err != nil {
		t.Skip("symlinks not supported on this environment")
	}

	cfg := &config.Config{
		Paths: config.Paths{
			WgcfAccountFile: symlinkPath,
			WgcfProfileFile: filepath.Join(dir, "nonexistent.conf"),
		},
	}

	err := secureFiles(cfg)
	if err == nil || !strings.Contains(err.Error(), "open") {
		t.Errorf("expected open error on symlink, got: %v", err)
	}

	regularPath := filepath.Join(dir, "regular.conf")
	if writeErr := os.WriteFile(regularPath, []byte("data"), 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}
	cfg.Paths.WgcfAccountFile = regularPath
	if secureErr := secureFiles(cfg); secureErr != nil {
		t.Fatalf("unexpected error for regular file: %v", secureErr)
	}

	info, statErr := os.Stat(regularPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected 0600 perm, got %04o", info.Mode().Perm())
	}
}

func TestParseProfilePermissions(t *testing.T) {
	dir := t.TempDir()
	profileFile := filepath.Join(dir, "wgcf-profile.conf")
	if err := os.WriteFile(profileFile, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfProfileFile: profileFile,
		},
	}
	if _, err := ParseProfile(cfg); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Errorf("expected unsafe permissions error, got: %v", err)
	}
}

func TestParseProfileOversized(t *testing.T) {
	dir := t.TempDir()
	profileFile := filepath.Join(dir, "wgcf-profile.conf")
	data := strings.Repeat("a", maxWgcfFileSize+10)
	if err := os.WriteFile(profileFile, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfProfileFile: profileFile,
		},
	}
	if _, err := ParseProfile(cfg); err == nil || !strings.Contains(err.Error(), "exceeds 64KB limit") {
		t.Errorf("expected 64KB limit error, got: %v", err)
	}
}

func TestParseProfileInvalidValidation(t *testing.T) {
	dir := t.TempDir()
	profileFile := filepath.Join(dir, "wgcf-profile.conf")
	invalidProfile := `[Interface]
PrivateKey = bad
Address = 172.16.0.77/32,2606:4700::77/128
[Peer]
PublicKey = bad
`
	if err := os.WriteFile(profileFile, []byte(invalidProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfProfileFile: profileFile,
		},
	}
	if _, err := ParseProfile(cfg); err == nil || !strings.Contains(err.Error(), "invalid profile") {
		t.Errorf("expected invalid profile error, got: %v", err)
	}
}

func TestValidateProfileEdgeCases(t *testing.T) {
	validKey := "YH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZEEEE="
	p := &Profile{
		PrivateKey: "short",
		PublicKey:  validKey,
		IPv4:       "172.16.0.77",
		IPv6:       "2606:4700::77",
	}
	if err := validateProfile(p); err == nil {
		t.Error("expected error for short private key, got nil")
	}

	p.PrivateKey = validKey
	p.PublicKey = "short"
	if err := validateProfile(p); err == nil {
		t.Error("expected error for short public key, got nil")
	}

	p.PublicKey = validKey
	p.IPv4 = ""
	if err := validateProfile(p); err == nil {
		t.Error("expected error for missing IPv4, got nil")
	}

	p.IPv4 = "172.16.0.77"
	p.IPv6 = ""
	if err := validateProfile(p); err == nil {
		t.Error("expected error for missing IPv6, got nil")
	}

	p.IPv6 = "2606:4700::1"
	p.PrivateKey = strings.Repeat("!", 44)
	if err := validateProfile(p); err == nil {
		t.Error("expected error for non-base64 private key, got nil")
	}

	p.PrivateKey = validKey
	p.PublicKey = strings.Repeat("!", 44)
	if err := validateProfile(p); err == nil {
		t.Error("expected error for non-base64 public key, got nil")
	}
}

func TestSecureFilesStatError(t *testing.T) {
	dir := t.TempDir()
	dummyFile := filepath.Join(dir, "dummy_file")
	if err := os.WriteFile(dummyFile, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfAccountFile: filepath.Join(dummyFile, "account.toml"),
			WgcfProfileFile: filepath.Join(dir, "profile.conf"),
		},
	}
	if err := secureFiles(cfg); err == nil {
		t.Error("expected stat error for invalid path, got nil")
	}
}

func TestParseINIInvalidAddress(t *testing.T) {
	content := "[Interface]\nAddress = 172.16.0.77/32\n"
	if _, err := parseINI(content); err == nil {
		t.Error("expected error for missing IPv6 in Address, got nil")
	}
}

func TestDefaultExecuteWgcfSuccess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out, err := defaultExecuteWgcf(context.Background(), exe, t.TempDir(), "-test.list", "^$")
	if err != nil {
		t.Errorf("defaultExecuteWgcf failed: %v, out: %s", err, string(out))
	}
}

func TestSetupMkdirError(t *testing.T) {
	origMkdir := osMkdirAll
	defer func() { osMkdirAll = origMkdir }()
	osMkdirAll = func(string, os.FileMode) error {
		return errors.New("mock mkdir error")
	}

	cfg := &config.Config{}
	log := logging.New(logging.LevelDebug, "test")
	if err := Setup(cfg, log); err == nil || !strings.Contains(err.Error(), "create data directory") {
		t.Errorf("expected create data directory error, got: %v", err)
	}
}

func TestSetupRemoveAccountError(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData:        dir,
			WgcfAccountFile: filepath.Join(dir, "account.toml"),
			WgcfProfileFile: filepath.Join(dir, "profile.conf"),
		},
		Warp: config.WarpConfig{
			Regenerate: true,
		},
	}
	if err := os.WriteFile(cfg.Paths.WgcfAccountFile, []byte("account"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Paths.WgcfProfileFile, []byte("profile"), 0o600); err != nil {
		t.Fatal(err)
	}

	origRemove := osRemove
	defer func() { osRemove = origRemove }()
	osRemove = func(path string) error {
		if path == cfg.Paths.WgcfAccountFile {
			return errors.New("mock remove account error")
		}
		return nil
	}

	log := logging.New(logging.LevelDebug, "test")
	if err := Setup(cfg, log); err == nil || !strings.Contains(err.Error(), "remove account file") {
		t.Errorf("expected remove account file error, got: %v", err)
	}
}

func TestSetupRemoveProfileError(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData:        dir,
			WgcfAccountFile: filepath.Join(dir, "account.toml"),
			WgcfProfileFile: filepath.Join(dir, "profile.conf"),
		},
		Warp: config.WarpConfig{
			Regenerate: true,
		},
	}
	if err := os.WriteFile(cfg.Paths.WgcfAccountFile, []byte("account"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Paths.WgcfProfileFile, []byte("profile"), 0o600); err != nil {
		t.Fatal(err)
	}

	origRemove := osRemove
	defer func() { osRemove = origRemove }()
	osRemove = func(path string) error {
		if path == cfg.Paths.WgcfProfileFile {
			return errors.New("mock remove profile error")
		}
		return nil
	}

	log := logging.New(logging.LevelDebug, "test")
	if err := Setup(cfg, log); err == nil || !strings.Contains(err.Error(), "remove profile file") {
		t.Errorf("expected remove profile file error, got: %v", err)
	}
}

func mockErrFileChmod(_ *os.File, _ os.FileMode) error {
	return errors.New("mock chmod error")
}

func mockErrWgcfFileClose(f *os.File) error {
	if err := f.Close(); err != nil {
		return err
	}
	return errors.New("mock close error")
}

func TestSecureFilesChmodError(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData:        dir,
			WgcfAccountFile: filepath.Join(dir, "account.toml"),
			WgcfProfileFile: filepath.Join(dir, "profile.conf"),
		},
	}
	if err := os.WriteFile(cfg.Paths.WgcfAccountFile, []byte("account"), 0o600); err != nil {
		t.Fatal(err)
	}

	origChmod := fileChmod
	defer func() { fileChmod = origChmod }()
	fileChmod = mockErrFileChmod

	if err := secureFiles(cfg); err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Errorf("expected chmod error, got: %v", err)
	}

	log := logging.New(logging.LevelDebug, "test")
	origExec := executeWgcf
	defer func() { executeWgcf = origExec }()
	executeWgcf = mockExecuteWgcf
	if err := Setup(cfg, log); err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Errorf("expected setup error from secureFiles chmod, got: %v", err)
	}
}

func TestSecureFilesCloseError(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData:        dir,
			WgcfAccountFile: filepath.Join(dir, "account.toml"),
			WgcfProfileFile: filepath.Join(dir, "profile.conf"),
		},
	}
	if err := os.WriteFile(cfg.Paths.WgcfAccountFile, []byte("account"), 0o600); err != nil {
		t.Fatal(err)
	}

	origClose := fileClose
	defer func() { fileClose = origClose }()
	fileClose = mockErrWgcfFileClose

	if err := secureFiles(cfg); err == nil || !strings.Contains(err.Error(), "close") {
		t.Errorf("expected close error, got: %v", err)
	}
}

func TestParseProfileOpenError(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.conf")
	if err := os.WriteFile(profilePath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Paths: config.Paths{WgcfProfileFile: profilePath},
	}

	origOpen := osOpen
	defer func() { osOpen = origOpen }()
	osOpen = func(string) (*os.File, error) {
		return nil, errors.New("mock open error")
	}

	if _, err := ParseProfile(cfg); err == nil || !strings.Contains(err.Error(), "read profile") {
		t.Errorf("expected open error, got: %v", err)
	}
}

func TestParseProfileCloseAndReadErrors(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.conf")
	validContent := `[Interface]
PrivateKey = YH2h2kSHzMaAgBNiNWuMEljlKGsaVKnv+hFtZOZEEEE=
Address = 172.16.0.2/32,2606:4700:110:8949:fed8:548c:4603:5b00/128

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
`
	if err := os.WriteFile(profilePath, []byte(validContent), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Paths: config.Paths{WgcfProfileFile: profilePath},
	}

	origClose := fileClose
	defer func() { fileClose = origClose }()
	fileClose = func(*os.File) error {
		return errors.New("mock close error")
	}
	if _, err := ParseProfile(cfg); err == nil || !strings.Contains(err.Error(), "close profile") {
		t.Errorf("expected close error, got: %v", err)
	}
	fileClose = origClose

	origRead := fileReadAll
	defer func() { fileReadAll = origRead }()
	fileReadAll = func(io.Reader) ([]byte, error) {
		return nil, errors.New("mock read error")
	}
	if _, err := ParseProfile(cfg); err == nil || !strings.Contains(err.Error(), "read profile") {
		t.Errorf("expected read error, got: %v", err)
	}
}

func TestParseProfileInvalidINI(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.conf")
	content := "[Interface]\nAddress = invalid_address\n"
	if err := os.WriteFile(profilePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Paths: config.Paths{WgcfProfileFile: profilePath},
	}
	if _, err := ParseProfile(cfg); err == nil || !strings.Contains(err.Error(), "parse profile") {
		t.Errorf("expected parse profile error, got: %v", err)
	}
}

func TestDefaultFileHelpers(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "wgcf_helper_test")
	if err != nil {
		t.Fatal(err)
	}
	if chmodErr := defaultFileChmod(f, 0o600); chmodErr != nil {
		t.Errorf("defaultFileChmod failed: %v", chmodErr)
	}
	if closeErr := defaultFileClose(f); closeErr != nil {
		t.Errorf("defaultFileClose failed: %v", closeErr)
	}
	if closeErr := defaultFileClose(f); closeErr == nil {
		t.Error("expected error on double close, got nil")
	}
	if chmodErr := defaultFileChmod(f, 0o600); chmodErr == nil {
		t.Error("expected error on chmod of closed file, got nil")
	}

	b, readErr := defaultFileReadAll(strings.NewReader("wgcf_data"))
	if readErr != nil || string(b) != "wgcf_data" {
		t.Errorf("defaultFileReadAll unexpected result: %s, %v", string(b), readErr)
	}
	if _, readFailErr := defaultFileReadAll(errReader{}); readFailErr == nil {
		t.Error("expected error on errReader, got nil")
	}
}

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated read failure")
}
