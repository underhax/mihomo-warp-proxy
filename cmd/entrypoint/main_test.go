package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/contract"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
	"github.com/underhax/mihomo-warp-proxy/internal/wgcf"
)

func mockFetchReservedSuccess(_ string, _ *logging.Logger) ([3]byte, error) {
	return [3]byte{1, 2, 3}, nil
}

func mockPrepareGeoDefault(_ context.Context, _ *config.Config, _ *logging.Logger) error {
	return nil
}

func mockPrepareGeoError(_ context.Context, _ *config.Config, _ *logging.Logger) error {
	return errors.New("mock prepare geo error")
}

func mockWgcfSetupSuccess(_ context.Context, _ *config.Config, _ *logging.Logger) error {
	return nil
}

func mockWgcfSetupFailure(_ context.Context, _ *config.Config, _ *logging.Logger) error {
	return errors.New("mock wgcf setup failure")
}

func mockWgcfParseProfileSuccess(_ *config.Config) (*wgcf.Profile, error) {
	return &wgcf.Profile{}, nil
}

func mockFetchReservedError(_ string, _ *logging.Logger) ([3]byte, error) {
	return [3]byte{}, errors.New("mock fetch reserved error")
}

func mockHealthCheckSuccess(_ context.Context, _ *config.Config, _ ...string) error {
	return nil
}

func mockHealthCheckFailure(_ context.Context, _ *config.Config, _ ...string) error {
	return errors.New("mock health check error")
}

func init() {
	fetchReserved = mockFetchReservedSuccess
	prepareGeo = mockPrepareGeoDefault
	healthCheck = mockHealthCheckSuccess
}

func TestRunCommonTasksMinimal(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")

	cfg := &config.Config{
		Paths: config.Paths{
			MihomoConfigFile: configFile,
		},
		ProxyPort:     7890,
		ProxyLogLevel: "info",
	}

	log := logging.New(logging.LevelDebug, "test")

	if err := runCommonTasks(t.Context(), cfg, log); err != nil {
		t.Fatalf("runCommonTasks failed: %v", err)
	}

	if _, err := os.Stat(configFile); err != nil {
		t.Errorf("expected config file to be created: %v", err)
	}
}

func TestRunCommonTasksGeoError(t *testing.T) {
	origGeo := prepareGeo
	prepareGeo = mockPrepareGeoError
	t.Cleanup(func() {
		prepareGeo = origGeo
	})

	cfg := &config.Config{
		Geo: config.GeoConfig{
			Enabled: true,
		},
	}

	log := logging.New(logging.LevelDebug, "test")

	if err := runCommonTasks(t.Context(), cfg, log); err == nil {
		t.Error("expected error when geo download fails, got nil")
	}
}

func TestRunCommonTasksWarpSetupError(t *testing.T) {
	origSetup := wgcfSetup
	wgcfSetup = mockWgcfSetupFailure
	t.Cleanup(func() {
		wgcfSetup = origSetup
	})

	cfg := &config.Config{
		Warp: config.WarpConfig{
			Enabled: true,
		},
	}

	log := logging.New(logging.LevelDebug, "test")

	if err := runCommonTasks(t.Context(), cfg, log); err == nil {
		t.Error("expected error when warp setup fails, got nil")
	}
}

func TestRunWarpSetupSuccess(t *testing.T) {
	origReserved := fetchReserved
	fetchReserved = mockFetchReservedSuccess
	t.Cleanup(func() {
		fetchReserved = origReserved
	})

	dir := t.TempDir()
	accountFile := filepath.Join(dir, "wgcf-account.toml")
	profileFile := filepath.Join(dir, "wgcf-profile.conf")
	configFile := filepath.Join(dir, "config.yaml")

	accountContent := "access_token = \"test-token\"\ndevice_id = \"abcdef01-1234-5678-abcd-ef0123456789\"\n"
	if err := os.WriteFile(accountFile, []byte(accountContent), 0o600); err != nil {
		t.Fatal(err)
	}

	profileContent := "[Interface]\n" +
		"PrivateKey = aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
		"Address = 172.16.0.40/32,2606:4700:110:8949:fed8:548c:4603:5b40/128\n" +
		"DNS = 1.1.1.1,1.0.0.1\n" +
		"MTU = 1280\n\n" +
		"[Peer]\n" +
		"PublicKey = fmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n" +
		"AllowedIPs = 0.0.0.0/0,::/0\n" +
		"Endpoint = engage.cloudflareclient.com:2408\n"
	if err := os.WriteFile(profileFile, []byte(profileContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData:         dir,
			WgcfAccountFile:  accountFile,
			WgcfProfileFile:  profileFile,
			MihomoConfigFile: configFile,
		},
		Warp: config.WarpConfig{
			Enabled:  true,
			Endpoint: "engage.cloudflareclient.com:2408",
		},
		ProxyPort:     7890,
		ProxyLogLevel: "info",
	}

	log := logging.New(logging.LevelDebug, "test")

	if err := runWarpSetup(t.Context(), cfg, log); err != nil {
		t.Fatalf("runWarpSetup failed: %v", err)
	}

	if _, err := os.Stat(configFile); err != nil {
		t.Errorf("expected config file to be created by runWarpSetup: %v", err)
	}
}

func TestExecMihomo(t *testing.T) {
	origExec := syscallExec
	var capturedBin string
	var capturedArgs []string
	syscallExec = func(argv0 string, argv, _ []string) error {
		capturedBin = argv0
		capturedArgs = argv
		return nil
	}
	t.Cleanup(func() {
		syscallExec = origExec
	})

	cfg := &config.Config{
		Paths: config.Paths{
			MihomoBin:        "/app/bin/mihomo",
			MihomoData:       "/data",
			MihomoConfigFile: "/data/config.yaml",
		},
	}
	log := logging.New(logging.LevelDebug, "test")

	if err := execMihomo(cfg, log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedBin != cfg.Paths.MihomoBin {
		t.Errorf("got bin %q, want %q", capturedBin, cfg.Paths.MihomoBin)
	}
	if len(capturedArgs) < 5 {
		t.Fatalf("unexpected args length: %d", len(capturedArgs))
	}
}

func TestMainReexecSuccess(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")

	origExec := syscallExec
	var executed bool
	syscallExec = func(_ string, _, _ []string) error {
		executed = true
		return nil
	}

	origLoadConfig := loadConfig
	loadConfig = func(_ string) (*config.Config, error) {
		return &config.Config{
			LogLevelStr: contract.LogLevelDebug,
			ProxyPort:   7890,
			Paths: config.Paths{
				MihomoData:       dir,
				MihomoConfigFile: configFile,
				MihomoBin:        "/usr/local/bin/mihomo",
			},
		}, nil
	}
	t.Cleanup(func() {
		syscallExec = origExec
		loadConfig = origLoadConfig
	})

	origArgs := os.Args
	os.Args = []string{"entrypoint"}
	t.Cleanup(func() {
		os.Args = origArgs
	})

	main()

	if !executed {
		t.Errorf("expected execMihomo to be invoked in main")
	}
}

func TestMainInvalidLogLevel(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")

	origExec := syscallExec
	var executed bool
	syscallExec = func(_ string, _, _ []string) error {
		executed = true
		return nil
	}

	origLoadConfig := loadConfig
	loadConfig = func(_ string) (*config.Config, error) {
		return &config.Config{
			LogLevelStr: "INVALID_LEVEL",
			ProxyPort:   7890,
			Paths: config.Paths{
				MihomoData:       dir,
				MihomoConfigFile: configFile,
				MihomoBin:        "/usr/local/bin/mihomo",
			},
		}, nil
	}
	t.Cleanup(func() {
		syscallExec = origExec
		loadConfig = origLoadConfig
	})

	origArgs := os.Args
	os.Args = []string{"entrypoint"}
	t.Cleanup(func() {
		os.Args = origArgs
	})

	main()

	if !executed {
		t.Errorf("expected execMihomo to be invoked in main")
	}
}

func TestDefaultLoadConfig(t *testing.T) {
	t.Setenv("PROXY_USER", "validuser")
	t.Setenv("PROXY_PASS", "Ab1cdefghijklmnopqrstuvwxyz0123456789")
	cfg, err := defaultLoadConfig("test-version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || cfg.Version != "test-version" {
		t.Errorf("unexpected config result: %v", cfg)
	}
	if cfg.ProxyPass != "Ab1cdefghijklmnopqrstuvwxyz0123456789" {
		t.Errorf("ProxyPass mismatch: got %q", cfg.ProxyPass)
	}
}

func TestDefaultLoadConfigError(t *testing.T) {
	t.Setenv("PROXY_PORT", "not-a-port")
	_, err := defaultLoadConfig("test-version")
	if err == nil {
		t.Error("expected error for invalid config, got nil")
	}
}

func TestRunWarpSetupParseProfileError(t *testing.T) {
	dir := t.TempDir()
	accountFile := filepath.Join(dir, "wgcf-account.toml")
	if err := os.WriteFile(accountFile, []byte("account_id = \"id\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData:        dir,
			WgcfAccountFile: accountFile,
			WgcfProfileFile: filepath.Join(dir, "nonexistent-profile.conf"),
		},
		Warp: config.WarpConfig{
			Enabled: true,
		},
	}
	origSetup := wgcfSetup
	wgcfSetup = mockWgcfSetupSuccess
	t.Cleanup(func() {
		wgcfSetup = origSetup
	})

	log := logging.New(logging.LevelDebug, "test")
	if err := runWarpSetup(t.Context(), cfg, log); err == nil {
		t.Error("expected error when profile parsing fails, got nil")
	}
}

func TestMainSuccess(t *testing.T) {
	origRun := runFn
	origExit := osExit
	var ran bool
	var exited bool
	runFn = func(_ context.Context, _ []string) error {
		ran = true
		return nil
	}
	osExit = func(_ int) {
		exited = true
	}
	t.Cleanup(func() {
		runFn = origRun
		osExit = origExit
	})

	main()

	if !ran {
		t.Error("expected runFn to be called in main")
	}
	if exited {
		t.Error("expected osExit not to be called in main on success")
	}
}

func TestMainError(t *testing.T) {
	origRun := runFn
	origExit := osExit
	var exitCode int
	runFn = func(_ context.Context, _ []string) error {
		return errors.New("test error")
	}
	osExit = func(code int) {
		exitCode = code
	}
	t.Cleanup(func() {
		runFn = origRun
		osExit = origExit
	})

	main()

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
}

func TestMainCanceled(t *testing.T) {
	origRun := runFn
	origExit := osExit
	var exitCode int
	var exited bool
	runFn = func(_ context.Context, _ []string) error {
		return context.Canceled
	}
	osExit = func(code int) {
		exitCode = code
		exited = true
	}
	t.Cleanup(func() {
		runFn = origRun
		osExit = origExit
	})

	main()

	if !exited {
		t.Error("expected osExit to be called on context.Canceled")
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0 on context.Canceled, got %d", exitCode)
	}
}

func TestRunLoadConfigError(t *testing.T) {
	origLoad := loadConfig
	loadConfig = func(_ string) (*config.Config, error) {
		return nil, errors.New("cannot load")
	}
	t.Cleanup(func() {
		loadConfig = origLoad
	})

	err := run(t.Context(), nil)
	if err == nil {
		t.Error("expected error from run on config failure, got nil")
	}
}

func TestRunHealth(t *testing.T) {
	origLoad := loadConfig
	origHealth := checkHealth
	t.Cleanup(func() {
		loadConfig = origLoad
		checkHealth = origHealth
	})

	tests := []struct {
		name       string
		loadFn     func(string) (*config.Config, error)
		healthFn   func(context.Context, *config.Config) error
		wantErrSub string
	}{
		{
			name: "success",
			loadFn: func(_ string) (*config.Config, error) {
				return &config.Config{ProxyPort: 7890}, nil
			},
			healthFn: func(_ context.Context, _ *config.Config) error {
				return nil
			},
			wantErrSub: "",
		},
		{
			name: "health check failure",
			loadFn: func(_ string) (*config.Config, error) {
				return &config.Config{ProxyPort: 7890}, nil
			},
			healthFn: func(_ context.Context, _ *config.Config) error {
				return errors.New("simulated probe failure")
			},
			wantErrSub: "health check failed",
		},
		{
			name: "config load failure",
			loadFn: func(_ string) (*config.Config, error) {
				return nil, errors.New("simulated config load error")
			},
			healthFn: func(_ context.Context, _ *config.Config) error {
				return nil
			},
			wantErrSub: "configuration error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loadConfig = tt.loadFn
			checkHealth = tt.healthFn
			err := run(t.Context(), []string{"health"})
			if tt.wantErrSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErrSub, err)
			}
		})
	}
}

func TestDefaultCheckHealth(t *testing.T) {
	origHealthCheck := healthCheck
	t.Cleanup(func() {
		healthCheck = origHealthCheck
	})

	t.Run("success returns nil", func(t *testing.T) {
		healthCheck = mockHealthCheckSuccess
		cfg := &config.Config{ProxyPort: 7890}
		if err := defaultCheckHealth(t.Context(), cfg); err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
	})

	t.Run("failure wraps error", func(t *testing.T) {
		healthCheck = mockHealthCheckFailure
		cfg := &config.Config{ProxyPort: 7890}
		err := defaultCheckHealth(t.Context(), cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "check health: mock health check error") {
			t.Errorf("expected wrapped error, got: %v", err)
		}
	})
}

func TestRunCommonTasksError(t *testing.T) {
	dir := t.TempDir()
	origLoad := loadConfig
	origGeo := prepareGeo
	prepareGeo = mockPrepareGeoError
	loadConfig = func(_ string) (*config.Config, error) {
		return &config.Config{
			LogLevelStr: contract.LogLevelDebug,
			Geo: config.GeoConfig{
				Enabled: true,
			},
			Paths: config.Paths{
				MihomoData:       dir,
				MihomoConfigFile: filepath.Join(dir, "config.yaml"),
			},
		}, nil
	}
	t.Cleanup(func() {
		loadConfig = origLoad
		prepareGeo = origGeo
	})

	err := run(t.Context(), nil)
	if err == nil {
		t.Error("expected runCommonTasks error, got nil")
	}
}

func TestRunExecMihomoError(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")

	origExec := syscallExec
	origLoad := loadConfig
	syscallExec = func(_ string, _, _ []string) error {
		return errors.New("exec failed")
	}
	loadConfig = func(_ string) (*config.Config, error) {
		return &config.Config{
			LogLevelStr: contract.LogLevelDebug,
			ProxyPort:   7890,
			Paths: config.Paths{
				MihomoData:       dir,
				MihomoConfigFile: configFile,
				MihomoBin:        filepath.Join(dir, "bin_mihomo"),
			},
		}, nil
	}
	t.Cleanup(func() {
		syscallExec = origExec
		loadConfig = origLoad
	})

	err := run(t.Context(), nil)
	if err == nil {
		t.Error("expected execMihomo error, got nil")
	}
}

func TestRunBackupSuccess(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configFile, []byte("port: 7890\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	origExec := syscallExec
	origLoad := loadConfig
	syscallExec = func(_ string, _, _ []string) error {
		return nil
	}
	loadConfig = func(_ string) (*config.Config, error) {
		return &config.Config{
			LogLevelStr: contract.LogLevelDebug,
			ProxyPort:   7890,
			Paths: config.Paths{
				MihomoData:       dir,
				MihomoConfigFile: configFile,
				MihomoBin:        filepath.Join(dir, "exec_mihomo"),
			},
		}, nil
	}
	t.Cleanup(func() {
		syscallExec = origExec
		loadConfig = origLoad
	})

	if err := run(t.Context(), nil); err != nil {
		t.Fatalf("unexpected error with backup: %v", err)
	}
	if _, err := os.Stat(configFile + ".back"); err != nil {
		t.Errorf("expected backup file to exist: %v", err)
	}
}

func TestRunBackupFailure(t *testing.T) {
	dir := t.TempDir()
	origExec := syscallExec
	origLoad := loadConfig
	syscallExec = func(_ string, _, _ []string) error {
		return nil
	}
	loadConfig = func(_ string) (*config.Config, error) {
		return &config.Config{
			LogLevelStr: contract.LogLevelDebug,
			ProxyPort:   7890,
			Paths: config.Paths{
				MihomoData:       dir,
				MihomoConfigFile: "/proc/forbidden/config.yaml",
				MihomoBin:        filepath.Join(dir, "test_mihomo"),
			},
		}, nil
	}
	t.Cleanup(func() {
		syscallExec = origExec
		loadConfig = origLoad
	})

	if err := run(t.Context(), nil); err == nil {
		t.Error("expected error for forbidden config path, got nil")
	}
}

func TestDefaultRun(t *testing.T) {
	origLoad := loadConfig
	loadConfig = func(_ string) (*config.Config, error) {
		return nil, errors.New("sentinel error")
	}
	t.Cleanup(func() {
		loadConfig = origLoad
	})

	err := defaultRun(t.Context(), nil)
	if err == nil {
		t.Error("expected error from defaultRun, got nil")
	}
}

func TestRunWarpSetupEnsureConfigError(t *testing.T) {
	origReserved := fetchReserved
	fetchReserved = mockFetchReservedSuccess
	t.Cleanup(func() {
		fetchReserved = origReserved
	})

	dir := t.TempDir()
	accountFile := filepath.Join(dir, "wgcf-account.toml")
	profileFile := filepath.Join(dir, "wgcf-profile.conf")
	if err := os.WriteFile(accountFile, []byte("access_token=\"a\"\ndevice_id=\"b\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profileContent := "[Interface]\n" +
		"PrivateKey = aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
		"Address = 172.16.0.40/32,2606:4700:110:8949:fed8:548c:4603:5b40/128\n" +
		"DNS = 1.1.1.1,1.0.0.1\n" +
		"MTU = 1280\n\n" +
		"[Peer]\n" +
		"PublicKey = fmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n" +
		"AllowedIPs = 0.0.0.0/0,::/0\n" +
		"Endpoint = engage.cloudflareclient.com:2408\n"
	if err := os.WriteFile(profileFile, []byte(profileContent), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Paths: config.Paths{
			WgcfData:         dir,
			WgcfAccountFile:  accountFile,
			WgcfProfileFile:  profileFile,
			MihomoConfigFile: "/proc/nonexistent/config.yaml",
		},
		Warp: config.WarpConfig{
			Enabled: true,
		},
	}
	log := logging.New(logging.LevelDebug, "test")
	if err := runWarpSetup(t.Context(), cfg, log); err == nil {
		t.Error("expected error when EnsureConfig fails in runWarpSetup, got nil")
	}
}

func TestRunCommonTasksEnsureConfigError(t *testing.T) {
	cfg := &config.Config{
		Paths: config.Paths{
			MihomoConfigFile: "/proc/nonexistent/config.yaml",
		},
	}
	log := logging.New(logging.LevelDebug, "test")
	if err := runCommonTasks(t.Context(), cfg, log); err == nil {
		t.Error("expected error when EnsureConfig fails with warp disabled, got nil")
	}
}

var testGeoCalled bool

func mockPrepareGeoFlag(_ context.Context, _ *config.Config, _ *logging.Logger) error {
	testGeoCalled = true
	return nil
}

func mockEnsureConfigNoop(_ *config.Config, _ *wgcf.Profile, _ [3]byte, _ *logging.Logger) error {
	return nil
}

func TestRunCommonTasksGeoSuccess(t *testing.T) {
	origGeo := prepareGeo
	origEnsure := ensureConfig
	t.Cleanup(func() {
		prepareGeo = origGeo
		ensureConfig = origEnsure
	})

	testGeoCalled = false
	prepareGeo = mockPrepareGeoFlag
	ensureConfig = mockEnsureConfigNoop

	cfg := &config.Config{
		Geo: config.GeoConfig{
			Enabled: true,
		},
		Warp: config.WarpConfig{
			Enabled: false,
		},
	}
	log := logging.New(logging.LevelDebug, "test")

	if err := runCommonTasks(t.Context(), cfg, log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !testGeoCalled {
		t.Error("expected prepareGeo to be called")
	}
}

var testCapturedReserved [3]byte

func mockEnsureConfigCapture(_ *config.Config, _ *wgcf.Profile, res [3]byte, _ *logging.Logger) error {
	testCapturedReserved = res
	return nil
}

func TestRunWarpSetupReservedSuccess(t *testing.T) {
	origSetup := wgcfSetup
	origParse := wgcfParseProfile
	origReserved := fetchReserved
	origEnsure := ensureConfig
	t.Cleanup(func() {
		wgcfSetup = origSetup
		wgcfParseProfile = origParse
		fetchReserved = origReserved
		ensureConfig = origEnsure
	})

	wgcfSetup = mockWgcfSetupSuccess
	wgcfParseProfile = mockWgcfParseProfileSuccess
	fetchReserved = mockFetchReservedSuccess
	ensureConfig = mockEnsureConfigCapture

	cfg := &config.Config{
		Paths: config.Paths{
			WgcfAccountFile: "/dummy/account.toml",
		},
	}
	log := logging.New(logging.LevelDebug, "test")

	if err := runWarpSetup(t.Context(), cfg, log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if testCapturedReserved != [3]byte{1, 2, 3} {
		t.Errorf("expected reserved [1, 2, 3], got %v", testCapturedReserved)
	}
}

func TestRunWarpSetupFetchReservedError(t *testing.T) {
	origSetup := wgcfSetup
	origParse := wgcfParseProfile
	origReserved := fetchReserved
	origEnsure := ensureConfig
	t.Cleanup(func() {
		wgcfSetup = origSetup
		wgcfParseProfile = origParse
		fetchReserved = origReserved
		ensureConfig = origEnsure
	})

	wgcfSetup = mockWgcfSetupSuccess
	wgcfParseProfile = mockWgcfParseProfileSuccess
	fetchReserved = mockFetchReservedError
	ensureConfig = mockEnsureConfigCapture

	cfg := &config.Config{
		Paths: config.Paths{
			WgcfAccountFile: "/dummy/account.toml",
		},
	}
	log := logging.New(logging.LevelDebug, "test")

	if err := runWarpSetup(t.Context(), cfg, log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if testCapturedReserved != [3]byte{} {
		t.Errorf("expected empty reserved bytes on error, got %v", testCapturedReserved)
	}
}

func TestRunWarpSetupWgcfSetupError(t *testing.T) {
	origSetup := wgcfSetup
	wgcfSetup = mockWgcfSetupFailure
	t.Cleanup(func() {
		wgcfSetup = origSetup
	})
	cfg := &config.Config{}
	log := logging.New(logging.LevelDebug, "test")
	if err := runWarpSetup(t.Context(), cfg, log); err == nil {
		t.Error("expected error when wgcfSetup fails, got nil")
	}
}
