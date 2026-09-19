// Package main implements the container init process for mihomo-warp-proxy.
package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/underhax/mihomo-warp-proxy/internal/backup"
	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/contract"
	"github.com/underhax/mihomo-warp-proxy/internal/geo"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
	"github.com/underhax/mihomo-warp-proxy/internal/mihomo"
	"github.com/underhax/mihomo-warp-proxy/internal/usermode"
	"github.com/underhax/mihomo-warp-proxy/internal/warp"
	"github.com/underhax/mihomo-warp-proxy/internal/wgcf"
)

var version = "dev"

func defaultLoadConfig(version string) (*config.Config, error) {
	cfg, err := config.Load(version)
	if err != nil {
		return nil, fmt.Errorf("config.Load: %w", err)
	}
	return cfg, nil
}

func defaultRun(args []string) error {
	return run(args)
}

var (
	syscallExec      = syscall.Exec
	loadConfig       = defaultLoadConfig
	runFn            = defaultRun
	osExit           = os.Exit
	prepareGeo       = geo.PrepareGeoFiles
	wgcfSetup        = wgcf.Setup
	wgcfParseProfile = wgcf.ParseProfile
	fetchReserved    = warp.FetchReserved
	ensureConfig     = mihomo.EnsureConfig
)

func main() {
	if err := runFn(os.Args[1:]); err != nil {
		log := logging.New(logging.LevelWarn, version)
		log.Errorf("%v", err)
		osExit(1)
	}
}

func run(args []string) error {
	reexec := len(args) > 0 && args[0] == contract.FlagRunAsUser

	log := logging.New(logging.LevelWarn, version)

	cfg, err := loadConfig(version)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	level, err := logging.ParseLevel(cfg.LogLevelStr)
	if err != nil {
		log.Warnf("%v — using WARN", err)
		level = logging.LevelWarn
	}
	log = logging.New(level, version)

	log.Debugf("configuration loaded: port=%d warp=%v geo=%v", cfg.ProxyPort, cfg.Warp.Enabled, cfg.Geo.Enabled)
	log.Debugf("entrypoint starting (version %s, reexec=%v)", version, reexec)

	if err := usermode.Dispatch(cfg, reexec, log); err != nil {
		return fmt.Errorf("usermode: %w", err)
	}

	if err := backup.ConfigFile(cfg.Paths.MihomoConfigFile); err != nil {
		log.Warnf("config backup failed: %v", err)
	} else {
		log.Debugf("config backup created: %s.back", cfg.Paths.MihomoConfigFile)
	}

	if err := runCommonTasks(cfg, log); err != nil {
		return err
	}

	return execMihomo(cfg, log)
}

func runCommonTasks(cfg *config.Config, log *logging.Logger) error {
	if cfg.Geo.Enabled {
		log.Debug("starting geo file preparation")
		if err := prepareGeo(cfg, log); err != nil {
			return fmt.Errorf("geo: %w", err)
		}
		log.Debug("geo file preparation complete")
	}

	if cfg.Warp.Enabled {
		log.Debug("starting warp setup")
		return runWarpSetup(cfg, log)
	}

	log.Debug("warp disabled — ensuring minimal mihomo config")
	if err := ensureConfig(cfg, nil, [3]byte{}, log); err != nil {
		return fmt.Errorf("mihomo: ensure config: %w", err)
	}
	return nil
}

func runWarpSetup(cfg *config.Config, log *logging.Logger) error {
	if err := wgcfSetup(cfg, log); err != nil {
		return fmt.Errorf("wgcf setup: %w", err)
	}
	log.Debug("wgcf setup complete")

	profile, err := wgcfParseProfile(cfg)
	if err != nil {
		return fmt.Errorf("wgcf parse profile: %w", err)
	}

	var reserved [3]byte
	r, err := fetchReserved(cfg.Paths.WgcfAccountFile, log)
	if err != nil {
		log.Warnf("could not fetch WARP reserved bytes: %v", err)
	} else {
		reserved = r
	}

	if err := ensureConfig(cfg, profile, reserved, log); err != nil {
		return fmt.Errorf("mihomo: ensure config: %w", err)
	}
	return nil
}

func execMihomo(cfg *config.Config, log *logging.Logger) error {
	args := []string{
		cfg.Paths.MihomoBin,
		"-d", cfg.Paths.MihomoData,
		"-f", cfg.Paths.MihomoConfigFile,
	}

	log.Debugf("exec: %v", args)

	if err := syscallExec(cfg.Paths.MihomoBin, args, config.FilterEnviron(os.Environ())); err != nil {
		return fmt.Errorf("exec mihomo: %w", err)
	}
	return nil
}
