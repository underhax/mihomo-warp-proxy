// Package usermode handles the three container startup modes and the
// privilege-drop mechanism to run unprivileged UID:GID processes.
package usermode

import (
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/contract"
	"github.com/underhax/mihomo-warp-proxy/internal/fsutil"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
)

var knownFiles = []string{
	"config.yaml",
	"config.yaml.back",
	"cache.db",
	"geoip.dat",
	"geosite.dat",
	"geoip.metadb",
	"GeoLite2-ASN.mmdb",
}

var knownDirs = []string{
	".cache",
}

var knownWgcfFiles = []string{
	"wgcf-account.toml",
	"wgcf-profile.conf",
}

var (
	getuid       = os.Getuid
	getgid       = os.Getgid
	osLchown     = os.Lchown
	syscallExec  = syscall.Exec
	strconvAtoi  = strconv.Atoi
	osStat       = os.Stat
	osExecutable = os.Executable
	execLookPath = exec.LookPath
)

// Dispatch selects and executes the appropriate startup branch based on UID,
// multi-user mode, and whether execution was already re-execed by su-exec.
func Dispatch(cfg *config.Config, reexec bool, log *logging.Logger) error {
	if reexec {
		return nil
	}

	if getuid() == 0 {
		return rootBranch(cfg, log)
	}

	if cfg.MultiUserMode {
		return nonRootMultiUser(cfg, log)
	}

	return nonRootLegacy(log)
}

func rootBranch(cfg *config.Config, log *logging.Logger) error {
	log.Debugf("usermode: running as root, will drop to %d:%d", cfg.ProxyUID, cfg.ProxyGID)

	if err := prepareDirectories(cfg, log); err != nil {
		return err
	}

	if isDirOwnedBy(cfg.Paths.MihomoData, cfg.ProxyUID, cfg.ProxyGID) {
		log.Debugf("usermode: %s already owned by %d:%d — skipping chown, re-execing",
			cfg.Paths.MihomoData, cfg.ProxyUID, cfg.ProxyGID)
	} else {
		if err := chownImageDirs(cfg, log); err != nil {
			return err
		}
	}

	return reexecAsUser(cfg, log)
}

func nonRootMultiUser(cfg *config.Config, log *logging.Logger) error {
	uid := getuid()
	gid := getgid()

	if uid < 0 || int64(uid) > math.MaxUint32 || gid < 0 || int64(gid) > math.MaxUint32 {
		return fmt.Errorf("usermode: UID %d or GID %d is out of bounds for uint32", uid, gid)
	}
	log.Debugf("usermode: multi-user mode, running as %d:%d", uid, gid)

	if _, err := osStat(cfg.Paths.MihomoData); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("usermode: %s does not exist — mount the volume or run as root first", cfg.Paths.MihomoData)
		}
		return fmt.Errorf("usermode: stat %s: %w", cfg.Paths.MihomoData, err)
	}
	if _, err := osStat(cfg.Paths.WgcfData); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("usermode: %s does not exist — mount the volume or run as root first", cfg.Paths.WgcfData)
		}
		return fmt.Errorf("usermode: stat %s: %w", cfg.Paths.WgcfData, err)
	}

	if !fsutil.IsDirWritable(cfg.Paths.MihomoData) {
		return fmt.Errorf("usermode: no write access to %s — ensure the directory is owned by %d:%d",
			cfg.Paths.MihomoData, uid, gid)
	}
	if !fsutil.IsDirWritable(cfg.Paths.WgcfData) {
		return fmt.Errorf("usermode: no write access to %s — ensure the directory is owned by %d:%d",
			cfg.Paths.WgcfData, uid, gid)
	}

	cfg.ProxyUID = uint32(uid)
	cfg.ProxyGID = uint32(gid)
	return nil
}

func nonRootLegacy(log *logging.Logger) error {
	uid := getuid()
	gid := getgid()

	if uid == 911 && gid == 911 {
		log.Debug("usermode: running as 911:911 (legacy mode)")
		return nil
	}

	return fmt.Errorf(
		"usermode: container started as %d:%d which is not allowed in legacy mode.\n"+
			"Allowed options:\n"+
			"  1) Run as root (no --user flag) — entrypoint drops privileges automatically\n"+
			"  2) Run as --user=911:911\n"+
			"  3) Set MULTI_USER_MODE=true to allow any UID:GID",
		uid, gid,
	)
}

func prepareDirectories(cfg *config.Config, log *logging.Logger) error {
	for _, dir := range []string{cfg.Paths.MihomoData, cfg.Paths.WgcfData} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("usermode: mkdir %s: %w", dir, err)
		}
		log.Debugf("usermode: ensured directory %s", dir)
	}
	return nil
}

func chownImageDirs(cfg *config.Config, log *logging.Logger) error {
	uid, gid, err := uidGIDToInt(cfg.ProxyUID, cfg.ProxyGID)
	if err != nil {
		return err
	}

	log.Debugf("usermode: setting ownership of image directories to %d:%d", uid, gid)

	for _, dir := range []string{cfg.Paths.MihomoData, cfg.Paths.WgcfData} {
		if err := osLchown(dir, uid, gid); err != nil {
			return fmt.Errorf("usermode: chown %s: %w", dir, err)
		}
	}

	for _, name := range knownFiles {
		path := cfg.Paths.MihomoData + "/" + name
		if _, err := os.Lstat(path); err == nil {
			if err := osLchown(path, uid, gid); err != nil {
				log.Warnf("usermode: chown %s: %v", path, err)
			}
		}
	}

	for _, name := range knownDirs {
		path := cfg.Paths.MihomoData + "/" + name
		if err := chownDirRecursive(path, uid, gid); err != nil {
			log.Warnf("usermode: chown %s: %v", path, err)
		}
	}

	for _, name := range knownWgcfFiles {
		path := cfg.Paths.WgcfData + "/" + name
		if _, err := os.Lstat(path); err == nil {
			if err := osLchown(path, uid, gid); err != nil {
				log.Warnf("usermode: chown %s: %v", path, err)
			}
		}
	}

	return nil
}

func uidGIDToInt(uid, gid uint32) (intUID, intGID int, err error) {
	intUID, err = uint32ToInt(uid)
	if err != nil {
		return 0, 0, fmt.Errorf("usermode: UID %d is out of bounds for int: %w", uid, err)
	}

	intGID, err = uint32ToInt(gid)
	if err != nil {
		return 0, 0, fmt.Errorf("usermode: GID %d is out of bounds for int: %w", gid, err)
	}

	return intUID, intGID, nil
}

func uint32ToInt(value uint32) (int, error) {
	converted, err := strconvAtoi(strconv.FormatUint(uint64(value), 10))
	if err != nil {
		return 0, fmt.Errorf("convert uint32 to int: %w", err)
	}
	return converted, nil
}

func reexecAsUser(cfg *config.Config, log *logging.Logger) error {
	self, err := osExecutable()
	if err != nil {
		return fmt.Errorf("usermode: resolve executable path: %w", err)
	}

	suExec, err := execLookPath(cfg.Paths.SuExecBin)
	if err != nil {
		if _, statErr := osStat(cfg.Paths.SuExecBin); statErr != nil {
			return fmt.Errorf("usermode: su-exec not found at %s: %w", cfg.Paths.SuExecBin, err)
		}
		suExec = cfg.Paths.SuExecBin
	}

	uidGid := fmt.Sprintf("%d:%d", cfg.ProxyUID, cfg.ProxyGID)
	args := []string{suExec, uidGid, self, contract.FlagRunAsUser}

	log.Debugf("usermode: re-execing as %s via su-exec", uidGid)

	if err := syscallExec(suExec, args, config.FilterEnviron(os.Environ())); err != nil {
		return fmt.Errorf("usermode: syscall.Exec failed: %w", err)
	}
	return nil
}

func chownDirRecursive(dir string, uid, gid int) error {
	err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr == nil {
			return osLchown(path, uid, gid)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("usermode: chown recursive %s: %w", dir, err)
	}
	return nil
}
