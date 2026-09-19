package usermode

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/fsutil"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
)

var testLog = logging.New(logging.LevelDebug, "test")

func testCfg(mihomoData, wgcfData string) *config.Config {
	return &config.Config{
		ProxyUID:      911,
		ProxyGID:      911,
		MultiUserMode: true,
		Paths: config.Paths{
			MihomoData:       mihomoData,
			WgcfData:         wgcfData,
			SuExecBin:        "/sbin/su-exec",
			MihomoConfigFile: mihomoData + "/config.yaml",
		},
	}
}

func TestNonRootLegacyWrongUID(t *testing.T) {
	uid := os.Getuid()
	gid := os.Getgid()
	if uid == 911 && gid == 911 {
		t.Skip("test process is already 911:911")
	}

	err := nonRootLegacy(testLog)
	if err == nil {
		t.Error("expected error for non-911:911 uid in legacy mode, got nil")
	}
}

func TestNonRootMultiUserMissingDir(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg(dir+"/mihomo", dir+"/wgcf")

	err := nonRootMultiUser(cfg, testLog)
	if err == nil {
		t.Error("expected error when MihomoData does not exist, got nil")
	}
}

func TestNonRootMultiUserWritable(t *testing.T) {
	dir := t.TempDir()
	mihomoData := dir + "/mihomo"
	wgcfData := dir + "/wgcf"

	if err := os.MkdirAll(mihomoData, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wgcfData, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := testCfg(mihomoData, wgcfData)

	if err := nonRootMultiUser(cfg, testLog); err != nil {
		t.Errorf("unexpected error for writable dirs: %v", err)
	}

	if int(cfg.ProxyUID) != os.Getuid() {
		t.Errorf("ProxyUID not updated: got %d, want %d", cfg.ProxyUID, os.Getuid())
	}
	if int(cfg.ProxyGID) != os.Getgid() {
		t.Errorf("ProxyGID not updated: got %d, want %d", cfg.ProxyGID, os.Getgid())
	}
}

func TestIsDirWritable(t *testing.T) {
	dir := t.TempDir()
	if !fsutil.IsDirWritable(dir) {
		t.Error("temp dir should be writable")
	}
	if fsutil.IsDirWritable("/proc/1") {
		t.Error("/proc/1 should not be writable")
	}
}

func TestUIDGIDToInt(t *testing.T) {
	uid, gid, err := uidGIDToInt(911, 912)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uid != 911 || gid != 912 {
		t.Fatalf("got %d:%d, want 911:912", uid, gid)
	}

	_, _, err = uidGIDToInt(uint32(math.MaxInt32)+1, 912)
	if strconv.IntSize == 32 && err == nil {
		t.Fatal("expected error for UID outside int range")
	}
	if strconv.IntSize == 64 && err != nil {
		t.Fatalf("unexpected error on 64-bit int: %v", err)
	}
}

func TestDispatchReexecSkipsAllBranches(t *testing.T) {
	cfg := testCfg(t.TempDir(), t.TempDir())
	if err := Dispatch(cfg, true, testLog); err != nil {
		t.Errorf("Dispatch with reexec=true returned error: %v", err)
	}
}

func TestPrepareDirectories(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg(dir+"/mihomo", dir+"/wgcf")
	if err := prepareDirectories(cfg, testLog); err != nil {
		t.Fatalf("prepareDirectories failed: %v", err)
	}
	if info, err := os.Stat(cfg.Paths.MihomoData); err != nil || !info.IsDir() {
		t.Error("MihomoData directory was not created")
	}
	if info, err := os.Stat(cfg.Paths.WgcfData); err != nil || !info.IsDir() {
		t.Error("WgcfData directory was not created")
	}
}

func TestChownDirRecursive(t *testing.T) {
	dir := t.TempDir()
	sub := dir + "/sub"
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	file := sub + "/file.txt"
	if err := os.WriteFile(file, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := chownDirRecursive(dir, os.Getuid(), os.Getgid()); err != nil {
		t.Errorf("chownDirRecursive failed: %v", err)
	}
}

func TestDispatchNonRootBranches(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping non-root dispatch tests when running as root")
	}
	dir := t.TempDir()
	mihomoData := dir + "/mihomo"
	wgcfData := dir + "/wgcf"
	if err := os.MkdirAll(mihomoData, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wgcfData, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := testCfg(mihomoData, wgcfData)
	cfg.MultiUserMode = true
	if err := Dispatch(cfg, false, testLog); err != nil {
		t.Errorf("Dispatch multi-user failed: %v", err)
	}

	cfg.MultiUserMode = false
	if os.Getuid() != 911 {
		if err := Dispatch(cfg, false, testLog); err == nil {
			t.Error("expected legacy dispatch error for non-911 user, got nil")
		}
	}
}

func TestDispatchRoot(t *testing.T) {
	origUID := getuid
	origGID := getgid
	origExec := syscallExec
	origLchown := osLchown
	getuid = func() int { return 0 }
	getgid = func() int { return 0 }
	osLchown = func(_ string, _, _ int) error {
		return nil
	}
	var executed bool
	syscallExec = func(_ string, _, _ []string) error {
		executed = true
		return nil
	}
	t.Cleanup(func() {
		getuid = origUID
		getgid = origGID
		syscallExec = origExec
		osLchown = origLchown
	})

	dir := t.TempDir()
	cfg := testCfg(dir+"/mihomo", dir+"/wgcf")
	cfg.Paths.SuExecBin = "/bin/sh"

	if err := Dispatch(cfg, false, testLog); err != nil {
		t.Fatalf("Dispatch returned error: %v", err)
	}
	if !executed {
		t.Errorf("expected syscallExec to be invoked in root branch")
	}
}

func TestDispatchLegacyAllowed(t *testing.T) {
	origUID := getuid
	origGID := getgid
	getuid = func() int { return 911 }
	getgid = func() int { return 911 }
	t.Cleanup(func() {
		getuid = origUID
		getgid = origGID
	})

	cfg := testCfg(t.TempDir(), t.TempDir())
	cfg.MultiUserMode = false

	if err := Dispatch(cfg, false, testLog); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRootBranchAlreadyOwned(t *testing.T) {
	origExec := syscallExec
	var execArgs []string
	syscallExec = func(_ string, argv, _ []string) error {
		execArgs = argv
		return nil
	}
	t.Cleanup(func() {
		syscallExec = origExec
	})

	dir := t.TempDir()
	cfg := testCfg(dir+"/mihomo", dir+"/wgcf")
	cfg.Paths.SuExecBin = "/bin/sh"

	if err := prepareDirectories(cfg, testLog); err != nil {
		t.Fatal(err)
	}

	u := os.Getuid()
	if u >= 0 && int64(u) <= math.MaxUint32 {
		cfg.ProxyUID = uint32(u)
	}
	g := os.Getgid()
	if g >= 0 && int64(g) <= math.MaxUint32 {
		cfg.ProxyGID = uint32(g)
	}

	if err := rootBranch(cfg, testLog); err != nil {
		t.Fatalf("rootBranch failed: %v", err)
	}
	if len(execArgs) == 0 {
		t.Errorf("expected execArgs to be populated")
	}
}

func TestRootBranchChownError(t *testing.T) {
	origLchown := osLchown
	osLchown = func(_ string, _, _ int) error {
		return errors.New("chown forbidden")
	}
	t.Cleanup(func() {
		osLchown = origLchown
	})

	dir := t.TempDir()
	cfg := testCfg(dir+"/mihomo", dir+"/wgcf")
	cfg.ProxyUID = 12345
	cfg.ProxyGID = 12345

	err := rootBranch(cfg, testLog)
	if err == nil || !strings.Contains(err.Error(), "chown forbidden") {
		t.Fatalf("expected chown forbidden error, got: %v", err)
	}
}

func TestChownImageDirsAllKnownFiles(t *testing.T) {
	dir := t.TempDir()
	mihomoData := filepath.Join(dir, "mihomo")
	wgcfData := filepath.Join(dir, "wgcf")
	if err := os.MkdirAll(mihomoData, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wgcfData, 0o750); err != nil {
		t.Fatal(err)
	}

	content := []byte("dummy")
	for _, name := range knownFiles {
		if err := os.WriteFile(filepath.Join(mihomoData, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range knownDirs {
		d := filepath.Join(mihomoData, name)
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "item"), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range knownWgcfFiles {
		if err := os.WriteFile(filepath.Join(wgcfData, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var chowned []string
	origLchown := osLchown
	osLchown = func(name string, _, _ int) error {
		chowned = append(chowned, name)
		return nil
	}
	t.Cleanup(func() {
		osLchown = origLchown
	})

	cfg := testCfg(mihomoData, wgcfData)
	if err := chownImageDirs(cfg, testLog); err != nil {
		t.Fatalf("chownImageDirs failed: %v", err)
	}
	if len(chowned) < len(knownFiles)+len(knownWgcfFiles)+2 {
		t.Errorf("chowned count too low: %d", len(chowned))
	}
}

func TestChownImageDirsWarnOnLchownError(t *testing.T) {
	dir := t.TempDir()
	mihomoData := filepath.Join(dir, "mihomo")
	wgcfData := filepath.Join(dir, "wgcf")
	if err := os.MkdirAll(mihomoData, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(wgcfData, 0o750); err != nil {
		t.Fatal(err)
	}

	content := []byte("dummy")
	for _, name := range knownFiles {
		if err := os.WriteFile(filepath.Join(mihomoData, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range knownDirs {
		if err := os.MkdirAll(filepath.Join(mihomoData, name), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range knownWgcfFiles {
		if err := os.WriteFile(filepath.Join(wgcfData, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	origLchown := osLchown
	osLchown = func(name string, _, _ int) error {
		if name == mihomoData || name == wgcfData {
			return nil
		}
		return errors.New("warning chown failed")
	}
	t.Cleanup(func() {
		osLchown = origLchown
	})

	cfg := testCfg(mihomoData, wgcfData)
	if err := chownImageDirs(cfg, testLog); err != nil {
		t.Fatalf("chownImageDirs should succeed with warnings, got: %v", err)
	}
}

func TestReexecAsUserErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg(dir+"/mihomo", dir+"/wgcf")
	cfg.Paths.SuExecBin = filepath.Join(dir, "nonexistent-suexec")

	err := reexecAsUser(cfg, testLog)
	if err == nil || !strings.Contains(err.Error(), "su-exec not found") {
		t.Fatalf("expected su-exec not found error, got: %v", err)
	}

	fakeSuExec := filepath.Join(dir, "fake-suexec")
	if writeErr := os.WriteFile(fakeSuExec, []byte("#!/bin/sh\n"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	cfg.Paths.SuExecBin = fakeSuExec

	origExec := syscallExec
	syscallExec = func(_ string, _, _ []string) error {
		return errors.New("syscall exec mock error")
	}
	t.Cleanup(func() {
		syscallExec = origExec
	})

	err = reexecAsUser(cfg, testLog)
	if err == nil || !strings.Contains(err.Error(), "syscall exec mock error") {
		t.Fatalf("expected syscall exec error, got: %v", err)
	}
}

func TestNonRootMultiUserBoundErrors(t *testing.T) {
	origUID := getuid
	getuid = func() int { return -1 }
	t.Cleanup(func() {
		getuid = origUID
	})

	cfg := testCfg(t.TempDir(), t.TempDir())
	err := nonRootMultiUser(cfg, testLog)
	if err == nil || !strings.Contains(err.Error(), "out of bounds") {
		t.Fatalf("expected out of bounds error, got: %v", err)
	}
}

func TestNonRootMultiUserWgcfMissing(t *testing.T) {
	dir := t.TempDir()
	mihomoData := filepath.Join(dir, "mihomo")
	if err := os.MkdirAll(mihomoData, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := testCfg(mihomoData, filepath.Join(dir, "nonexistent-wgcf"))

	err := nonRootMultiUser(cfg, testLog)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected wgcf does not exist error, got: %v", err)
	}
}

func TestUint32ToIntError(t *testing.T) {
	origAtoi := strconvAtoi
	defer func() { strconvAtoi = origAtoi }()
	strconvAtoi = func(_ string) (int, error) {
		return 0, errors.New("mock atoi failure")
	}

	if _, err := uint32ToInt(123); err == nil {
		t.Error("expected error from uint32ToInt when atoi fails, got nil")
	}
	if _, _, err := uidGIDToInt(123, 456); err == nil {
		t.Error("expected error from uidGIDToInt on uid failure, got nil")
	}
}

func TestUidGIDToIntGidError(t *testing.T) {
	origAtoi := strconvAtoi
	defer func() { strconvAtoi = origAtoi }()
	callCount := 0
	strconvAtoi = func(_ string) (int, error) {
		callCount++
		if callCount == 2 {
			return 0, errors.New("mock gid failure")
		}
		return 100, nil
	}

	if _, _, err := uidGIDToInt(123, 456); err == nil {
		t.Error("expected error from uidGIDToInt on gid failure, got nil")
	}
}

func TestPrepareDirectoriesError(t *testing.T) {
	cfg := &config.Config{
		Paths: config.Paths{
			MihomoData: "/proc/forbidden/dir",
			WgcfData:   "/proc/forbidden/dir2",
		},
	}
	err := prepareDirectories(cfg, testLog)
	if err == nil {
		t.Error("expected error creating forbidden directory, got nil")
	}
}

func TestNonRootMultiUserWgcfNotWritable(t *testing.T) {
	dir := t.TempDir()
	mihomoData := filepath.Join(dir, "mihomo")
	if err := os.MkdirAll(mihomoData, 0o750); err != nil {
		t.Fatal(err)
	}
	wgcfData := filepath.Join(dir, "wgcf")
	if err := os.WriteFile(wgcfData, []byte("not_a_dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testCfg(mihomoData, wgcfData)
	err := nonRootMultiUser(cfg, testLog)
	if err == nil || !strings.Contains(err.Error(), "no write access to") {
		t.Errorf("expected no write access error, got: %v", err)
	}
}

func TestRootBranchPrepareDirectoriesError(t *testing.T) {
	cfg := &config.Config{
		Paths: config.Paths{
			MihomoData: "/proc/forbidden/dir",
			WgcfData:   "/proc/forbidden/dir2",
		},
	}
	if err := rootBranch(cfg, testLog); err == nil {
		t.Error("expected error from rootBranch when prepareDirectories fails, got nil")
	}
}

func TestNonRootMultiUserStatErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := testCfg(filepath.Join(dir, "mihomo"), filepath.Join(dir, "wgcf"))

	origStat := osStat
	defer func() { osStat = origStat }()

	osStat = func(path string) (os.FileInfo, error) {
		if strings.Contains(path, "mihomo") {
			return nil, errors.New("mock stat mihomo error")
		}
		return nil, os.ErrNotExist
	}

	if err := nonRootMultiUser(cfg, testLog); err == nil || !strings.Contains(err.Error(), "mock stat mihomo error") {
		t.Errorf("expected mihomo stat error, got: %v", err)
	}

	osStat = func(path string) (os.FileInfo, error) {
		if strings.Contains(path, "mihomo") {
			return origStat(dir)
		}
		return nil, errors.New("mock stat wgcf error")
	}

	if err := nonRootMultiUser(cfg, testLog); err == nil || !strings.Contains(err.Error(), "mock stat wgcf error") {
		t.Errorf("expected wgcf stat error, got: %v", err)
	}
}

func TestReexecAsUserExecutableError(t *testing.T) {
	origExec := osExecutable
	defer func() { osExecutable = origExec }()
	osExecutable = func() (string, error) {
		return "", errors.New("mock executable failure")
	}

	cfg := &config.Config{}
	if err := reexecAsUser(cfg, testLog); err == nil {
		t.Error("expected error when osExecutable fails, got nil")
	}
}

func TestReexecAsUserLookPathFallback(t *testing.T) {
	dir := t.TempDir()
	suExecFile := filepath.Join(dir, "su-exec")
	if err := os.WriteFile(suExecFile, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	origLook := execLookPath
	origSyscall := syscallExec
	defer func() {
		execLookPath = origLook
		syscallExec = origSyscall
	}()

	execLookPath = func(_ string) (string, error) {
		return "", errors.New("lookpath not found")
	}
	var calledBin string
	syscallExec = func(argv0 string, _, _ []string) error {
		calledBin = argv0
		return nil
	}

	cfg := &config.Config{
		Paths: config.Paths{
			SuExecBin: suExecFile,
		},
	}
	if err := reexecAsUser(cfg, testLog); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calledBin != suExecFile {
		t.Errorf("expected su-exec fallback %s, got %s", suExecFile, calledBin)
	}
}

func TestChownImageDirsUidGidToIntError(t *testing.T) {
	origAtoi := strconvAtoi
	defer func() { strconvAtoi = origAtoi }()
	strconvAtoi = func(_ string) (int, error) {
		return 0, errors.New("mock atoi failure")
	}

	cfg := &config.Config{
		ProxyUID: 911,
		ProxyGID: 911,
	}
	if err := chownImageDirs(cfg, testLog); err == nil {
		t.Error("expected error from chownImageDirs when uidGIDToInt fails, got nil")
	}
}

func TestNonRootMultiUserMihomoNotWritable(t *testing.T) {
	dir := t.TempDir()
	mihomoData := filepath.Join(dir, "mihomo")
	if err := os.WriteFile(mihomoData, []byte("not_a_dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	wgcfData := filepath.Join(dir, "wgcf")
	if err := os.MkdirAll(wgcfData, 0o750); err != nil {
		t.Fatal(err)
	}

	cfg := testCfg(mihomoData, wgcfData)
	err := nonRootMultiUser(cfg, testLog)
	if err == nil || !strings.Contains(err.Error(), "no write access to") {
		t.Errorf("expected no write access error for mihomo, got: %v", err)
	}
}
