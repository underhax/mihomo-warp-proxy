// Package logging provides a leveled structured logger for the container entrypoint process.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/underhax/mihomo-warp-proxy/internal/contract"
)

// Level aliases slog.Level to standardize project-wide log verbosity controls.
type Level = slog.Level

// Severity levels mapping project logging contracts to standard slog tiers.
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

type recordFormatter interface {
	formatRecord(r slog.Record) error
}

// Logger provides thread-safe structured diagnostic logging with process and build metadata.
type Logger struct {
	handler recordFormatter
	version string
	level   slog.Level
	pid     int
}

type logHandler struct {
	version string
	level   slog.Level
	pid     int
}

func (h *logHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func defaultLogWriter() io.Writer {
	return os.Stderr
}

var logWriter = defaultLogWriter

func (h *logHandler) formatRecord(r slog.Record) error {
	ts := r.Time.UTC().Format("2006-01-02T15:04:05Z")
	levelStr := levelName(r.Level)

	msg := strings.ReplaceAll(r.Message, "\r", "")
	msg = strings.ReplaceAll(msg, "\n", " | ")

	line := fmt.Sprintf("%s [%s] [%d] %s (v%s)\n",
		ts, levelStr, h.pid, msg, h.version)

	_, err := io.WriteString(logWriter(), line)
	if err != nil {
		return fmt.Errorf("write log line: %w", err)
	}
	return nil
}

func (h *logHandler) Handle(_ context.Context, r slog.Record) error {
	return h.formatRecord(r)
}

func (h *logHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *logHandler) WithGroup(_ string) slog.Handler      { return h }

func levelName(l slog.Level) string {
	switch l {
	case slog.LevelDebug:
		return contract.LogLevelDebug
	case slog.LevelInfo:
		return contract.LogLevelInfo
	case slog.LevelWarn:
		return contract.LogLevelWarn
	case slog.LevelError:
		return contract.LogLevelError
	default:
		return contract.LogLevelInfo
	}
}

// ParseLevel maps configured log level strings to slog.Level to enforce runtime verbosity thresholds.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case contract.LogLevelDebug:
		return LevelDebug, nil
	case contract.LogLevelInfo:
		return LevelInfo, nil
	case contract.LogLevelWarn, "WARNING":
		return LevelWarn, nil
	case contract.LogLevelError:
		return LevelError, nil
	default:
		return LevelWarn, fmt.Errorf("unrecognised %s %q: accepted values are %s, %s, %s, %s",
			contract.EnvScriptLogLevel,
			s,
			contract.LogLevelDebug,
			contract.LogLevelInfo,
			contract.LogLevelWarn,
			contract.LogLevelError,
		)
	}
}

// New constructs a Logger instance configured to tag records with build version and process ID.
func New(level slog.Level, version string) *Logger {
	h := &logHandler{
		level:   level,
		pid:     os.Getpid(),
		version: version,
	}
	return &Logger{
		handler: h,
		level:   level,
		pid:     os.Getpid(),
		version: version,
	}
}

func (l *Logger) log(level slog.Level, msg string) {
	if level < l.level {
		return
	}
	r := slog.NewRecord(time.Now(), level, msg, 0)
	if err := l.handler.formatRecord(r); err != nil {
		return
	}
}

// Debug emits diagnostic information for local troubleshooting and verbose tracing.
func (l *Logger) Debug(msg string) { l.log(LevelDebug, msg) }

// Debugf formats and emits diagnostic information for detailed troubleshooting.
func (l *Logger) Debugf(format string, args ...any) {
	l.log(LevelDebug, fmt.Sprintf(format, args...))
}

// Info emits routine operational progress events during initialization.
func (l *Logger) Info(msg string) { l.log(LevelInfo, msg) }

// Infof formats and emits routine operational progress events during initialization.
func (l *Logger) Infof(format string, args ...any) {
	l.log(LevelInfo, fmt.Sprintf(format, args...))
}

// Warn emits non-fatal conditions that warrant operator attention.
func (l *Logger) Warn(msg string) { l.log(LevelWarn, msg) }

// Warnf formats and emits non-fatal conditions that warrant operator attention.
func (l *Logger) Warnf(format string, args ...any) {
	l.log(LevelWarn, fmt.Sprintf(format, args...))
}

// Error emits failure events requiring intervention or preceding termination.
func (l *Logger) Error(msg string) { l.log(LevelError, msg) }

// Errorf formats and emits failure events requiring intervention.
func (l *Logger) Errorf(format string, args ...any) {
	l.log(LevelError, fmt.Sprintf(format, args...))
}

var osExit = os.Exit

// Fatal records an unrecoverable failure message and halts container initialization with exit code 1.
func (l *Logger) Fatal(msg string) {
	l.log(LevelError, msg)
	osExit(1)
}

// Fatalf formats and records an unrecoverable failure message before halting the process.
func (l *Logger) Fatalf(format string, args ...any) {
	l.log(LevelError, fmt.Sprintf(format, args...))
	osExit(1)
}
