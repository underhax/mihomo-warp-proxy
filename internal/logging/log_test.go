package logging

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/underhax/mihomo-warp-proxy/internal/contract"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		input   string
		want    Level
		wantErr bool
	}{
		{contract.LogLevelDebug, LevelDebug, false},
		{"debug", LevelDebug, false},
		{contract.LogLevelInfo, LevelInfo, false},
		{contract.LogLevelWarn, LevelWarn, false},
		{"WARNING", LevelWarn, false},
		{contract.LogLevelError, LevelError, false},
		{"  " + contract.LogLevelWarn + "  ", LevelWarn, false},
		{"", LevelWarn, true},
		{"VERBOSE", LevelWarn, true},
		{"TRACE", LevelWarn, true},
	}

	for _, tc := range cases {
		got, err := ParseLevel(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseLevel(%q): expected error, got nil", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLevel(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseLevel(%q): got %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	logger := New(LevelWarn, "test")
	logger.Debug("this should not appear")
	logger.Info("this should not appear either")
	logger.Warn("this should appear")

	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	os.Stderr = origStderr

	buf := make([]byte, 4096)
	n, readErr := r.Read(buf)
	if readErr != nil {
		t.Fatal(readErr)
	}
	output := string(buf[:n])

	if strings.Contains(output, "this should not appear") {
		t.Errorf("DEBUG/INFO message leaked through WARN-level logger: %q", output)
	}
	if !strings.Contains(output, "this should appear") {
		t.Errorf("WARN message missing from output: %q", output)
	}
}

func TestLogOutputFormat(t *testing.T) {
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	logger := New(LevelDebug, "9.9.9")
	logger.Info("hello world")

	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	os.Stderr = origStderr

	buf := make([]byte, 4096)
	n, readErr := r.Read(buf)
	if readErr != nil {
		t.Fatal(readErr)
	}
	line := string(buf[:n])

	if !strings.Contains(line, "[INFO]") {
		t.Errorf("missing level in output: %q", line)
	}
	if !strings.Contains(line, "hello world") {
		t.Errorf("missing message in output: %q", line)
	}
	if !strings.Contains(line, "(v9.9.9)") {
		t.Errorf("missing version in output: %q", line)
	}
	if !strings.Contains(line, "T") || !strings.Contains(line, "Z") {
		t.Errorf("timestamp format unexpected in output: %q", line)
	}
}

func TestLoggerMethods(t *testing.T) {
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	logger := New(LevelDebug, "1.0.0")

	logger.Debugf("debug formatted %d", 1)
	logger.Infof("info formatted %s", "two")
	logger.Warnf("warn formatted %s", "three")
	logger.Error("error plain")
	logger.Errorf("error formatted %s", "five")

	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	os.Stderr = origStderr

	buf := make([]byte, 8192)
	n, readErr := r.Read(buf)
	if readErr != nil {
		t.Fatal(readErr)
	}
	output := string(buf[:n])

	for _, expected := range []string{
		"debug formatted 1",
		"info formatted two",
		"warn formatted three",
		"error plain",
		"error formatted five",
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("missing expected output %q in: %s", expected, output)
		}
	}
}

func TestLoggerFatal(t *testing.T) {
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	origExit := osExit
	var exitCode int
	osExit = func(code int) {
		exitCode = code
	}
	t.Cleanup(func() {
		osExit = origExit
		os.Stderr = origStderr
	})

	logger := New(LevelDebug, "1.0.0")
	logger.Fatal("fatal message")

	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	buf := make([]byte, 1024)
	n, readErr := r.Read(buf)
	if readErr != nil {
		t.Fatal(readErr)
	}
	output := string(buf[:n])

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(output, "fatal message") {
		t.Errorf("missing message in output: %q", output)
	}
}

func TestLoggerFatalf(t *testing.T) {
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	origExit := osExit
	var exitCode int
	osExit = func(code int) {
		exitCode = code
	}
	t.Cleanup(func() {
		osExit = origExit
		os.Stderr = origStderr
	})

	logger := New(LevelDebug, "1.0.0")
	logger.Fatalf("fatal format %d", 123)

	if closeErr := w.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	buf := make([]byte, 1024)
	n, readErr := r.Read(buf)
	if readErr != nil {
		t.Fatal(readErr)
	}
	output := string(buf[:n])

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(output, "fatal format 123") {
		t.Errorf("missing message in output: %q", output)
	}
}

func TestLogHandlerMethods(t *testing.T) {
	h := &logHandler{}
	if h.WithAttrs(nil) != h {
		t.Errorf("expected WithAttrs to return same handler")
	}
	if h.WithGroup("test") != h {
		t.Errorf("expected WithGroup to return same handler")
	}
	h.level = LevelInfo
	if !h.Enabled(context.Background(), LevelInfo) {
		t.Errorf("expected Enabled to be true for LevelInfo")
	}
	if h.Enabled(context.Background(), LevelDebug) {
		t.Errorf("expected Enabled to be false for LevelDebug")
	}
}

func TestLevelNameDefault(t *testing.T) {
	if got := levelName(slog.Level(99)); got != contract.LogLevelInfo {
		t.Errorf("expected %s, got %s", contract.LogLevelInfo, got)
	}
}

type mockFailingLogHandler struct {
	slog.Handler
}

func (f *mockFailingLogHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (f *mockFailingLogHandler) Handle(_ context.Context, _ slog.Record) error {
	return errors.New("handler failure")
}

func (f *mockFailingLogHandler) formatRecord(_ slog.Record) error {
	return errors.New("handler failure")
}

func (f *mockFailingLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return f }
func (f *mockFailingLogHandler) WithGroup(_ string) slog.Handler      { return f }

func TestLoggerHandleError(_ *testing.T) {
	l := &Logger{
		handler: &mockFailingLogHandler{},
		version: "test",
	}
	l.Info("message that triggers handler error")
}

type errWriter struct{}

func (errWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write failure")
}

func TestLogHandlerWriteError(t *testing.T) {
	origWriter := logWriter
	defer func() { logWriter = origWriter }()
	logWriter = func() io.Writer { return errWriter{} }

	h := &logHandler{level: LevelInfo, version: "test"}
	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "test message", 0)
	if err := h.Handle(context.Background(), rec); err == nil {
		t.Error("expected write error, got nil")
	}
}
