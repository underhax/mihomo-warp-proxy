package warp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/underhax/mihomo-warp-proxy/internal/logging"
)

func TestDecodeClientID(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    [3]byte
		wantErr bool
	}{
		{
			name:  "standard base64 three bytes",
			input: base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03}),
			want:  [3]byte{0x01, 0x02, 0x03},
		},
		{
			name:  "url-safe base64 without padding",
			input: base64.RawURLEncoding.EncodeToString([]byte{0xAB, 0xCD, 0xEF}),
			want:  [3]byte{0xAB, 0xCD, 0xEF},
		},
		{
			name:  "zero bytes",
			input: base64.StdEncoding.EncodeToString([]byte{0x00, 0x00, 0x00}),
			want:  [3]byte{0x00, 0x00, 0x00},
		},
		{
			name:    "too few bytes (2)",
			input:   base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}),
			wantErr: true,
		},
		{
			name:    "too many bytes (4)",
			input:   base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04}),
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			input:   "!!!notbase64!!!",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeClientID(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (result: %v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func mockErrFileClose(f *os.File) error {
	if err := f.Close(); err != nil {
		return err
	}
	return errors.New("simulated file close failure")
}

func mockErrFileReadAll(_ io.Reader) ([]byte, error) {
	return nil, errors.New("simulated file read failure")
}

func TestParseAccountFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid file", func(t *testing.T) {
		content := `
account_id = "test-account"
access_token = "my-access-token"
device_id = "abcdef01-1234-5678-abcd-ef0123456789"
license_key = ""
`
		path := filepath.Join(dir, "valid.toml")
		writeFile(t, path, content, 0o600)

		fields, err := parseAccountFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fields.AccessToken != "my-access-token" {
			t.Errorf("AccessToken: got %q", fields.AccessToken)
		}
		if fields.DeviceID != "abcdef01-1234-5678-abcd-ef0123456789" {
			t.Errorf("DeviceID: got %q", fields.DeviceID)
		}
	})

	t.Run("quoted values stripped", func(t *testing.T) {
		content := `access_token = "token-with-quotes"` + "\n" +
			`device_id = "dev-id-123"` + "\n"
		path := filepath.Join(dir, "quoted.toml")
		writeFile(t, path, content, 0o600)

		fields, err := parseAccountFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fields.AccessToken != "token-with-quotes" {
			t.Errorf("quotes not stripped from AccessToken: %q", fields.AccessToken)
		}
	})

	t.Run("missing access_token", func(t *testing.T) {
		content := `device_id = "abc123"` + "\n"
		path := filepath.Join(dir, "no_token.toml")
		writeFile(t, path, content, 0o600)

		_, err := parseAccountFile(path)
		if err == nil {
			t.Error("expected error for missing access_token, got nil")
		}
	})

	t.Run("missing device_id", func(t *testing.T) {
		content := `access_token = "token"` + "\n"
		path := filepath.Join(dir, "no_device.toml")
		writeFile(t, path, content, 0o600)

		_, err := parseAccountFile(path)
		if err == nil {
			t.Error("expected error for missing device_id, got nil")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := parseAccountFile(filepath.Join(dir, "missing.toml"))
		if err == nil {
			t.Error("expected error for missing file, got nil")
		}
	})

	t.Run("line without equals ignored", func(t *testing.T) {
		content := "invalid_line_without_equals\naccess_token = \"token\"\ndevice_id = \"abc\"\n"
		path := filepath.Join(dir, "no_equals.toml")
		writeFile(t, path, content, 0o600)

		fields, err := parseAccountFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fields.AccessToken != "token" || fields.DeviceID != "abc" {
			t.Errorf("unexpected fields: %+v", fields)
		}
	})

	t.Run("file close error", func(t *testing.T) {
		content := "access_token = \"token\"\ndevice_id = \"abc\"\n"
		path := filepath.Join(dir, "close_err.toml")
		writeFile(t, path, content, 0o600)

		origClose := fileClose
		fileClose = mockErrFileClose
		t.Cleanup(func() {
			fileClose = origClose
		})

		if _, err := parseAccountFile(path); err == nil {
			t.Error("expected error for file close failure, got nil")
		}
	})

	t.Run("file read error", func(t *testing.T) {
		content := "access_token = \"token\"\ndevice_id = \"abc\"\n"
		path := filepath.Join(dir, "read_err.toml")
		writeFile(t, path, content, 0o600)

		origReadAll := fileReadAll
		fileReadAll = mockErrFileReadAll
		t.Cleanup(func() {
			fileReadAll = origReadAll
		})

		if _, err := parseAccountFile(path); err == nil {
			t.Error("expected error for file read failure, got nil")
		}
	})
}

func TestCheckFilePermissions(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		perm    os.FileMode
		wantErr bool
	}{
		{"0o600 accepted", 0o600, false},
		{"0o400 accepted", 0o400, false},
		{"0o644 rejected", 0o644, true},
		{"0o660 rejected", 0o660, true},
		{"0o640 rejected", 0o640, true},
		{"0o777 rejected", 0o777, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".toml")
			writeFile(t, path, "x", tc.perm)

			err := checkFilePermissions(path)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for perm %04o, got nil", tc.perm)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for perm %04o: %v", tc.perm, err)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		err := checkFilePermissions(filepath.Join(dir, "nonexistent.toml"))
		if err == nil {
			t.Error("expected error for missing file, got nil")
		}
	})
}

func TestValidDeviceIDRegex(t *testing.T) {
	valid := []string{
		"abcdef01-1234-5678-abcd-ef0123456789",
		"ABCDEF01-1234-5678-ABCD-EF0123456789",
		"abc123",
	}
	invalid := []string{
		"",
		"../etc/passwd",
		"abc/def",
		"abc def",
		"abc\x00def",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	for _, id := range valid {
		if !validDeviceID.MatchString(id) {
			t.Errorf("validDeviceID rejected valid id %q", id)
		}
	}
	for _, id := range invalid {
		if validDeviceID.MatchString(id) {
			t.Errorf("validDeviceID accepted invalid id %q", id)
		}
	}
}

func writeFile(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("writeFile %q: %v", path, err)
	}
}

func mockFetchDeviceInfo(_, _ string) (*deviceResponse, error) {
	var resp deviceResponse
	resp.Config.ClientID = "AQID"
	return &resp, nil
}

func TestFetchReserved(t *testing.T) {
	dir := t.TempDir()
	accountFile := filepath.Join(dir, "wgcf-account.toml")

	content := "access_token = \"fake-token\"\ndevice_id = \"abcdef01-1234-5678-abcd-ef0123456789\"\n"
	writeFile(t, accountFile, content, 0o600)

	origFetch := fetchDeviceInfo
	fetchDeviceInfo = mockFetchDeviceInfo
	t.Cleanup(func() {
		fetchDeviceInfo = origFetch
	})

	log := logging.New(logging.LevelDebug, "test")

	reserved, err := FetchReserved(accountFile, log)
	if err != nil {
		t.Fatalf("FetchReserved failed: %v", err)
	}

	want := [3]byte{1, 2, 3}
	if reserved != want {
		t.Errorf("got %v, want %v", reserved, want)
	}
}

func mockNetworkErrorFetchDeviceInfo(_, _ string) (*deviceResponse, error) {
	return nil, errors.New("network down")
}

func mockErrorFieldFetchDeviceInfo(_, _ string) (*deviceResponse, error) {
	var resp deviceResponse
	resp.Error = "unauthorized"
	return &resp, nil
}

func mockEmptyClientFetchDeviceInfo(_, _ string) (*deviceResponse, error) {
	var resp deviceResponse
	return &resp, nil
}

func mockBadB64FetchDeviceInfo(_, _ string) (*deviceResponse, error) {
	var resp deviceResponse
	resp.Config.ClientID = "invalid!b64"
	return &resp, nil
}

func TestFetchReservedErrors(t *testing.T) {
	log := logging.New(logging.LevelDebug, "test")

	t.Run("missing account file", func(t *testing.T) {
		if _, err := FetchReserved("/nonexistent/account.toml", log); err == nil {
			t.Error("expected error for missing account file, got nil")
		}
	})

	t.Run("parse account file error", func(t *testing.T) {
		dir := t.TempDir()
		accountFile := filepath.Join(dir, "invalid_account.toml")
		writeFile(t, accountFile, "invalid content\n", 0o600)
		if _, err := FetchReserved(accountFile, log); err == nil {
			t.Error("expected error when parseAccountFile fails, got nil")
		}
	})

	t.Run("invalid device id chars", func(t *testing.T) {
		dir := t.TempDir()
		accountFile := filepath.Join(dir, "bad_dev.toml")
		writeFile(t, accountFile, "access_token = \"tok\"\ndevice_id = \"bad!id@\"\n", 0o600)
		if _, err := FetchReserved(accountFile, log); err == nil {
			t.Error("expected error for invalid device_id regex, got nil")
		}
	})

	t.Run("api call error", func(t *testing.T) {
		dir := t.TempDir()
		accountFile := filepath.Join(dir, "api_err.toml")
		writeFile(t, accountFile, "access_token = \"tok\"\ndevice_id = \"abcdef01\"\n", 0o600)

		origFetch := fetchDeviceInfo
		fetchDeviceInfo = mockNetworkErrorFetchDeviceInfo
		t.Cleanup(func() {
			fetchDeviceInfo = origFetch
		})

		if _, err := FetchReserved(accountFile, log); err == nil {
			t.Error("expected error when API fails, got nil")
		}
	})

	t.Run("api returned error field", func(t *testing.T) {
		dir := t.TempDir()
		accountFile := filepath.Join(dir, "api_field_err.toml")
		writeFile(t, accountFile, "access_token = \"tok\"\ndevice_id = \"abcdef01\"\n", 0o600)

		origFetch := fetchDeviceInfo
		fetchDeviceInfo = mockErrorFieldFetchDeviceInfo
		t.Cleanup(func() {
			fetchDeviceInfo = origFetch
		})

		if _, err := FetchReserved(accountFile, log); err == nil {
			t.Error("expected error when API returns error field, got nil")
		}
	})

	t.Run("api returned empty client id", func(t *testing.T) {
		dir := t.TempDir()
		accountFile := filepath.Join(dir, "empty_client.toml")
		writeFile(t, accountFile, "access_token = \"tok\"\ndevice_id = \"abcdef01\"\n", 0o600)

		origFetch := fetchDeviceInfo
		fetchDeviceInfo = mockEmptyClientFetchDeviceInfo
		t.Cleanup(func() {
			fetchDeviceInfo = origFetch
		})

		if _, err := FetchReserved(accountFile, log); err == nil {
			t.Error("expected error when client_id is empty, got nil")
		}
	})

	t.Run("api returned invalid client id base64", func(t *testing.T) {
		dir := t.TempDir()
		accountFile := filepath.Join(dir, "bad_b64.toml")
		writeFile(t, accountFile, "access_token = \"tok\"\ndevice_id = \"abcdef01\"\n", 0o600)

		origFetch := fetchDeviceInfo
		fetchDeviceInfo = mockBadB64FetchDeviceInfo
		t.Cleanup(func() {
			fetchDeviceInfo = origFetch
		})

		if _, err := FetchReserved(accountFile, log); err == nil {
			t.Error("expected error when client_id cannot be decoded, got nil")
		}
	})
}

func TestParseAccountFileOversized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oversized.toml")
	content := make([]byte, maxAccountFileSize+10)
	writeFile(t, path, string(content), 0o600)

	if _, err := parseAccountFile(path); err == nil {
		t.Error("expected error for oversized account file, got nil")
	}
}

func TestDefaultNewWarpClient(t *testing.T) {
	client := defaultNewWarpClient()
	if client.Timeout != apiTimeout {
		t.Errorf("got timeout %v, want %v", client.Timeout, apiTimeout)
	}
}

type mockWarpTransport struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockWarpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

type mockErrCloser struct {
	io.Reader
}

func (mockErrCloser) Close() error {
	return errors.New("simulated body close error")
}

func mockWarpRoundTrip(req *http.Request) (*http.Response, error) {
	auth := req.Header.Get("Authorization")
	switch auth {
	case "Bearer network-err":
		return nil, errors.New("network failure")
	case "Bearer error-token":
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(bytes.NewBufferString(`{"error":"unauthorized"}`)),
		}, nil
	case "Bearer invalid-json":
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`invalid json`)),
		}, nil
	case "Bearer close-err":
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       mockErrCloser{Reader: bytes.NewBufferString(`{"config":{"client_id":"AQID"}}`)},
		}, nil
	default:
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"config":{"client_id":"AQID"}}`)),
		}, nil
	}
}

func mockCustomWarpClient() *http.Client {
	return &http.Client{
		Transport: &mockWarpTransport{roundTripFunc: mockWarpRoundTrip},
	}
}

func TestDefaultFetchDeviceInfo(t *testing.T) {
	origClient := newWarpClient
	newWarpClient = mockCustomWarpClient
	t.Cleanup(func() {
		newWarpClient = origClient
	})

	resp, err := defaultFetchDeviceInfo("valid-token", "device-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Config.ClientID != "AQID" {
		t.Errorf("got client_id %q, want AQID", resp.Config.ClientID)
	}

	if _, err := defaultFetchDeviceInfo("network-err", "device-1"); err == nil {
		t.Error("expected error for network failure, got nil")
	}

	if _, err := defaultFetchDeviceInfo("error-token", "device-1"); err == nil {
		t.Error("expected error for status 401, got nil")
	}

	if _, err := defaultFetchDeviceInfo("invalid-json", "device-1"); err == nil {
		t.Error("expected error for invalid json, got nil")
	}

	if _, err := defaultFetchDeviceInfo("close-err", "device-1"); err == nil {
		t.Error("expected error for body close failure, got nil")
	}

	if _, err := defaultFetchDeviceInfo("valid-token", "\x7f"); err == nil {
		t.Error("expected error for invalid url, got nil")
	}
}

func TestParseAccountFileOversizedAndMissingFields(t *testing.T) {
	dir := t.TempDir()

	oversizedPath := filepath.Join(dir, "oversized.toml")
	data := bytes.Repeat([]byte("a"), maxAccountFileSize+10)
	writeFile(t, oversizedPath, string(data), 0o600)
	if _, err := parseAccountFile(oversizedPath); err == nil {
		t.Error("expected error for oversized account file, got nil")
	}

	missingDevicePath := filepath.Join(dir, "no_device_id.toml")
	writeFile(t, missingDevicePath, "access_token = \"my-token\"\n", 0o600)
	if _, err := parseAccountFile(missingDevicePath); err == nil {
		t.Error("expected error for missing device_id, got nil")
	}
}

func TestFetchReservedEdgeCases(t *testing.T) {
	dir := t.TempDir()
	log := logging.New(logging.LevelDebug, "test")

	t.Run("invalid device id chars", func(t *testing.T) {
		path := filepath.Join(dir, "bad_device.toml")
		content := "access_token = \"tok\"\ndevice_id = \"bad/id!\"\n"
		writeFile(t, path, content, 0o600)
		if _, err := FetchReserved(path, log); err == nil {
			t.Error("expected error for bad device_id chars, got nil")
		}
	})
}

type mockErrReader struct{}

func (mockErrReader) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated read failure")
}

func TestDefaultFileHelpers(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "warp_helper_test")
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := defaultFileClose(f); closeErr != nil {
		t.Errorf("defaultFileClose failed: %v", closeErr)
	}
	if closeErr := defaultFileClose(f); closeErr == nil {
		t.Error("expected error on double close, got nil")
	}

	b, readErr := defaultFileReadAll(strings.NewReader("warp_data"))
	if readErr != nil || string(b) != "warp_data" {
		t.Errorf("defaultFileReadAll unexpected result: %s, %v", string(b), readErr)
	}
	if _, readFailErr := defaultFileReadAll(mockErrReader{}); readFailErr == nil {
		t.Error("expected error on mockErrReader, got nil")
	}
}
