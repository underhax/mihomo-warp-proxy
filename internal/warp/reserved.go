// Package warp fetches the WARP device reserved bytes from the Cloudflare
// API to identify the client during WireGuard handshakes.
package warp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/underhax/mihomo-warp-proxy/internal/logging"
)

const maxAccountFileSize = 64 * 1024

const (
	warpAPIBase     = "https://api.cloudflareclient.com/v0a2158/reg"
	apiTimeout      = 30 * time.Second
	maxResponseSize = 1 * 1024 * 1024
)

var validDeviceID = regexp.MustCompile(`^[a-fA-F0-9\-]{1,64}$`)

type accountFields struct {
	AccessToken string
	DeviceID    string
}

type deviceResponse struct {
	Config struct {
		ClientID string `json:"client_id"`
	} `json:"config"`
	Error string `json:"error"`
}

// FetchReserved reads device credentials from the account file and retrieves
// client reserved bytes from the API to configure WireGuard parameters.
func FetchReserved(accountFile string, log *logging.Logger) ([3]byte, error) {
	var empty [3]byte

	if err := checkFilePermissions(accountFile); err != nil {
		return empty, err
	}

	fields, err := parseAccountFile(accountFile)
	if err != nil {
		return empty, fmt.Errorf("warp: parse account file: %w", err)
	}

	if !validDeviceID.MatchString(fields.DeviceID) {
		return empty, fmt.Errorf("warp: device_id %q contains invalid characters", fields.DeviceID)
	}

	log.Debugf("warp: fetching reserved bytes for device %s", fields.DeviceID)

	resp, err := fetchDeviceInfo(fields.AccessToken, fields.DeviceID)
	if err != nil {
		return empty, fmt.Errorf("warp: API request failed: %w", err)
	}

	if resp.Error != "" {
		return empty, fmt.Errorf("warp: API returned error: %s", resp.Error)
	}

	if resp.Config.ClientID == "" {
		return empty, errors.New("warp: client_id not present in API response")
	}

	reserved, err := decodeClientID(resp.Config.ClientID)
	if err != nil {
		return empty, fmt.Errorf("warp: decode client_id: %w", err)
	}

	log.Debugf("warp: reserved bytes: [%d, %d, %d]", reserved[0], reserved[1], reserved[2])
	return reserved, nil
}

func defaultNewWarpClient() *http.Client {
	return &http.Client{
		Timeout: apiTimeout,
	}
}

var newWarpClient = defaultNewWarpClient

func defaultFetchDeviceInfo(accessToken, deviceID string) (devResp *deviceResponse, retErr error) {
	apiURL := fmt.Sprintf("%s/%s", warpAPIBase, deviceID)

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create API request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("CF-Client-Version", "a-6.10-2158")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("Content-Type", "application/json")

	client := newWarpClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute API request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("close API response: %w", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxResponseSize)
	var result deviceResponse
	if err := json.NewDecoder(limited).Decode(&result); err != nil {
		return nil, fmt.Errorf("parse JSON response: %w", err)
	}

	return &result, nil
}

var fetchDeviceInfo = defaultFetchDeviceInfo

func decodeClientID(clientID string) ([3]byte, error) {
	var result [3]byte

	decoded, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(clientID)
		if err != nil {
			return result, fmt.Errorf("base64 decode failed: %w", err)
		}
	}

	if len(decoded) != 3 {
		return result, fmt.Errorf("client_id decoded to %d bytes, expected exactly 3", len(decoded))
	}

	copy(result[:], decoded)
	return result, nil
}

func defaultFileClose(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("close file: %w", err)
	}
	return nil
}

func defaultFileReadAll(r io.Reader) ([]byte, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return buf, nil
}

var (
	fileClose   = defaultFileClose
	fileReadAll = defaultFileReadAll
)

func parseAccountFile(path string) (fields *accountFields, retErr error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("open account file: %w", err)
	}
	defer func() {
		if closeErr := fileClose(f); closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("close account file: %w", closeErr)
		}
	}()

	data, err := fileReadAll(io.LimitReader(f, maxAccountFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read account file: %w", err)
	}
	if len(data) > maxAccountFileSize {
		return nil, fmt.Errorf("account file %q exceeds 64KB limit", path)
	}

	parsed := &accountFields{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)

		switch key {
		case "access_token":
			parsed.AccessToken = value
		case "device_id":
			parsed.DeviceID = value
		}
	}

	if parsed.AccessToken == "" {
		return nil, fmt.Errorf("access_token not found in %q", path)
	}
	if parsed.DeviceID == "" {
		return nil, fmt.Errorf("device_id not found in %q", path)
	}

	return parsed, nil
}

func checkFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("warp: stat %q: %w", path, err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 && perm != 0o400 {
		return fmt.Errorf("warp: account file %q has unsafe permissions %04o (want 0o600 or 0o400)", path, perm)
	}
	return nil
}
