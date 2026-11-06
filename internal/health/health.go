// Package health implements container liveness and readiness verification
// by probing upstream network connectivity through the local mihomo proxy.
package health

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
)

const defaultHealthTimeout = 10 * time.Second

const defaultHealthTarget = "https://cp.cloudflare.com/generate_204"

func defaultDoRequest(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("execute healthcheck request: %w", err)
	}
	return resp, nil
}

var doRequest = defaultDoRequest

// Check probes proxy connectivity against upstream endpoints to ensure outbound traffic routing functions correctly.
func Check(ctx context.Context, cfg *config.Config, targetURL ...string) (retErr error) {
	target := defaultHealthTarget
	if len(targetURL) > 0 && targetURL[0] != "" {
		target = targetURL[0]
	}

	proxyURL := &url.URL{
		Scheme: "socks5",
		Host:   net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(cfg.ProxyPort), 10)),
	}
	if cfg.ProxyUser != "" || cfg.ProxyPass != "" {
		proxyURL.User = url.UserPassword(cfg.ProxyUser, cfg.ProxyPass)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: defaultHealthTimeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return fmt.Errorf("create healthcheck request: %w", err)
	}

	resp, err := doRequest(ctx, client, req)
	if err != nil {
		return fmt.Errorf("healthcheck probe failed: %w", err)
	}
	defer func() {
		if _, copyErr := io.Copy(io.Discard, resp.Body); copyErr != nil && retErr == nil {
			retErr = fmt.Errorf("drain healthcheck response body: %w", copyErr)
		}
		if closeErr := resp.Body.Close(); closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("close healthcheck response body: %w", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck probe returned unexpected status %d", resp.StatusCode)
	}

	return nil
}
