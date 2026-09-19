// Package geo downloads and caches geodata files required by mihomo,
// enforcing strict HTTPS and DNS rebinding protections against SSRF.
package geo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
	"github.com/underhax/mihomo-warp-proxy/internal/validate"
)

const (
	maxFileSize     = 100 * 1024 * 1024
	maxRedirects    = 5
	downloadTimeout = 5 * time.Minute
	headTimeout     = 30 * time.Second
)

var (
	osRemove                  = os.Remove
	osRename                  = os.Rename
	osChmod                   = os.Chmod
	osCreateTemp              = os.CreateTemp
	urlParse                  = url.Parse
	httpNewRequestWithContext = http.NewRequestWithContext
)

// PrepareGeoFiles downloads all configured geodata files in parallel, verifying
// content integrity and caching metadata to skip unchanged resources.
func PrepareGeoFiles(cfg *config.Config, log *logging.Logger) error {
	urls := []struct {
		url string
		dst string
	}{
		{cfg.Geo.URLs.GeoIP, filepath.Join(cfg.Paths.MihomoData, "geoip.dat")},
		{cfg.Geo.URLs.GeoSite, filepath.Join(cfg.Paths.MihomoData, "geosite.dat")},
		{cfg.Geo.URLs.MMDB, filepath.Join(cfg.Paths.MihomoData, "geoip.metadb")},
		{cfg.Geo.URLs.ASN, filepath.Join(cfg.Paths.MihomoData, "GeoLite2-ASN.mmdb")},
	}

	client := newHTTPClient()

	g := &errgroup.Group{}
	for _, entry := range urls {
		g.Go(func() error {
			return download(client, cfg, log, entry.url, entry.dst)
		})
	}
	if err := g.Wait(); err != nil {
		return fmt.Errorf("geo: sync downloads: %w", err)
	}
	return nil
}

func download(client *http.Client, cfg *config.Config, log *logging.Logger, rawURL, dst string) error {
	if err := validateGeoURL(rawURL); err != nil {
		return fmt.Errorf("geo: invalid URL %q: %w", rawURL, err)
	}

	origURL, err := urlParse(rawURL)
	if err != nil {
		return fmt.Errorf("geo: parse original URL %q: %w", rawURL, err)
	}
	origHost := origURL.Hostname()

	log.Debugf("geo: checking %s -> %s", rawURL, dst)

	meta, finalURL, err := fetchMeta(client, cfg, rawURL, origHost)
	if err != nil {
		return fmt.Errorf("geo: HEAD %q: %w", rawURL, err)
	}

	if !cfg.Geo.Redownload {
		unchanged, err := isCached(dst, rawURL, meta, cfg.Paths.MihomoData)
		if err == nil && unchanged {
			log.Debugf("geo: %s unchanged, skipping download", filepath.Base(dst))
			return nil
		}
	}

	log.Debugf("geo: downloading %s", filepath.Base(dst))
	if err := streamToFile(client, cfg, finalURL, origHost, dst); err != nil {
		return fmt.Errorf("geo: download %q: %w", rawURL, err)
	}

	if err := osChmod(dst, 0o600); err != nil {
		return fmt.Errorf("geo: chmod %q: %w", dst, err)
	}

	if err := writeCacheMeta(rawURL, meta, cfg.Paths.MihomoData); err != nil {
		log.Warnf("geo: failed to write cache metadata for %s: %v", filepath.Base(dst), err)
	}

	log.Debugf("geo: %s saved", filepath.Base(dst))
	return nil
}

func fetchMeta(client *http.Client, cfg *config.Config, rawURL, origHost string) (http.Header, string, error) {
	current := rawURL

	for range maxRedirects {
		if err := validateGeoURL(current); err != nil {
			return nil, "", fmt.Errorf("redirect target invalid: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), headTimeout)
		req, err := httpNewRequestWithContext(ctx, http.MethodHead, current, http.NoBody)
		if err != nil {
			cancel()
			return nil, "", fmt.Errorf("create HEAD request: %w", err)
		}
		applyAuth(req, cfg, origHost)

		resp, err := client.Do(req)
		cancel()
		if err != nil {
			return nil, "", fmt.Errorf("create HEAD request: %w", err)
		}
		closeErr := resp.Body.Close()
		if closeErr != nil {
			return nil, "", fmt.Errorf("close HEAD response: %w", closeErr)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp.Header, current, nil
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil, "", fmt.Errorf("redirect %d with no Location header", resp.StatusCode)
			}
			resolved, err := resolveRedirect(current, loc)
			if err != nil {
				return nil, "", fmt.Errorf("resolve redirect location %q: %w", loc, err)
			}
			current = resolved
			continue
		}

		return nil, "", fmt.Errorf("unexpected HTTP status %d for %s", resp.StatusCode, current)
	}

	return nil, "", fmt.Errorf("exceeded %d redirects for %s", maxRedirects, rawURL)
}

func streamToFile(client *http.Client, cfg *config.Config, rawURL, origHost, dst string) (retErr error) {
	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()

	resp, err := openDownloadStream(ctx, client, cfg, rawURL, origHost)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("close response body: %w", closeErr)
		}
	}()

	return saveStreamToDestination(resp.Body, dst)
}

func openDownloadStream(ctx context.Context, client *http.Client, cfg *config.Config, rawURL, origHost string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create GET request: %w", err)
	}
	applyAuth(req, cfg, origHost)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute GET request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return nil, fmt.Errorf("close response body on status %d: %w", resp.StatusCode, closeErr)
		}
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	ct := strings.ToLower(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0])
	ct = strings.TrimSpace(ct)
	if strings.HasPrefix(ct, "text/") {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return nil, fmt.Errorf("close response body on text content-type: %w", closeErr)
		}
		return nil, fmt.Errorf("server returned text content-type %q — likely an error page", ct)
	}

	return resp, nil
}

func saveStreamToDestination(body io.Reader, dst string) (retErr error) {
	dir := filepath.Dir(dst)
	tmp, err := osCreateTemp(dir, ".geo_download_*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	tmpDone := false
	defer func() {
		if !tmpDone {
			closeErr := tempFileClose(tmp)
			removeErr := osRemove(tmpName)
			retErr = errors.Join(retErr, closeErr, removeErr)
		}
	}()

	err = tempFileChmod(tmp, 0o600)
	if err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}

	limited := io.LimitReader(body, maxFileSize+1)
	n, err := io.Copy(tmp, limited)
	if err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if n > maxFileSize {
		return fmt.Errorf("download exceeds %d byte limit", maxFileSize)
	}
	if n == 0 {
		return errors.New("downloaded file is empty")
	}

	if err := tempFileSync(tmp); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tempFileClose(tmp); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := osRename(tmpName, dst); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	tmpDone = true
	return nil
}

func metaKey(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return hex.EncodeToString(sum[:]) + ".meta"
}

func cacheDir(mihomoData string) (string, error) {
	dir := filepath.Join(mihomoData, ".cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create cache directory: %w", err)
	}
	return dir, nil
}

func isCached(dst, rawURL string, remoteHeaders http.Header, mihomoData string) (bool, error) {
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		return false, nil
	}

	dir, err := cacheDir(mihomoData)
	if err != nil {
		return false, fmt.Errorf("resolve cache dir: %w", err)
	}

	cacheFile := filepath.Clean(filepath.Join(dir, metaKey(rawURL)))
	cached, err := os.ReadFile(cacheFile)
	if err != nil {
		return false, fmt.Errorf("read cache metadata: %w", err)
	}

	current := serializeMeta(remoteHeaders)
	return string(cached) == current, nil
}

func writeCacheMeta(rawURL string, remoteHeaders http.Header, mihomoData string) (retErr error) {
	dir, err := cacheDir(mihomoData)
	if err != nil {
		return fmt.Errorf("resolve cache dir: %w", err)
	}

	cacheFile := filepath.Join(dir, metaKey(rawURL))
	data := serializeMeta(remoteHeaders)

	tmp, err := osCreateTemp(dir, ".meta_*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	tmpName := tmp.Name()
	tmpDone := false
	defer func() {
		if !tmpDone {
			closeErr := tempFileClose(tmp)
			removeErr := osRemove(tmpName)
			retErr = errors.Join(retErr, closeErr, removeErr)
		}
	}()

	if _, err := tempFileWriteString(tmp, data); err != nil {
		return fmt.Errorf("write cache metadata: %w", err)
	}
	if err := tempFileClose(tmp); err != nil {
		return fmt.Errorf("close temp cache file: %w", err)
	}
	if err := osRename(tmpName, cacheFile); err != nil {
		return fmt.Errorf("rename cache file: %w", err)
	}
	tmpDone = true
	return nil
}

func serializeMeta(h http.Header) string {
	etag := h.Get("Etag")
	lm := h.Get("Last-Modified")
	return fmt.Sprintf("etag=%s\nlast-modified=%s\n", etag, lm)
}

var validateResolveAndValidate = validate.ResolveAndValidate

func defaultResolveHost(host string) error {
	if err := validateResolveAndValidate(host); err != nil {
		return fmt.Errorf("resolve host: %w", err)
	}
	return nil
}

var resolveHost = defaultResolveHost

func validateGeoURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("only HTTPS URLs are allowed, got scheme %q", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host: %q", rawURL)
	}

	lower := strings.ToLower(rawURL)
	for _, bad := range []string{"%00", "%0a", "%0d", "%2e%2e", "%25"} {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("URL contains dangerous percent-encoding %q", bad)
		}
	}

	if err := resolveHost(host); err != nil {
		return fmt.Errorf("resolve and validate host: %w", err)
	}
	return nil
}

func resolveRedirect(current, location string) (string, error) {
	base, err := url.Parse(current)
	if err != nil {
		return "", fmt.Errorf("parse current URL: %w", err)
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("invalid Location header %q: %w", location, err)
	}
	resolved := base.ResolveReference(loc).String()

	if strings.HasPrefix(strings.ToLower(current), "https://") &&
		!strings.HasPrefix(strings.ToLower(resolved), "https://") {
		return "", fmt.Errorf("redirect would downgrade from HTTPS to HTTP: %q", resolved)
	}

	return resolved, nil
}

func applyAuth(req *http.Request, cfg *config.Config, origHost string) {
	if cfg.Geo.AuthUser != "" && cfg.Geo.AuthPass != "" && req.URL.Hostname() == origHost {
		req.SetBasicAuth(cfg.Geo.AuthUser, cfg.Geo.AuthPass)
	}
}

func defaultDialerControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("geo: malformed dial address %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip != nil && validate.IsRestrictedIP(ip) {
		return fmt.Errorf("geo: connection to restricted IP %s blocked (DNS rebinding protection)", host)
	}
	return nil
}

func defaultCheckRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func defaultNewHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: -1,
		Control:   defaultDialerControl,
	}

	return &http.Client{
		CheckRedirect: defaultCheckRedirect,
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
			DisableKeepAlives: true,
			DialContext:       dialer.DialContext,
		},
	}
}

var newHTTPClient = defaultNewHTTPClient

func defaultTempFileSync(f *os.File) error {
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	return nil
}

func defaultTempFileClose(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	return nil
}

func defaultTempFileChmod(f *os.File, mode os.FileMode) error {
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	return nil
}

func defaultTempFileWriteString(f *os.File, s string) (int, error) {
	n, err := f.WriteString(s)
	if err != nil {
		return n, fmt.Errorf("write string temp file: %w", err)
	}
	return n, nil
}

var (
	tempFileSync        = defaultTempFileSync
	tempFileClose       = defaultTempFileClose
	tempFileChmod       = defaultTempFileChmod
	tempFileWriteString = defaultTempFileWriteString
)
