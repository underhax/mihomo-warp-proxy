package geo

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
	"github.com/underhax/mihomo-warp-proxy/internal/logging"
)

func TestValidateGeoURL(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"http rejected", "http://example.com/file.dat", true},
		{"ftp rejected", "ftp://example.com/file.dat", true},
		{"empty rejected", "", true},
		{"no host rejected", "https:///file.dat", true},
		{"null byte encoding", "https://example.com/%00file", true},
		{"newline encoding", "https://example.com/%0afile", true},
		{"CR encoding", "https://example.com/%0dfile", true},
		{"dotdot encoding", "https://example.com/%2e%2efile", true},
		{"percent encoding", "https://example.com/%25file", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGeoURL(tc.url)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q, got nil", tc.url)
			}
		})
	}
}

func TestResolveRedirect(t *testing.T) {
	cases := []struct {
		name     string
		current  string
		location string
		want     string
		wantErr  bool
	}{
		{
			name:     "absolute https location",
			current:  "https://example.com/source-absolute",
			location: "https://cdn.example.com/new",
			want:     "https://cdn.example.com/new",
		},
		{
			name:     "absolute path location",
			current:  "https://example.com/source-path",
			location: "/v2/file.dat",
			want:     "https://example.com/v2/file.dat",
		},
		{
			name:     "relative location",
			current:  "https://example.com/files/old",
			location: "new",
			want:     "https://example.com/files/new",
		},
		{
			name:     "protocol-relative location",
			current:  "https://example.com/source-protocol",
			location: "//cdn.example.com/file.dat",
			want:     "https://cdn.example.com/file.dat",
		},
		{
			name:     "https to http downgrade rejected",
			current:  "https://example.com/source-downgrade",
			location: "http://example.com/new",
			wantErr:  true,
		},
		{
			name:     "invalid location rejected",
			current:  "https://example.com/source-invalid",
			location: "://bad",
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveRedirect(tc.current, tc.location)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSerializeMeta(t *testing.T) {
	h := http.Header{}
	h.Set("Etag", `"abc123"`)
	h.Set("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT")

	got := serializeMeta(h)
	if got == "" {
		t.Error("serializeMeta returned empty string")
	}

	if got != serializeMeta(h) {
		t.Error("serializeMeta is not deterministic")
	}

	h2 := http.Header{}
	h2.Set("Etag", `"different"`)
	if got == serializeMeta(h2) {
		t.Error("serializeMeta returned same result for different headers")
	}
}

func TestMetaKey(t *testing.T) {
	url1 := "https://example.com/geoip.dat"
	url2 := "https://example.com/geosite.dat"

	k1 := metaKey(url1)
	k2 := metaKey(url2)

	if k1 == k2 {
		t.Error("different URLs must produce different cache keys")
	}

	if metaKey(url1) != k1 {
		t.Error("metaKey is not deterministic")
	}

	const suffix = ".meta"
	if len(k1) <= len(suffix) || k1[len(k1)-len(suffix):] != suffix {
		t.Errorf("metaKey missing .meta suffix: %q", k1)
	}
	hexPart := k1[:len(k1)-len(suffix)]
	for _, r := range hexPart {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			t.Errorf("metaKey hex part contains non-hex character %q in %q", r, k1)
		}
	}
}

func TestIsCached(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "geoip.dat")
	rawURL := "https://example.com/geoip.dat"

	headers := http.Header{}
	headers.Set("Etag", `"v1"`)
	headers.Set("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT")

	t.Run("no local file returns false", func(t *testing.T) {
		cached, err := isCached(dst, rawURL, headers, dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cached {
			t.Error("expected false when local file does not exist")
		}
	})

	if err := os.WriteFile(dst, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeCacheMeta(rawURL, headers, dir); err != nil {
		t.Fatal(err)
	}

	t.Run("matching metadata returns true", func(t *testing.T) {
		cached, err := isCached(dst, rawURL, headers, dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cached {
			t.Error("expected true when metadata matches")
		}
	})

	t.Run("changed etag returns false", func(t *testing.T) {
		changed := http.Header{}
		changed.Set("Etag", `"v2"`)
		changed.Set("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT")

		cached, err := isCached(dst, rawURL, changed, dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cached {
			t.Error("expected false when ETag changed")
		}
	})
}

func TestStreamToFileSizeLimit(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		defer func() {
			if closeErr := pw.Close(); closeErr != nil {
				return
			}
		}()
		buf := make([]byte, 4096)
		written := 0
		limit := maxFileSize + 2
		for written < limit {
			n := len(buf)
			if written+n > limit {
				n = limit - written
			}
			writtenBytes, writeErr := pw.Write(buf[:n])
			if writeErr != nil {
				return
			}
			written += writtenBytes
		}
	}()

	limited := &limitedBody{r: pr, limit: maxFileSize + 1}
	n, countErr := countBytes(limited)
	if countErr != nil && !errors.Is(countErr, io.EOF) {
		t.Logf("count error: %v", countErr)
	}
	if closeErr := pr.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	if n <= int64(maxFileSize) {
		t.Errorf("test data generator produced only %d bytes, need > %d", n, maxFileSize)
	}
}

type limitedBody struct {
	r     *os.File
	limit int64
}

func (l *limitedBody) Read(p []byte) (int, error) {
	return l.r.Read(p)
}

func countBytes(r *limitedBody) (int64, error) {
	buf := make([]byte, 4096)
	var total int64
	for {
		n, err := r.Read(buf)
		total += int64(n)
		if err != nil || total > int64(maxFileSize) {
			return total, err
		}
	}
}

func TestApplyAuthCrossOriginProtection(t *testing.T) {
	cfg := &config.Config{
		Geo: config.GeoConfig{
			AuthUser: "testuser",
			AuthPass: "testpass",
		},
	}

	cases := []struct {
		name     string
		reqURL   string
		origHost string
		wantAuth bool
	}{
		{
			name:     "same host — credentials applied",
			reqURL:   "https://cdn-auth.example.com/geoip.dat",
			origHost: "cdn-auth.example.com",
			wantAuth: true,
		},
		{
			name:     "cross-origin redirect — credentials withheld",
			reqURL:   "https://attacker.example.com/geoip.dat",
			origHost: "cdn-origin.example.com",
			wantAuth: false,
		},
		{
			name:     "subdomain treated as different host — credentials withheld",
			reqURL:   "https://sub.cdn-redirect.example.com/geoip.dat",
			origHost: "cdn-redirect.example.com",
			wantAuth: false,
		},
		{
			name:     "no credentials configured — header absent",
			reqURL:   "https://cdn-noauth.example.com/geoip.dat",
			origHost: "cdn-noauth.example.com",
			wantAuth: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			if tc.name == "no credentials configured — header absent" {
				c = &config.Config{}
			}
			parsed, err := url.Parse(tc.reqURL)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", tc.reqURL, err)
			}
			req := &http.Request{URL: parsed, Header: http.Header{}}
			applyAuth(req, c, tc.origHost)
			hasAuth := req.Header.Get("Authorization") != ""
			if hasAuth != tc.wantAuth {
				t.Errorf("Authorization present=%v, want %v", hasAuth, tc.wantAuth)
			}
		})
	}
}

var errMockResolve = errors.New("host not found")

func mockResolveHost(host string) error {
	if host == "example.com" {
		return nil
	}
	return errMockResolve
}

func mockValidateResolveAndValidate(host string) error {
	if host == "example.com" {
		return nil
	}
	return errMockResolve
}

func init() {
	validateResolveAndValidate = mockValidateResolveAndValidate
}

type mockRoundTripper struct{}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	header := make(http.Header)
	header.Set("Etag", `"v1"`)
	header.Set("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT")
	header.Set("Content-Type", "application/octet-stream")

	var body io.ReadCloser
	if req.Method == http.MethodHead {
		body = http.NoBody
	} else {
		body = io.NopCloser(strings.NewReader("fake geodata payload"))
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       body,
		Request:    req,
	}, nil
}

func mockNewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &mockRoundTripper{},
	}
}

func TestPrepareGeoFiles(t *testing.T) {
	origResolve := resolveHost
	origClient := newHTTPClient
	resolveHost = mockResolveHost
	newHTTPClient = mockNewHTTPClient
	t.Cleanup(func() {
		resolveHost = origResolve
		newHTTPClient = origClient
	})

	dir := t.TempDir()
	cacheSubDir := filepath.Join(dir, ".cache")

	cfg := &config.Config{
		Geo: config.GeoConfig{
			Enabled:    true,
			Redownload: true,
			URLs: config.GeoURLs{
				GeoIP:   "https://example.com/mock-geoip.dat",
				GeoSite: "https://example.com/mock-geosite.dat",
				MMDB:    "https://example.com/mock-geoip.metadb",
				ASN:     "https://example.com/mock-GeoLite2-ASN.mmdb",
			},
		},
		Paths: config.Paths{
			MihomoData: dir,
		},
		Version: "test",
	}

	log := logging.New(logging.LevelDebug, "test")

	if err := PrepareGeoFiles(cfg, log); err != nil {
		t.Fatalf("PrepareGeoFiles failed: %v", err)
	}

	expected := []string{
		filepath.Join(dir, "geoip.dat"),
		filepath.Join(dir, "geosite.dat"),
		filepath.Join(dir, "geoip.metadb"),
		filepath.Join(dir, "GeoLite2-ASN.mmdb"),
	}

	for _, f := range expected {
		info, err := os.Stat(f)
		if err != nil {
			t.Errorf("expected file not found: %s: %v", f, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file is empty: %s", f)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file %s has permissions %04o, want 0600", f, perm)
		}
	}

	entries, err := os.ReadDir(cacheSubDir)
	if err != nil {
		t.Fatalf("cache directory not created: %v", err)
	}
	if len(entries) != 4 {
		t.Errorf("expected 4 cache metadata files, got %d", len(entries))
	}

	cfg.Geo.Redownload = false
	if err := PrepareGeoFiles(cfg, log); err != nil {
		t.Fatalf("second PrepareGeoFiles failed: %v", err)
	}
}

func TestDefaultNewHTTPClient(t *testing.T) {
	client := defaultNewHTTPClient()
	if client == nil || client.Transport == nil {
		t.Error("expected non-nil client and transport")
	}
}

type mockStatusRoundTripper struct {
	header     http.Header
	statusCode int
}

func (m *mockStatusRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: m.statusCode,
		Header:     m.header,
		Body:       io.NopCloser(strings.NewReader("response")),
		Request:    req,
	}, nil
}

func TestFetchMetaErrors(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	cfg := &config.Config{
		Geo: config.GeoConfig{
			AuthUser: "user",
			AuthPass: "pass",
		},
	}

	t.Run("status 404", func(t *testing.T) {
		client := &http.Client{Transport: &mockStatusRoundTripper{statusCode: http.StatusNotFound, header: http.Header{}}}
		if _, _, err := fetchMeta(client, cfg, "https://example.com/file", "example.com"); err == nil {
			t.Error("expected error for 404, got nil")
		}
	})

	t.Run("redirect missing location", func(t *testing.T) {
		client := &http.Client{Transport: &mockStatusRoundTripper{statusCode: http.StatusFound, header: http.Header{}}}
		if _, _, err := fetchMeta(client, cfg, "https://example.com/file", "example.com"); err == nil {
			t.Error("expected error for redirect without location, got nil")
		}
	})

	t.Run("redirect loop", func(t *testing.T) {
		h := http.Header{}
		h.Set("Location", "https://example.com/file")
		client := &http.Client{Transport: &mockStatusRoundTripper{statusCode: http.StatusFound, header: h}}
		if _, _, err := fetchMeta(client, cfg, "https://example.com/file", "example.com"); err == nil {
			t.Error("expected error for redirect loop, got nil")
		}
	})
}

func TestOpenDownloadStreamErrors(t *testing.T) {
	cfg := &config.Config{}
	client := &http.Client{Transport: &mockStatusRoundTripper{statusCode: http.StatusInternalServerError, header: http.Header{}}}
	ctx := context.Background()
	resp, err := openDownloadStream(ctx, client, cfg, "https://example.com/file", "example.com")
	if err == nil {
		if resp != nil && resp.Body != nil {
			if closeErr := resp.Body.Close(); closeErr != nil {
				t.Log(closeErr)
			}
		}
		t.Error("expected error for 500 status, got nil")
	}

	textHeader := http.Header{}
	textHeader.Set("Content-Type", "text/html; charset=utf-8")
	textClient := &http.Client{Transport: &mockStatusRoundTripper{statusCode: http.StatusOK, header: textHeader}}
	resp2, err := openDownloadStream(ctx, textClient, cfg, "https://example.com/file", "example.com")
	if err == nil {
		if resp2 != nil && resp2.Body != nil {
			if closeErr := resp2.Body.Close(); closeErr != nil {
				t.Log(closeErr)
			}
		}
		t.Error("expected error for text/html content-type, got nil")
	}
}

func TestSaveStreamToDestinationErrors(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "out.dat")

	t.Run("destination invalid directory", func(t *testing.T) {
		err := saveStreamToDestination(strings.NewReader("data"), filepath.Join(dir, "sub", "not_exist", "out.dat"))
		if err == nil {
			t.Error("expected error for non-existent directory, got nil")
		}
	})

	t.Run("destination normal write", func(t *testing.T) {
		err := saveStreamToDestination(strings.NewReader("small payload"), dst)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty payload error", func(t *testing.T) {
		err := saveStreamToDestination(strings.NewReader(""), filepath.Join(dir, "empty.dat"))
		if err == nil {
			t.Error("expected error for empty payload, got nil")
		}
	})

	t.Run("payload exceeds max size", func(t *testing.T) {
		large := io.LimitReader(&infiniteReader{}, maxFileSize+2)
		err := saveStreamToDestination(large, filepath.Join(dir, "large.dat"))
		if err == nil {
			t.Error("expected error for oversized payload, got nil")
		}
	})

	t.Run("write temp file error", func(t *testing.T) {
		err := saveStreamToDestination(errReader{}, filepath.Join(dir, "dest_err.dat"))
		if err == nil || !strings.Contains(err.Error(), "write temp file") {
			t.Errorf("expected write temp file error, got: %v", err)
		}
	})

	t.Run("rename temp file error", func(t *testing.T) {
		origRename := osRename
		defer func() { osRename = origRename }()
		osRename = func(_, _ string) error {
			return errors.New("mock rename error")
		}

		err := saveStreamToDestination(strings.NewReader("valid data"), filepath.Join(dir, "dest_rename.dat"))
		if err == nil || !strings.Contains(err.Error(), "rename temp file") {
			t.Errorf("expected rename temp file error, got: %v", err)
		}
	})
}

type infiniteReader struct{}

func (i *infiniteReader) Read(p []byte) (int, error) {
	return len(p), nil
}

func TestWriteCacheMetaErrors(t *testing.T) {
	h := http.Header{}
	h.Set("Etag", `"v1"`)
	if err := writeCacheMeta("https://example.com/geo", h, "/nonexistent_dir_impossible/xyz"); err == nil {
		t.Error("expected error for unwritable dir, got nil")
	}
}

type mockHeadFailRoundTripper struct{}

func (m *mockHeadFailRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodHead {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header:     http.Header{},
			Body:       http.NoBody,
			Request:    req,
		}, nil
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/octet-stream")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("geo payload")),
		Request:    req,
	}, nil
}

func TestDownloadMetaFetchFails(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	dir := t.TempDir()
	cfg := &config.Config{
		Geo: config.GeoConfig{
			Enabled: true,
		},
		Paths: config.Paths{
			MihomoData: dir,
		},
	}
	log := logging.New(logging.LevelDebug, "test")
	client := &http.Client{Transport: &mockHeadFailRoundTripper{}}
	dst := filepath.Join(dir, "test.dat")

	if err := download(client, cfg, log, "https://example.com/fallback.dat", dst); err == nil {
		t.Error("expected error on HEAD failure, got nil")
	}
}

func TestDownloadWriteCacheMetaWarn(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	dir := t.TempDir()
	cacheBlocker := filepath.Join(dir, ".cache")
	if err := os.WriteFile(cacheBlocker, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Geo: config.GeoConfig{
			Enabled:    true,
			Redownload: true,
		},
		Paths: config.Paths{
			MihomoData: dir,
		},
	}
	log := logging.New(logging.LevelDebug, "test")
	client := mockNewHTTPClient()
	dst := filepath.Join(dir, "test.dat")

	if err := download(client, cfg, log, "https://example.com/file.dat", dst); err != nil {
		t.Fatalf("download should succeed despite cache write failure: %v", err)
	}
}

type customRoundTripper struct {
	fn func(req *http.Request) (*http.Response, error)
}

func (c *customRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.fn(req)
}

func TestWriteCacheMetaEmptyHeaders(t *testing.T) {
	dir := t.TempDir()
	err := writeCacheMeta("https://example.com/test.dat", http.Header{}, dir)
	if err != nil {
		t.Fatalf("unexpected error with empty headers: %v", err)
	}
}

func TestFetchMetaRedirectNoLocation(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	client := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     http.Header{},
					Body:       http.NoBody,
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{}
	_, _, err := fetchMeta(client, cfg, "https://example.com/redirect", "example.com")
	if err == nil || !strings.Contains(err.Error(), "no Location header") {
		t.Errorf("expected no Location header error, got: %v", err)
	}
}

func TestFetchMetaStatusError(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	client := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Header:     http.Header{},
					Body:       http.NoBody,
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{}
	_, _, err := fetchMeta(client, cfg, "https://example.com/notfound", "example.com")
	if err == nil || !strings.Contains(err.Error(), "unexpected HTTP status 404") {
		t.Errorf("expected 404 status error, got: %v", err)
	}
}

func TestDefaultNewHTTPClientCheckRedirect(t *testing.T) {
	client := defaultNewHTTPClient()
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be set")
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("got %v, want http.ErrUseLastResponse", err)
	}
}

func TestValidateGeoURLAndResolveRedirectEdgeCases(t *testing.T) {
	if err := validateGeoURL("https://example.com/foo\x7f"); err == nil {
		t.Error("expected parse error for URL with control char, got nil")
	}
	if _, err := resolveRedirect("https://example.com/foo\x7f", "https://example.com/bar"); err == nil {
		t.Error("expected resolveRedirect error for bad current URL, got nil")
	}
}

func TestFetchMetaMaxRedirectsExceeded(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				h := make(http.Header)
				h.Set("Location", "https://example.com/loop")
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     h,
					Body:       http.NoBody,
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{}
	_, _, err := fetchMeta(client, cfg, "https://example.com/loop", "example.com")
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("expected exceeded max redirects error, got: %v", err)
	}
}

func TestFetchMetaRedirectToInvalidTarget(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				h := make(http.Header)
				h.Set("Location", "https://example.com/%00bad")
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     h,
					Body:       http.NoBody,
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{}
	_, _, err := fetchMeta(client, cfg, "https://example.com/start", "example.com")
	if err == nil || !strings.Contains(err.Error(), "redirect target invalid") {
		t.Errorf("expected redirect target invalid error, got: %v", err)
	}
}

type mockErrReader struct{}

func (e *mockErrReader) Read(_ []byte) (int, error) {
	return 0, errors.New("read error")
}

func TestSaveStreamToDestinationEdgeCases(t *testing.T) {
	dir := t.TempDir()

	err := saveStreamToDestination(&mockErrReader{}, filepath.Join(dir, "err.dat"))
	if err == nil || !strings.Contains(err.Error(), "write temp file") {
		t.Errorf("expected write temp file error, got: %v", err)
	}

	existingDir := filepath.Join(dir, "target_dir")
	if mkdirErr := os.Mkdir(existingDir, 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	err = saveStreamToDestination(strings.NewReader("content"), existingDir)
	if err == nil || !strings.Contains(err.Error(), "rename temp file") {
		t.Errorf("expected rename temp file error, got: %v", err)
	}

	dummyFile := filepath.Join(dir, "dummy_file")
	if writeErr := os.WriteFile(dummyFile, []byte("data"), 0o600); writeErr != nil {
		t.Fatal(writeErr)
	}
	err = saveStreamToDestination(strings.NewReader("content"), filepath.Join(dummyFile, "out.dat"))
	if err == nil || !strings.Contains(err.Error(), "create temp file") {
		t.Errorf("expected create temp file error, got: %v", err)
	}
}

func TestIsCachedEdgeCases(t *testing.T) {
	dir := t.TempDir()
	dummyFile := filepath.Join(dir, "dummy_file")
	if err := os.WriteFile(dummyFile, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "existing_dst.dat")
	if err := os.WriteFile(dst, []byte("dst"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := isCached(dst, "https://example.com/test", http.Header{}, dummyFile)
	if err == nil || !strings.Contains(err.Error(), "resolve cache dir") {
		t.Errorf("expected resolve cache dir error, got: %v", err)
	}

	_, err = isCached(dst, "https://example.com/test", http.Header{}, dir)
	if err == nil || !strings.Contains(err.Error(), "read cache metadata") {
		t.Errorf("expected read cache metadata error, got: %v", err)
	}
}

func TestWriteCacheMetaRenameError(t *testing.T) {
	dir := t.TempDir()
	rawURL := "https://example.com/rename_test"
	cDir, err := cacheDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	targetCacheFile := filepath.Join(cDir, metaKey(rawURL))
	if mkdirErr := os.Mkdir(targetCacheFile, 0o700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	err = writeCacheMeta(rawURL, http.Header{}, dir)
	if err == nil || !strings.Contains(err.Error(), "rename cache file") {
		t.Errorf("expected rename cache file error, got: %v", err)
	}
}

func TestOpenDownloadStreamEdgeCases(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{}

	resp, err := openDownloadStream(ctx, mockNewHTTPClient(), cfg, "https://example.com/bad\x7f", "example.com")
	if resp != nil && resp.Body != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Log(closeErr)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "create GET request") {
		t.Errorf("expected create GET request error, got: %v", err)
	}

	failingClient := &http.Client{
		Transport: &customRoundTripper{
			fn: func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("network failure")
			},
		},
	}
	resp, err = openDownloadStream(ctx, failingClient, cfg, "https://example.com/fail", "example.com")
	if resp != nil && resp.Body != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Log(closeErr)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "execute GET request") {
		t.Errorf("expected execute GET request error, got: %v", err)
	}
}

func TestPrepareGeoFilesError(t *testing.T) {
	origResolve := resolveHost
	origClient := newHTTPClient
	resolveHost = mockResolveHost
	newHTTPClient = mockNewHTTPClient
	t.Cleanup(func() {
		resolveHost = origResolve
		newHTTPClient = origClient
	})

	cfg := &config.Config{
		Geo: config.GeoConfig{
			URLs: config.GeoURLs{
				GeoIP:   "https://example.com/%00invalid",
				GeoSite: "https://example.com/geosite.dat",
				MMDB:    "https://example.com/geoip.metadb",
				ASN:     "https://example.com/GeoLite2-ASN.mmdb",
			},
		},
		Paths: config.Paths{
			MihomoData: t.TempDir(),
		},
	}
	log := logging.New(logging.LevelDebug, "test")
	err := PrepareGeoFiles(cfg, log)
	if err == nil || !strings.Contains(err.Error(), "sync downloads") {
		t.Errorf("expected sync downloads error, got: %v", err)
	}
}

func TestOpenDownloadStreamTextContentType(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{}

	textClient := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				h := make(http.Header)
				h.Set("Content-Type", "text/plain; charset=utf-8")
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     h,
					Body:       io.NopCloser(strings.NewReader("error")),
					Request:    req,
				}, nil
			},
		},
	}
	resp, err := openDownloadStream(ctx, textClient, cfg, "https://example.com/text", "example.com")
	if resp != nil && resp.Body != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Log(closeErr)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "text content-type") {
		t.Errorf("expected text content-type error, got: %v", err)
	}
}

func TestFetchMetaInvalidRedirectLocation(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				h := make(http.Header)
				h.Set("Location", "http://example.com/downgrade")
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     h,
					Body:       http.NoBody,
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{}
	_, _, err := fetchMeta(client, cfg, "https://example.com/badloc", "example.com")
	if err == nil || !strings.Contains(err.Error(), "resolve redirect location") {
		t.Errorf("expected resolve redirect location error, got: %v", err)
	}
}

func TestStreamToFileSaveError(t *testing.T) {
	client := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				h := make(http.Header)
				h.Set("Content-Type", "application/octet-stream")
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     h,
					Body:       io.NopCloser(strings.NewReader("valid content")),
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{}
	dir := t.TempDir()
	existingDir := filepath.Join(dir, "target_dir")
	if err := os.Mkdir(existingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	err := streamToFile(client, cfg, "https://example.com/file.dat", "example.com", existingDir)
	if err == nil {
		t.Error("expected error when streamToFile destination is a directory, got nil")
	}
}

func TestWriteCacheMetaResolveDirError(t *testing.T) {
	dir := t.TempDir()
	dummyFile := filepath.Join(dir, "dummy_file")
	if err := os.WriteFile(dummyFile, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeCacheMeta("https://example.com/test", http.Header{}, dummyFile)
	if err == nil || !strings.Contains(err.Error(), "resolve cache dir") {
		t.Errorf("expected resolve cache dir error, got: %v", err)
	}
}

type mockBodyCloseError struct {
	io.Reader
}

func (mockBodyCloseError) Close() error {
	return errors.New("simulated body close error")
}

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated read failure")
}

func TestFetchMetaBodyCloseError(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	client := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       mockBodyCloseError{Reader: strings.NewReader("")},
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{}
	_, _, err := fetchMeta(client, cfg, "https://example.com/file", "example.com")
	if err == nil || !strings.Contains(err.Error(), "close HEAD response") {
		t.Errorf("expected close HEAD response error, got: %v", err)
	}
}

func TestStreamToFileBodyCloseError(t *testing.T) {
	client := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				h := make(http.Header)
				h.Set("Content-Type", "application/octet-stream")
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     h,
					Body:       mockBodyCloseError{Reader: strings.NewReader("content")},
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{}
	dst := filepath.Join(t.TempDir(), "out.dat")
	err := streamToFile(client, cfg, "https://example.com/file", "example.com", dst)
	if err == nil || !strings.Contains(err.Error(), "close response body") {
		t.Errorf("expected close response body error, got: %v", err)
	}
}

func TestOpenDownloadStreamBodyCloseErrors(t *testing.T) {
	client404 := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       mockBodyCloseError{Reader: strings.NewReader("404")},
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{}
	resp404, err := openDownloadStream(context.Background(), client404, cfg, "https://example.com/file", "example.com")
	if resp404 != nil && resp404.Body != nil {
		if closeErr := resp404.Body.Close(); closeErr != nil {
			t.Log(closeErr)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "close response body on status 404") {
		t.Errorf("expected close error on status 404, got: %v", err)
	}

	clientHTML := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				h := make(http.Header)
				h.Set("Content-Type", "text/html; charset=utf-8")
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     h,
					Body:       mockBodyCloseError{Reader: strings.NewReader("<html>")},
					Request:    req,
				}, nil
			},
		},
	}
	respHTML, err := openDownloadStream(context.Background(), clientHTML, cfg, "https://example.com/file", "example.com")
	if respHTML != nil && respHTML.Body != nil {
		if closeErr := respHTML.Body.Close(); closeErr != nil {
			t.Log(closeErr)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "close response body on text content-type") {
		t.Errorf("expected close error on text content-type, got: %v", err)
	}
}

func TestDownloadChmodError(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() {
		resolveHost = origResolve
	})

	dir := t.TempDir()
	dst := filepath.Join(dir, "file.dat")
	client := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodHead {
					h := make(http.Header)
					h.Set("ETag", "123")
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     h,
						Body:       http.NoBody,
						Request:    req,
					}, nil
				}
				h := make(http.Header)
				h.Set("Content-Type", "application/octet-stream")
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     h,
					Body:       io.NopCloser(strings.NewReader("payload")),
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{
		Paths: config.Paths{
			MihomoData: dir,
		},
	}
	log := logging.New(logging.LevelDebug, "test")

	origChmod := osChmod
	defer func() { osChmod = origChmod }()
	osChmod = func(_ string, _ os.FileMode) error {
		return errors.New("mock chmod error")
	}

	err := download(client, cfg, log, "https://example.com/file.dat", dst)
	if err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Errorf("expected chmod error, got: %v", err)
	}
}

func TestDefaultDialerControl(t *testing.T) {
	if err := defaultDialerControl("tcp", "bad-address-no-port", nil); err == nil {
		t.Error("expected malformed dial address error, got nil")
	}
	if err := defaultDialerControl("tcp", "127.0.0.1:80", nil); err == nil {
		t.Error("expected restricted IP error, got nil")
	}
	if err := defaultDialerControl("tcp", "93.184.216.34:443", nil); err != nil {
		t.Errorf("expected success for valid IP, got: %v", err)
	}
	if err := defaultDialerControl("tcp", "example.com:443", nil); err != nil {
		t.Errorf("expected success for host name (non-ip), got: %v", err)
	}
}

func TestDownloadURLParseError(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() { resolveHost = origResolve })

	origParse := urlParse
	defer func() { urlParse = origParse }()
	urlParse = func(string) (*url.URL, error) {
		return nil, errors.New("mock parse error")
	}

	cfg := &config.Config{Paths: config.Paths{MihomoData: t.TempDir()}}
	log := logging.New(logging.LevelDebug, "test")
	err := download(mockNewHTTPClient(), cfg, log, "https://example.com/file.dat", filepath.Join(cfg.Paths.MihomoData, "file.dat"))
	if err == nil || !strings.Contains(err.Error(), "parse original URL") {
		t.Errorf("expected parse original URL error, got: %v", err)
	}
}

func TestDownloadStreamToFileError(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() { resolveHost = origResolve })

	dir := t.TempDir()
	client := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodHead {
					h := make(http.Header)
					h.Set("ETag", "123")
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     h,
						Body:       http.NoBody,
						Request:    req,
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader("server error")),
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{Paths: config.Paths{MihomoData: dir}}
	log := logging.New(logging.LevelDebug, "test")
	err := download(client, cfg, log, "https://example.com/file.dat", filepath.Join(dir, "file.dat"))
	if err == nil || !strings.Contains(err.Error(), "unexpected HTTP status 500") {
		t.Errorf("expected download streamToFile error, got: %v", err)
	}
}

func TestFetchMetaRequestAndDoErrors(t *testing.T) {
	origResolve := resolveHost
	resolveHost = mockResolveHost
	t.Cleanup(func() { resolveHost = origResolve })

	origReq := httpNewRequestWithContext
	defer func() { httpNewRequestWithContext = origReq }()
	httpNewRequestWithContext = func(context.Context, string, string, io.Reader) (*http.Request, error) {
		return nil, errors.New("mock req error")
	}

	cfg := &config.Config{}
	_, _, err := fetchMeta(mockNewHTTPClient(), cfg, "https://example.com/file", "example.com")
	if err == nil || !strings.Contains(err.Error(), "create HEAD request") {
		t.Errorf("expected create HEAD request error, got: %v", err)
	}

	httpNewRequestWithContext = origReq
	clientErr := &http.Client{
		Transport: &customRoundTripper{
			fn: func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("network failure")
			},
		},
	}
	_, _, err = fetchMeta(clientErr, cfg, "https://example.com/file", "example.com")
	if err == nil || !strings.Contains(err.Error(), "create HEAD request") {
		t.Errorf("expected network failure error, got: %v", err)
	}
}

func TestStreamToFileOpenStreamError(t *testing.T) {
	client := &http.Client{
		Transport: &customRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader("err")),
					Request:    req,
				}, nil
			},
		},
	}
	cfg := &config.Config{}
	dst := filepath.Join(t.TempDir(), "out.dat")
	err := streamToFile(client, cfg, "https://example.com/file", "example.com", dst)
	if err == nil || !strings.Contains(err.Error(), "unexpected HTTP status 500") {
		t.Errorf("expected open stream error, got: %v", err)
	}
}

func TestSaveStreamToDestinationTempErrors(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.dat")

	origCreate := osCreateTemp
	defer func() { osCreateTemp = origCreate }()
	osCreateTemp = func(_, _ string) (*os.File, error) {
		return nil, errors.New("mock create temp error")
	}
	err := saveStreamToDestination(strings.NewReader("data"), dst)
	if err == nil || !strings.Contains(err.Error(), "create temp file") {
		t.Errorf("expected create temp error, got: %v", err)
	}
	osCreateTemp = origCreate

	origChmod := tempFileChmod
	defer func() { tempFileChmod = origChmod }()
	tempFileChmod = func(_ *os.File, _ os.FileMode) error {
		return errors.New("mock chmod error")
	}
	err = saveStreamToDestination(strings.NewReader("data"), dst)
	if err == nil || !strings.Contains(err.Error(), "chmod temp file") {
		t.Errorf("expected chmod temp error, got: %v", err)
	}
	tempFileChmod = origChmod

	origSync := tempFileSync
	defer func() { tempFileSync = origSync }()
	tempFileSync = func(_ *os.File) error {
		return errors.New("mock sync error")
	}
	err = saveStreamToDestination(strings.NewReader("data"), dst)
	if err == nil || !strings.Contains(err.Error(), "sync temp file") {
		t.Errorf("expected sync temp error, got: %v", err)
	}
	tempFileSync = origSync

	origClose := tempFileClose
	defer func() { tempFileClose = origClose }()
	tempFileClose = func(_ *os.File) error {
		return errors.New("mock close error")
	}
	err = saveStreamToDestination(strings.NewReader("data"), dst)
	if err == nil || !strings.Contains(err.Error(), "close temp file") {
		t.Errorf("expected close temp error, got: %v", err)
	}
}

func TestWriteCacheMetaTempErrors(t *testing.T) {
	dir := t.TempDir()

	origCreate := osCreateTemp
	defer func() { osCreateTemp = origCreate }()
	osCreateTemp = func(_, _ string) (*os.File, error) {
		return nil, errors.New("mock create temp error")
	}
	err := writeCacheMeta("https://example.com/file", http.Header{}, dir)
	if err == nil || !strings.Contains(err.Error(), "create temp cache file") {
		t.Errorf("expected create temp cache error, got: %v", err)
	}
	osCreateTemp = origCreate

	origWrite := tempFileWriteString
	defer func() { tempFileWriteString = origWrite }()
	tempFileWriteString = func(_ *os.File, _ string) (int, error) {
		return 0, errors.New("mock write error")
	}
	err = writeCacheMeta("https://example.com/file", http.Header{}, dir)
	if err == nil || !strings.Contains(err.Error(), "write cache metadata") {
		t.Errorf("expected write cache metadata error, got: %v", err)
	}
	tempFileWriteString = origWrite

	origClose := tempFileClose
	defer func() { tempFileClose = origClose }()
	tempFileClose = func(_ *os.File) error {
		return errors.New("mock close error")
	}
	err = writeCacheMeta("https://example.com/file", http.Header{}, dir)
	if err == nil || !strings.Contains(err.Error(), "close temp cache file") {
		t.Errorf("expected close temp cache error, got: %v", err)
	}
}

func TestDefaultTempFileHelpers(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "helper_test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := defaultTempFileWriteString(f, "test"); err != nil {
		t.Errorf("defaultTempFileWriteString failed: %v", err)
	}
	if err := defaultTempFileSync(f); err != nil {
		t.Errorf("defaultTempFileSync failed: %v", err)
	}
	if err := defaultTempFileChmod(f, 0o600); err != nil {
		t.Errorf("defaultTempFileChmod failed: %v", err)
	}
	if err := defaultTempFileClose(f); err != nil {
		t.Errorf("defaultTempFileClose failed: %v", err)
	}

	if _, err := defaultTempFileWriteString(f, "test"); err == nil {
		t.Error("expected error on closed file, got nil")
	}
	if err := defaultTempFileSync(f); err == nil {
		t.Error("expected error on closed file, got nil")
	}
	if err := defaultTempFileChmod(f, 0o600); err == nil {
		t.Error("expected error on closed file, got nil")
	}
	if err := defaultTempFileClose(f); err == nil {
		t.Error("expected error on closed file, got nil")
	}
}

func mockValidateResolveSuccess(_ string) error {
	return nil
}

func mockValidateResolveFailure(_ string) error {
	return errors.New("mock dns failure")
}

func TestDefaultResolveHostSuccessAndError(t *testing.T) {
	origVal := validateResolveAndValidate
	defer func() { validateResolveAndValidate = origVal }()

	validateResolveAndValidate = mockValidateResolveSuccess
	if err := defaultResolveHost("example.com"); err != nil {
		t.Errorf("expected success, got: %v", err)
	}

	validateResolveAndValidate = mockValidateResolveFailure
	if err := defaultResolveHost("example.com"); err == nil {
		t.Error("expected error, got nil")
	}
}
