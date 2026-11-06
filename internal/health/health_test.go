package health

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/underhax/mihomo-warp-proxy/internal/config"
)

type errCloser struct {
	io.Reader
}

func (e *errCloser) Close() error {
	return errors.New("simulated body close error")
}

type errDrainReader struct{}

func (errDrainReader) Read(_ []byte) (int, error) {
	return 0, errors.New("simulated body drain error")
}

func (errDrainReader) Close() error {
	return nil
}

func TestCheck(t *testing.T) {
	origDoRequest := doRequest
	defer func() { doRequest = origDoRequest }()

	tests := []struct {
		mockDo      func(context.Context, *http.Client, *http.Request) (*http.Response, error)
		name        string
		target      string
		user        string
		pass        string
		wantErrPart string
		statusCode  int
		port        uint16
	}{
		{
			name:       "success status 204 with credentials",
			port:       7890,
			user:       "proxyuser",
			pass:       "proxypass",
			target:     "https://test.example.com/generate_204",
			statusCode: http.StatusNoContent,
			mockDo: func(_ context.Context, _ *http.Client, req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Request:    req,
				}, nil
			},
		},
		{
			name:       "success status 200 without credentials and default target",
			port:       1080,
			statusCode: http.StatusOK,
			mockDo: func(_ context.Context, _ *http.Client, req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Request:    req,
				}, nil
			},
		},
		{
			name:        "unexpected status code returns error",
			port:        7890,
			target:      "https://status.example.org/probe",
			wantErrPart: "unexpected status 502",
			mockDo: func(_ context.Context, _ *http.Client, req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadGateway,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Request:    req,
				}, nil
			},
		},
		{
			name:        "network execution failure returns error",
			port:        7890,
			target:      "https://down.example.net/health",
			wantErrPart: "simulated connection refusal",
			mockDo: func(_ context.Context, _ *http.Client, _ *http.Request) (*http.Response, error) {
				return nil, errors.New("simulated connection refusal")
			},
		},
		{
			name:        "response body close error is handled",
			port:        7890,
			target:      "https://close-err.example.com/check",
			wantErrPart: "close healthcheck response body",
			mockDo: func(_ context.Context, _ *http.Client, req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       &errCloser{Reader: bytes.NewReader(nil)},
					Request:    req,
				}, nil
			},
		},
		{
			name:        "response body drain error is handled",
			port:        7890,
			target:      "https://drain-err.example.com/check",
			wantErrPart: "drain healthcheck response body",
			mockDo: func(_ context.Context, _ *http.Client, req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Body:       errDrainReader{},
					Request:    req,
				}, nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doRequest = tc.mockDo

			cfg := &config.Config{
				ProxyPort: tc.port,
				ProxyUser: tc.user,
				ProxyPass: tc.pass,
			}

			var err error
			if tc.target != "" {
				err = Check(context.Background(), cfg, tc.target)
			} else {
				err = Check(context.Background(), cfg)
			}

			if tc.wantErrPart == "" {
				if err != nil {
					t.Fatalf("expected success, got: %v", err)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), tc.wantErrPart) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErrPart, err)
			}
		})
	}
}

func TestCheckInvalidRequest(t *testing.T) {
	cfg := &config.Config{
		ProxyPort: 7890,
	}

	err := Check(context.Background(), cfg, "http://[::1]:namedport")
	if err == nil || !strings.Contains(err.Error(), "create healthcheck request") {
		t.Fatalf("expected create healthcheck request error, got: %v", err)
	}
}

func TestDefaultDoRequestExecution(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://invalid.example.net:1", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Timeout: defaultHealthTimeout,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resp, err := defaultDoRequest(ctx, client, req)
	if resp != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Log(closeErr)
		}
	}
	if err == nil {
		t.Fatal("expected canceled context error from defaultDoRequest")
	}
}

type mockRoundTripper func(*http.Request) (*http.Response, error)

func (f mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDefaultDoRequestSuccess(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://health.example.com/status", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Transport: mockRoundTripper(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Request:    r,
			}, nil
		}),
	}

	resp, err := defaultDoRequest(context.Background(), client, req)
	if err != nil {
		t.Fatalf("unexpected error from defaultDoRequest: %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected response: %v", resp)
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
}
