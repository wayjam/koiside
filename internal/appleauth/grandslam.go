package appleauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"howett.net/plist"
)

const defaultGrandSlamBagURL = "https://gsa.apple.com/grandslam/GsService2/lookup"

// AuthError represents a structured GrandSlam status error returned by Apple.
type AuthError struct {
	Code    int64
	Message string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("Apple auth error %d: %s", e.Code, e.Message)
}

// GrandSlamClient talks to Apple GrandSlam (GSA) endpoints with Apple Root CA trust.
type GrandSlamClient struct {
	httpClient *http.Client
	clientInfo ClientInfo
	bagURL     string

	mu     sync.Mutex
	urlBag map[string]any
}

// NewGrandSlamClient builds an HTTP client that trusts system CAs + bundled Apple Root CA.
func NewGrandSlamClient(clientInfo ClientInfo, _ []byte) (*GrandSlamClient, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: true,
	}
	return &GrandSlamClient{
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
		clientInfo: clientInfo,
		bagURL:     defaultGrandSlamBagURL,
	}, nil
}

// NewGrandSlamClientWithHTTP creates a GrandSlamClient backed by a custom HTTP client and bag URL (for tests).
func NewGrandSlamClientWithHTTP(httpClient *http.Client, clientInfo ClientInfo, bagURL string) *GrandSlamClient {
	if bagURL == "" {
		bagURL = defaultGrandSlamBagURL
	}
	return &GrandSlamClient{
		httpClient: httpClient,
		clientInfo: clientInfo,
		bagURL:     bagURL,
	}
}

// HTTPClient returns the underlying HTTP client.
func (g *GrandSlamClient) HTTPClient() *http.Client { return g.httpClient }

// ClientInfo returns the platform client info headers.
func (g *GrandSlamClient) ClientInfo() ClientInfo { return g.clientInfo }

// EnsureBag fetches and caches the GrandSlam URL bag.
func (g *GrandSlamClient) EnsureBag(ctx context.Context) error {
	g.mu.Lock()
	if g.urlBag != nil {
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.bagURL, nil)
	if err != nil {
		return err
	}
	g.applyBaseHeaders(req.Header, "text/xml")

	resp, err := g.send(req)
	if err != nil {
		return fmt.Errorf("appleauth: fetch GrandSlam bag: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("appleauth: GrandSlam bag HTTP %d", resp.StatusCode)
	}
	var root map[string]any
	if _, err := plist.Unmarshal(body, &root); err != nil {
		return fmt.Errorf("appleauth: parse GrandSlam bag: %w", err)
	}
	urls, _ := root["urls"].(map[string]any)
	if len(urls) == 0 {
		return errors.New("appleauth: GrandSlam bag missing urls")
	}

	g.mu.Lock()
	g.urlBag = urls
	g.mu.Unlock()
	return nil
}

// URL resolves a named endpoint from the GrandSlam URL bag.
func (g *GrandSlamClient) URL(key string) (string, error) {
	g.mu.Lock()
	urls := g.urlBag
	g.mu.Unlock()
	if urls == nil {
		return "", fmt.Errorf("appleauth: URL bag not loaded for %s", key)
	}
	u, _ := urls[key].(string)
	if u == "" {
		return "", fmt.Errorf("appleauth: URL bag missing %s", key)
	}
	return u, nil
}

func (g *GrandSlamClient) applyBaseHeaders(h http.Header, contentType string) {
	if contentType == "" {
		contentType = "text/xml"
	}
	h.Set("Content-Type", contentType)
	if contentType == "application/json" || contentType == "application/vnd.api+json" {
		h.Set("Accept", contentType)
	} else {
		h.Set("Accept", "text/x-xml-plist")
	}
	h.Set("X-Mme-Client-Info", g.clientInfo.ClientInfo)
	h.Set("User-Agent", g.clientInfo.UserAgent)
	h.Set("X-Xcode-Version", "27.0 (27A5218g)")
	h.Set("X-Apple-App-Info", "com.apple.gs.xcode.auth")
}

// DoRequest executes an HTTP request with GrandSlam base headers, preserving any explicit Content-Type.
func (g *GrandSlamClient) DoRequest(req *http.Request, smsJSON bool) (*http.Response, error) {
	ct := req.Header.Get("Content-Type")
	if ct == "" {
		if smsJSON {
			ct = "application/json"
		} else {
			ct = "text/xml"
		}
	}
	g.applyBaseHeaders(req.Header, ct)
	return g.send(req)
}

func (g *GrandSlamClient) send(req *http.Request) (*http.Response, error) {
	h := req.Header
	info := ClientInfo{ClientInfo: h.Get("X-Mme-Client-Info"), UserAgent: h.Get("User-Agent")}
	compatible := info.forApple()
	if compatible.ClientInfo != info.ClientInfo {
		h.Set("X-Mme-Client-Info", compatible.ClientInfo)
	}
	if compatible.UserAgent != info.UserAgent {
		h.Set("User-Agent", compatible.UserAgent)
	}
	return g.httpClient.Do(req)
}

// PlistRequest posts an XML plist to url and unmarshals the inner Response dictionary.
func (g *GrandSlamClient) PlistRequest(ctx context.Context, targetURL string, payload map[string]any, extra http.Header) (map[string]any, error) {
	raw, err := plist.Marshal(payload, plist.XMLFormat)
	if err != nil {
		return nil, err
	}

	var lastStatus int
	var lastBody []byte
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		g.applyBaseHeaders(req.Header, "text/xml")
		for k, vals := range extra {
			for _, v := range vals {
				req.Header.Set(k, v)
			}
		}

		resp, err := g.send(req)
		if err != nil {
			lastErr = err
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "EOF") {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Duration(attempt+1) * 400 * time.Millisecond):
					continue
				}
			}
			return nil, fmt.Errorf("appleauth: GrandSlam request failed: %w", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
				continue
			}
			return nil, readErr
		}
		lastStatus = resp.StatusCode
		lastBody = body

		var root map[string]any
		if _, err := plist.Unmarshal(body, &root); err == nil {
			if respDict, _ := root["Response"].(map[string]any); respDict != nil {
				if status, _ := respDict["Status"].(map[string]any); status != nil {
					if statusErr := checkGrandSlamStatus(respDict); statusErr != nil {
						return nil, statusErr
					}
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						return respDict, nil
					}
				}
			}
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 600 * time.Millisecond):
				continue
			}
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, formatGrandSlamHTTPError(resp.StatusCode, body, false)
		}

		if root == nil {
			if _, err := plist.Unmarshal(body, &root); err != nil {
				return nil, fmt.Errorf("appleauth: invalid GrandSlam response plist: %w", err)
			}
		}
		respDict, _ := root["Response"].(map[string]any)
		if respDict == nil {
			return nil, errors.New("appleauth: GrandSlam response missing Response")
		}
		return respDict, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("appleauth: GrandSlam request failed after retries: %w", lastErr)
	}
	return nil, formatGrandSlamHTTPError(lastStatus, lastBody, true)
}

func formatGrandSlamHTTPError(statusCode int, body []byte, afterRetries bool) error {
	preview := strings.TrimSpace(string(body))
	if len(preview) > 200 {
		preview = preview[:200]
	}
	suffix := ""
	if afterRetries {
		suffix = " after retries"
	}
	if preview != "" {
		return fmt.Errorf("appleauth: GrandSlam HTTP %d%s: %s", statusCode, suffix, preview)
	}
	return fmt.Errorf("appleauth: GrandSlam HTTP %d%s", statusCode, suffix)
}

func checkGrandSlamStatus(resp map[string]any) error {
	status, _ := resp["Status"].(map[string]any)
	if status == nil {
		status = resp
	}
	if ec, ok := int64Value(status["ec"]); ok && ec != 0 {
		em, _ := status["em"].(string)
		if em == "" {
			em = "Unknown error"
		}
		return &AuthError{Code: ec, Message: em}
	}
	return nil
}

func int64Value(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case uint64:
		return int64(x), true
	default:
		return 0, false
	}
}
