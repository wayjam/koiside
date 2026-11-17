package appstore

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"howett.net/plist"
)

// DefaultAuthURL is the fallback Store authentication endpoint when bag fetch fails or omits it.
const DefaultAuthURL = "https://auth.itunes.apple.com/auth/v1/native/fast/"

var (
	buyHostRe        = regexp.MustCompile(`^(?:buy|p\d+-buy)\.itunes\.apple\.com$`)
	legacyAuthPathRe = regexp.MustCompile(`^/WebObjects/MZFinance\.woa/wa/authenticate/*$`)
)

// BagOutput holds public Apple service URLs resolved from init.itunes.apple.com/bag.xml.
type BagOutput struct {
	AuthURL       string
	RedownloadURL string
	UpdateURL     string
}

// NormalizeAuthURL ensures native and legacy Apple authentication URLs carry their required path/trailing slash.
func NormalizeAuthURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return rawURL
	}
	host := u.Hostname()
	if buyHostRe.MatchString(host) && legacyAuthPathRe.MatchString(u.Path) {
		u.Path = "/WebObjects/MZFinance.woa/wa/authenticate/"
		return u.String()
	}
	if host != "auth.itunes.apple.com" {
		return rawURL
	}
	p := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(p, "/fast") {
		p += "/fast"
	}
	u.Path = p + "/"
	return u.String()
}

// FetchBag fetches Apple's public bag plist and falls back to DefaultAuthURL on upstream failures.
func (c *Client) FetchBag(ctx context.Context, deviceID string) BagOutput {
	rawURL := "https://init.itunes.apple.com/bag.xml?guid=" + url.QueryEscape(deviceID)
	if c != nil && c.BagURL != "" {
		u, err := url.Parse(c.BagURL)
		if err == nil {
			q := u.Query()
			q.Set("guid", deviceID)
			u.RawQuery = q.Encode()
			rawURL = u.String()
		}
	}

	resp, err := c.doAppleRequest(ctx, "GET", rawURL, map[string]string{
		"Accept": "application/xml",
	}, nil, nil)
	if err != nil || resp.Status < 200 || resp.Status >= 300 {
		return BagOutput{AuthURL: DefaultAuthURL}
	}

	plistBytes, err := extractPlistXML(resp.Body)
	if err != nil {
		return BagOutput{AuthURL: DefaultAuthURL}
	}

	var dict map[string]any
	if _, err := plist.Unmarshal(plistBytes, &dict); err != nil {
		return BagOutput{AuthURL: DefaultAuthURL}
	}

	urlBag, _ := dict["urlBag"].(map[string]any)
	authURL, _ := dict["authenticateAccount"].(string)
	if authURL == "" && urlBag != nil {
		authURL, _ = urlBag["authenticateAccount"].(string)
	}
	redownloadURL, _ := dict["redownloadProduct"].(string)
	if redownloadURL == "" && urlBag != nil {
		redownloadURL, _ = urlBag["redownloadProduct"].(string)
	}
	updateURL, _ := dict["updateProduct"].(string)
	if updateURL == "" && urlBag != nil {
		updateURL, _ = urlBag["updateProduct"].(string)
	}

	if authURL == "" {
		return BagOutput{
			AuthURL:       DefaultAuthURL,
			RedownloadURL: redownloadURL,
			UpdateURL:     updateURL,
		}
	}

	return BagOutput{
		AuthURL:       NormalizeAuthURL(authURL),
		RedownloadURL: redownloadURL,
		UpdateURL:     updateURL,
	}
}

func extractPlistXML(body []byte) ([]byte, error) {
	start := bytes.Index(body, []byte("<plist"))
	end := bytes.LastIndex(body, []byte("</plist>"))
	if start >= 0 && end > start {
		return body[start : end+len("</plist>")], nil
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && bytes.HasPrefix(trimmed, []byte("bplist")) {
		return trimmed, nil
	}
	return nil, errors.New("appstore: no plist in bag response")
}
