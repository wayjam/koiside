package appstore

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ExtractAndMergeCookies parses Set-Cookie headers from rawHeaders and merges them into existing.
func ExtractAndMergeCookies(setCookies []string, existing []Cookie) []Cookie {
	if len(setCookies) == 0 {
		return existing
	}
	return MergeCookies(existing, ParseCookieHeaders(setCookies))
}

// MergeCookies updates existing cookies in-place by name while preserving insertion order.
func MergeCookies(existing, incoming []Cookie) []Cookie {
	out := make([]Cookie, 0, len(existing)+len(incoming))
	index := make(map[string]int, len(existing)+len(incoming))
	for _, c := range existing {
		if idx, ok := index[c.Name]; ok {
			out[idx] = c
		} else {
			index[c.Name] = len(out)
			out = append(out, c)
		}
	}
	for _, c := range incoming {
		if idx, ok := index[c.Name]; ok {
			out[idx] = c
		} else {
			index[c.Name] = len(out)
			out = append(out, c)
		}
	}
	return out
}

// BuildCookieHeader returns a Cookie request header matching host, path, scheme, and expiration.
func BuildCookieHeader(cookies []Cookie, rawURL string) string {
	return buildCookieHeaderAt(cookies, rawURL, time.Now())
}

func buildCookieHeaderAt(cookies []Cookie, rawURL string, now time.Time) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	reqPath := u.Path
	if reqPath == "" {
		reqPath = "/"
	}
	scheme := u.Scheme
	nowSec := float64(now.UnixNano()) / 1e9

	var valid []string
	for _, c := range cookies {
		if c.Name == "" || c.Value == "" {
			continue
		}
		if c.Domain != "" && !matchesDomain(c.Domain, host) {
			continue
		}
		if !matchesPath(c.Path, reqPath) {
			continue
		}
		if c.ExpiresAt > 0 && c.ExpiresAt <= nowSec {
			continue
		}
		if c.Secure && scheme != "https" {
			continue
		}
		valid = append(valid, c.Name+"="+c.Value)
	}
	return strings.Join(valid, "; ")
}

// ParseCookieHeaders parses HTTP Set-Cookie header strings into Cookie structs.
func ParseCookieHeaders(headers []string) []Cookie {
	return parseCookieHeadersAt(headers, time.Now())
}

func parseCookieHeadersAt(headers []string, now time.Time) []Cookie {
	var out []Cookie
	for _, hdr := range headers {
		if parsed, err := http.ParseSetCookie(hdr); err == nil && parsed.Name != "" {
			c := Cookie{
				Name:     parsed.Name,
				Value:    parsed.Value,
				Path:     parsed.Path,
				Domain:   strings.TrimPrefix(parsed.Domain, "."),
				HTTPOnly: parsed.HttpOnly,
				Secure:   parsed.Secure,
			}
			if c.Path == "" {
				c.Path = "/"
			}
			if parsed.MaxAge > 0 {
				c.ExpiresAt = float64(now.UnixNano())/1e9 + float64(parsed.MaxAge)
			} else if !parsed.Expires.IsZero() {
				c.ExpiresAt = float64(parsed.Expires.UnixNano()) / 1e9
			}
			out = append(out, c)
			continue
		}

		parts := strings.Split(hdr, ";")
		if len(parts) == 0 {
			continue
		}
		nv := strings.TrimSpace(parts[0])
		eq := strings.IndexByte(nv, '=')
		if eq < 0 {
			continue
		}
		name := strings.TrimSpace(nv[:eq])
		val := strings.TrimSpace(nv[eq+1:])
		if name == "" {
			continue
		}
		c := Cookie{Name: name, Value: val, Path: "/"}
		for _, rawAttr := range parts[1:] {
			attr := strings.TrimSpace(rawAttr)
			attrEq := strings.IndexByte(attr, '=')
			attrName := strings.ToLower(strings.TrimSpace(attr))
			attrVal := ""
			if attrEq >= 0 {
				attrName = strings.ToLower(strings.TrimSpace(attr[:attrEq]))
				attrVal = strings.TrimSpace(attr[attrEq+1:])
			}
			switch attrName {
			case "path":
				if attrVal != "" {
					c.Path = attrVal
				} else {
					c.Path = "/"
				}
			case "domain":
				c.Domain = strings.TrimPrefix(attrVal, ".")
			case "max-age":
				if sec, err := strconv.Atoi(attrVal); err == nil {
					c.ExpiresAt = float64(now.UnixNano())/1e9 + float64(sec)
				}
			case "expires":
				if t, err := http.ParseTime(attrVal); err == nil {
					c.ExpiresAt = float64(t.UnixNano()) / 1e9
				}
			case "httponly":
				c.HTTPOnly = true
			case "secure":
				c.Secure = true
			}
		}
		out = append(out, c)
	}
	return out
}

func matchesDomain(cookieDomain, requestHost string) bool {
	norm := strings.ToLower(cookieDomain)
	host := strings.ToLower(requestHost)
	return host == norm || strings.HasSuffix(host, "."+norm)
}

func matchesPath(cookiePath, requestPath string) bool {
	if cookiePath == "" || cookiePath == "/" {
		return true
	}
	if requestPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(requestPath, cookiePath) {
		return false
	}
	return strings.HasSuffix(cookiePath, "/") || requestPath[len(cookiePath)] == '/'
}
