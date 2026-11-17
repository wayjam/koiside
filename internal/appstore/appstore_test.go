package appstore

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"howett.net/plist"
	"koiside/internal/appstore/sap"
)

func TestBagNormalizationAndFallback(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://auth.itunes.apple.com/auth/v1/native", "https://auth.itunes.apple.com/auth/v1/native/fast/"},
		{"https://auth.itunes.apple.com/auth/v1/native/fast", "https://auth.itunes.apple.com/auth/v1/native/fast/"},
		{"https://auth.itunes.apple.com/auth/v1/native/fast/", "https://auth.itunes.apple.com/auth/v1/native/fast/"},
		{
			"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate?routing=opaque&guid=aabb",
			"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/?routing=opaque&guid=aabb",
		},
		{
			"https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate",
			"https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/",
		},
		{"https://example.invalid/WebObjects/MZFinance.woa/wa/authenticate", "https://example.invalid/WebObjects/MZFinance.woa/wa/authenticate"},
	}
	for _, tc := range cases {
		if got := NormalizeAuthURL(tc.in); got != tc.want {
			t.Fatalf("NormalizeAuthURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("mode") {
		case "urlbag":
			b, _ := plist.Marshal(map[string]any{
				"urlBag": map[string]any{
					"authenticateAccount": "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate",
					"updateProduct":       "https://downloaddispatch.itunes.apple.com/up/updateProduct",
				},
			}, plist.XMLFormat)
			_, _ = w.Write(b)
		case "missing":
			b, _ := plist.Marshal(map[string]any{
				"urlBag": map[string]any{
					"updateProduct": "https://downloaddispatch.itunes.apple.com/up/updateProduct",
				},
			}, plist.XMLFormat)
			_, _ = w.Write(b)
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()

	c := NewClient()
	c.BagURL = srv.URL + "?mode=urlbag"
	bag := c.FetchBag(context.Background(), "aabbccddeeff")
	if bag.AuthURL != "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/" {
		t.Fatalf("unexpected AuthURL: %s", bag.AuthURL)
	}
	if bag.UpdateURL != "https://downloaddispatch.itunes.apple.com/up/updateProduct" {
		t.Fatalf("unexpected UpdateURL: %s", bag.UpdateURL)
	}

	c.BagURL = srv.URL + "?mode=missing"
	bag = c.FetchBag(context.Background(), "aabbccddeeff")
	if bag.AuthURL != DefaultAuthURL || bag.UpdateURL == "" {
		t.Fatalf("expected default AuthURL + UpdateURL, got %+v", bag)
	}

	c.BagURL = srv.URL + "?mode=err"
	bag = c.FetchBag(context.Background(), "aabbccddeeff")
	if bag.AuthURL != DefaultAuthURL {
		t.Fatalf("expected DefaultAuthURL on HTTP error, got %+v", bag)
	}
}

func TestCookieParsingAndMatching(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cookies := parseCookieHeadersAt([]string{
		"session=abc123; Domain=.itunes.apple.com; Path=/WebObjects; Max-Age=60; Secure; HttpOnly",
		"expired=old; Domain=itunes.apple.com; Path=/; Expires=Wed, 21 Oct 2015 07:28:00 GMT",
	}, now)
	if len(cookies) != 2 {
		t.Fatalf("expected 2 parsed cookies, got %d", len(cookies))
	}
	hdr := buildCookieHeaderAt(cookies, "https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct", now)
	if hdr != "session=abc123" {
		t.Fatalf("unexpected cookie header: %q", hdr)
	}
	if hdrHTTP := buildCookieHeaderAt(cookies, "http://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct", now); hdrHTTP != "" {
		t.Fatalf("secure cookie leaked over HTTP: %q", hdrHTTP)
	}
	merged := MergeCookies(cookies, []Cookie{{Name: "session", Value: "updated", Path: "/"}})
	if len(merged) != 2 || merged[0].Value != "updated" {
		t.Fatalf("unexpected merged cookies: %+v", merged)
	}
}

type fakeSigner struct {
	calls [][]byte
}

func (f *fakeSigner) Sign(body []byte) ([]byte, error) {
	cp := append([]byte(nil), body...)
	f.calls = append(f.calls, cp)
	return []byte{byte(len(f.calls))}, nil
}

type failingSigner struct{}

func (failingSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("SAP signing failed")
}

func TestAuthenticatorSAPFlowRedirects2FAAndRetry(t *testing.T) {
	var step atomic.Int32
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bag.xml":
			b, _ := plist.Marshal(map[string]any{
				"authenticateAccount": srvURL + "/auth/v1/native/fast/",
			}, plist.XMLFormat)
			_, _ = w.Write(b)
		case "/auth/v1/native/fast/":
			http.Redirect(w, r, srvURL+"/WebObjects/MZFinance.woa/wa/authenticate", http.StatusFound)
		case "/WebObjects/MZFinance.woa/wa/authenticate":
			n := step.Add(1)
			rawBody, _ := io.ReadAll(r.Body)
			var reqDict map[string]any
			_, _ = plist.Unmarshal(rawBody, &reqDict)
			if r.Header.Get("X-Apple-ActionSignature") == "" {
				t.Fatalf("missing X-Apple-ActionSignature on step %d", n)
			}
			switch n {
			case 1:
				w.Header().Set("x-set-apple-store-front", "143441-1")
				w.Header().Set("pod", "25")
				w.Header().Add("Set-Cookie", "session=continued; Path=/")
				b, _ := plist.Marshal(map[string]any{
					"failureType":     "",
					"customerMessage": "MZFinance.BadLogin.Configurator_message",
				}, plist.XMLFormat)
				_, _ = w.Write(b)
			case 2:
				if reqDict["attempt"] != "2" || reqDict["password"] != "password123456" {
					t.Fatalf("unexpected 2FA continuation payload: %+v", reqDict)
				}
				if !strings.Contains(r.Header.Get("Cookie"), "session=continued") {
					t.Fatalf("expected continued cookie, got %q", r.Header.Get("Cookie"))
				}
				w.WriteHeader(http.StatusNoContent)
			case 3:
				b, _ := plist.Marshal(map[string]any{
					"accountInfo": map[string]any{
						"appleId": "user@example.invalid",
						"address": map[string]any{
							"firstName": "Test",
							"lastName":  "User",
						},
					},
					"passwordToken": "test-token",
					"dsPersonId":    "123",
				}, plist.XMLFormat)
				_, _ = w.Write(b)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	client := NewClient()
	client.BagURL = srvURL + "/bag.xml"
	client.AuthSleep = func(_ context.Context, _ time.Duration) error { return nil }

	signer := &fakeSigner{}
	auth := NewAuthenticator(client, "aabbccddeeff", nil)
	auth.connectSAPFunc = func(context.Context) (sap.Signer, error) {
		return signer, nil
	}

	_, err := auth.Authenticate(context.Background(), "user@example.invalid", "password", "", nil)
	var authErr *AuthError
	if !errors.As(err, &authErr) || !authErr.CodeRequired {
		t.Fatalf("expected CodeRequired AuthError, got %v", err)
	}

	var retries int
	acc, err := auth.Authenticate(context.Background(), "user@example.invalid", "password", "123456", func(r AuthRetry) {
		retries++
		if r.Status != http.StatusNoContent {
			t.Fatalf("expected 204 retry, got %d", r.Status)
		}
	})
	if err != nil {
		t.Fatalf("Authenticate 2FA continuation failed: %v", err)
	}
	if retries != 1 {
		t.Fatalf("expected 1 retry callback, got %d", retries)
	}
	if acc.Store != "143441" || acc.Pod != "25" || acc.DSID != "123" || acc.PasswordToken != "test-token" {
		t.Fatalf("unexpected account: %+v", acc)
	}
	if len(signer.calls) != 4 {
		t.Fatalf("expected 4 signatures (redirect + 2FA challenge + 204 retry + final), got %d", len(signer.calls))
	}

	// Ensure credentials are never sent when SAP setup/signing fails.
	called := false
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer failSrv.Close()
	c2 := NewClient()
	c2.BagURL = srvURL + "/bag.xml"
	a2 := NewAuthenticator(c2, "aabbccddeeff", nil)
	a2.connectSAPFunc = func(context.Context) (sap.Signer, error) {
		return failingSigner{}, nil
	}
	if _, err := a2.Authenticate(context.Background(), "user@example.invalid", "password", "", nil); err == nil {
		t.Fatal("expected error when SAP signing fails")
	}
	if called {
		t.Fatal("credentials must not be sent on SAP failure")
	}
}

func TestSearchLookupPurchaseAndDownloadRecovery(t *testing.T) {
	var stage atomic.Int32
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/search":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resultCount": 1,
				"results": []map[string]any{{
					"trackId":          736536022,
					"bundleId":         "tv.danmaku.bilianime",
					"trackName":        "Bili",
					"version":          "9.13.0",
					"price":            0,
					"artworkUrl512":    "https://example.invalid/icon.png",
					"fileSizeBytes":    "1234567",
					"minimumOsVersion": "15.0",
				}},
			})
		case "/lookup":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resultCount": 1,
				"results": []map[string]any{{
					"trackId":       736536022,
					"bundleId":      "tv.danmaku.bilianime",
					"trackName":     "Bili",
					"version":       "9.13.0",
					"fileSizeBytes": 1234567,
				}},
			})
		case "/WebObjects/MZFinance.woa/wa/buyProduct":
			b, _ := plist.Marshal(map[string]any{
				"failureType":     "5002",
				"customerMessage": "An unknown error has occurred",
			}, plist.XMLFormat)
			_, _ = w.Write(b)
		case "/bag.xml":
			b, _ := plist.Marshal(map[string]any{
				"redownloadProduct": "https://downloaddispatch.itunes.apple.com/r/redownload",
				"updateProduct":     "https://downloaddispatch.itunes.apple.com/up/updateProduct",
			}, plist.XMLFormat)
			_, _ = w.Write(b)
		case "/WebObjects/MZStorePlatform.woa/wa/lookup":
			if r.Header.Get("Cookie") != "" || r.Header.Get("X-Token") != "" {
				t.Fatal("public catalog lookup must not receive account headers or cookies")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"results": map[string]any{
					"736536022": map[string]any{
						"bundleId": "tv.danmaku.bilianime",
						"offers": []map[string]any{{
							"version": map[string]any{"externalId": 891730218},
						}},
					},
				},
			})
		case "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct":
			b, _ := plist.Marshal(map[string]any{
				"status":     0,
				"authorized": false,
				"songList":   []any{},
			}, plist.XMLFormat)
			_, _ = w.Write(b)
		case "/r/redownload":
			stage.Store(1)
			w.WriteHeader(http.StatusInternalServerError)
		case "/up/updateProduct":
			raw, _ := io.ReadAll(r.Body)
			var req map[string]any
			_, _ = plist.Unmarshal(raw, &req)
			if req["appExtVrsId"] != "891730218" {
				t.Fatalf("expected pinned appExtVrsId 891730218, got %v", req["appExtVrsId"])
			}
			b, _ := plist.Marshal(map[string]any{
				"status": 0,
				"songList": []any{map[string]any{
					"URL": "https://example.apple.com/app.ipa",
					"metadata": map[string]any{
						"itemId":                             736536022,
						"softwareVersionBundleId":            "tv.danmaku.bilianime",
						"softwareVersionExternalIdentifier":  891730218,
						"softwareVersionExternalIdentifiers": []any{100, 891730218},
						"bundleShortVersionString":           "9.13.0",
						"bundleVersion":                      "913000",
						"passwordToken":                      "secret-should-strip",
						"releaseDate":                        "2026-10-01T00:00:00Z",
					},
					"sinfs": []any{map[string]any{
						"id":   0,
						"sinf": []byte("sinf-bytes"),
					}},
				}},
			}, plist.XMLFormat)
			_, _ = w.Write(b)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	c := NewClient()
	c.SearchBase = srvURL
	c.BagURL = srvURL + "/bag.xml"
	c.CatalogHost = strings.TrimPrefix(srvURL, "http://")

	apps, err := c.SearchApps(context.Background(), "bili", "CN", "software", 10)
	if err != nil || len(apps) != 1 || apps[0].FileSizeBytes != 1234567 {
		t.Fatalf("unexpected SearchApps result: %+v, err=%v", apps, err)
	}
	looked, err := c.LookupApp(context.Background(), "tv.danmaku.bilianime", 0, "CN")
	if err != nil || looked == nil || looked.ID != 736536022 {
		t.Fatalf("unexpected LookupApp result: %+v, err=%v", looked, err)
	}

	acc := Account{
		Email:            "test@example.invalid",
		Store:            "143465-19,32",
		Pod:              "10",
		DSID:             "123",
		PasswordToken:    "tok",
		DeviceIdentifier: "aabbccddeeff",
	}

	pRes, err := c.PurchaseApp(context.Background(), acc, *looked)
	if err != nil || !pRes.AlreadyOwned {
		t.Fatalf("expected AlreadyOwned for 5002, got %+v, err=%v", pRes, err)
	}

	dl, _, err := c.GetDownloadInfo(context.Background(), acc, *looked, "")
	if err != nil {
		t.Fatalf("GetDownloadInfo failed: %v", err)
	}
	if stage.Load() != 1 {
		t.Fatal("expected redownload fallback to trigger before updateProduct")
	}
	if dl.DownloadURL != "https://example.apple.com/app.ipa" || len(dl.Sinfs) != 1 {
		t.Fatalf("unexpected DownloadOutput: %+v", dl)
	}
	if bytes.Contains(dl.ITunesMetadata, []byte("passwordToken")) {
		t.Fatal("passwordToken leaked into iTunesMetadata")
	}

	versions, _, err := c.ListVersions(context.Background(), acc, *looked)
	if err != nil || len(versions) != 2 || versions[0] != "891730218" || versions[1] != "100" {
		t.Fatalf("unexpected version list: %v, err=%v", versions, err)
	}

	meta, _, err := c.GetVersionMetadata(context.Background(), acc, *looked, "891730218")
	if err != nil || meta.DisplayVersion != "9.13.0" {
		t.Fatalf("unexpected version metadata: %+v, err=%v", meta, err)
	}
}

func TestDispatchValidationAndFallbackBoundaries(t *testing.T) {
	for _, tc := range []struct {
		dict map[string]any
		want bool
	}{
		{map[string]any{"status": 0, "songList": []any{}}, true},
		{map[string]any{"failureType": "5002", "songList": []any{}}, true},
		{map[string]any{"customerMessage": "App No Longer Available"}, true},
		{map[string]any{"failureType": "2042"}, false},
		{map[string]any{"failureType": "9610"}, false},
		{map[string]any{"status": -1}, false},
		{map[string]any{"action": map[string]any{"url": "https://buy.itunes.apple.com/termsPage"}}, false},
		{map[string]any{"dialog": map[string]any{"explanation": "Review"}}, false},
		{map[string]any{"customerMessage": "Accept new terms"}, false},
	} {
		if got := NeedsDownloadFallback(tc.dict); got != tc.want {
			t.Fatalf("NeedsDownloadFallback(%v) = %v, want %v", tc.dict, got, tc.want)
		}
	}

	for _, bad := range []string{
		"http://downloaddispatch.itunes.apple.com/up/updateProduct",
		"https://example.com/up/updateProduct",
		"https://downloaddispatch.itunes.apple.com/up/updateProduct?token=1",
		"https://user@downloaddispatch.itunes.apple.com/up/updateProduct",
	} {
		if _, ok := DispatchEndpoint(bad, "update", "dev"); ok {
			t.Fatalf("expected DispatchEndpoint(%q) to fail", bad)
		}
	}
}

func TestChunkedDownloaderAndSinfInjection(t *testing.T) {
	payload := make([]byte, 2*1024*1024+137)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Accept-Ranges", "bytes")
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
			w.WriteHeader(http.StatusOK)
			return
		}
		rng := r.Header.Get("Range")
		if rng == "" {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
			_, _ = w.Write(payload)
			return
		}
		var start, end int
		_, _ = fmt.Sscanf(rng, "bytes=%d-%d", &start, &end)
		if end >= len(payload) {
			end = len(payload) - 1
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(payload[start : end+1])
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "dl.bin")
	if err := DownloadFile(context.Background(), srv.URL+"/file.ipa", dest, DownloadOptions{
		Threads:           4,
		AllowInsecureHTTP: true,
	}); err != nil {
		t.Fatalf("DownloadFile chunked failed: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("chunked downloaded bytes do not match source")
	}

	// Test SINF + iTunesMetadata injection (both Manifest.plist and fallback Info.plist).
	ipa1 := createTestIPA(t, dir, "MultiSinf", "CustomExec", []string{"SC_Info/main.sinf", "SC_Info/ext.sinf"})
	metaXML, _ := plist.Marshal(map[string]any{
		"itemId":                  736536022,
		"softwareVersionBundleId": "com.example.multi",
		"apple-id":                "user@example.invalid",
	}, plist.XMLFormat)
	if err := InjectSinfAndMetadata(ipa1, []Sinf{
		{ID: 0, Data: []byte("sinf-1")},
		{ID: 1, Data: []byte("sinf-2")},
	}, metaXML); err != nil {
		t.Fatalf("InjectSinfAndMetadata manifest failed: %v", err)
	}
	assertZipEntryEquals(t, ipa1, "Payload/MultiSinf.app/SC_Info/main.sinf", []byte("sinf-1"))
	assertZipEntryEquals(t, ipa1, "Payload/MultiSinf.app/SC_Info/ext.sinf", []byte("sinf-2"))
	metaEntry := readZipEntryBytes(t, ipa1, "iTunesMetadata.plist")
	if !VerifyBinaryPlist(metaEntry) {
		t.Fatalf("expected binary plist iTunesMetadata.plist, got %q", metaEntry[:min(16, len(metaEntry))])
	}

	ipa2 := createTestIPA(t, dir, "FallbackApp", "RealExec", nil)
	if err := InjectSinfAndMetadata(ipa2, []Sinf{
		{ID: 0, Data: []byte(base64.StdEncoding.EncodeToString([]byte("raw")))},
	}, nil); err != nil {
		t.Fatalf("InjectSinfAndMetadata fallback failed: %v", err)
	}
	assertZipEntryExists(t, ipa2, "Payload/FallbackApp.app/SC_Info/RealExec.sinf")

	// Reject path traversal in Manifest.plist SinfPaths.
	ipaBad := createTestIPA(t, dir, "TraversalApp", "Exec", []string{"../../evil.sinf"})
	if err := InjectSinfAndMetadata(ipaBad, []Sinf{{ID: 0, Data: []byte("x")}}, nil); err == nil {
		t.Fatal("expected traversal error")
	}
}

func createTestIPA(t *testing.T, dir, bundleName, execName string, sinfPaths []string) string {
	t.Helper()
	p := filepath.Join(dir, bundleName+".ipa")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	infoData, _ := plist.Marshal(map[string]any{
		"CFBundleExecutable": execName,
		"CFBundleIdentifier": "com.example." + strings.ToLower(bundleName),
	}, plist.XMLFormat)
	addZipBytes(t, zw, fmt.Sprintf("Payload/%s.app/Info.plist", bundleName), infoData)
	addZipBytes(t, zw, fmt.Sprintf("Payload/%s.app/%s", bundleName, execName), []byte("macho-binary"))
	if sinfPaths != nil {
		manData, _ := plist.Marshal(map[string]any{"SinfPaths": sinfPaths}, plist.XMLFormat)
		addZipBytes(t, zw, fmt.Sprintf("Payload/%s.app/SC_Info/Manifest.plist", bundleName), manData)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func addZipBytes(t *testing.T, zw *zip.Writer, name string, data []byte) {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
}

func readZipEntryBytes(t *testing.T, zipPath, name string) []byte {
	t.Helper()
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			b, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Fatalf("missing zip entry %s in %s", name, zipPath)
	return nil
}

func assertZipEntryEquals(t *testing.T, zipPath, name string, want []byte) {
	t.Helper()
	got := readZipEntryBytes(t, zipPath, name)
	if !bytes.Equal(got, want) {
		t.Fatalf("zip entry %s mismatch: got %q, want %q", name, got, want)
	}
}

func assertZipEntryExists(t *testing.T, zipPath, name string) {
	t.Helper()
	_ = readZipEntryBytes(t, zipPath, name)
}
