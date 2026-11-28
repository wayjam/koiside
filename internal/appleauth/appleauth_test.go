package appleauth

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/pbkdf2"
	"howett.net/plist"
)

func TestGrandSlamClientInfoOnRequests(t *testing.T) {
	wantDefault := ClientInfo{
		ClientInfo: "<MacBookPro18,3> <Mac OS X;26.6;25F84> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
		UserAgent:  "AuthKit/1 (Macintosh; OS X 26.6) (com.apple.akd/1.0)",
	}
	const customAgent = "akd/1.0 CFNetwork/3896.300.31 Darwin/27.3.0"
	const customMac = "<MacBookAir10,1> <Mac OS X;27.3;26C5035r> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
	highSierra := ClientInfo{
		ClientInfo: "<MacBookPro14,1> <Mac OS X;10.13.6;17G66> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
		UserAgent:  "akd/1.0 CFNetwork/897.15 Darwin/17.7.0",
	}
	windows := ClientInfo{
		ClientInfo: "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>",
		UserAgent:  "akd/1.0 CFNetwork/808.1.4",
	}
	for _, tc := range []struct {
		name   string
		server bool
		input  ClientInfo
		want   ClientInfo
	}{
		{name: "provider default", want: wantDefault},
		{
			name:  "custom macOS label",
			input: ClientInfo{strings.Replace(customMac, "<Mac OS X;", "<macOS;", 1), customAgent},
			want:  ClientInfo{customMac, customAgent},
		},
		{
			name:   "server Sierra metadata",
			server: true,
			input: ClientInfo{
				ClientInfo: "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
				UserAgent:  "akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0",
			},
			want: wantDefault,
		},
		{
			name:  "obsolete Xcode metadata",
			input: ClientInfo{strings.Replace(customMac, "com.apple.akd/1.0", "com.apple.dt.Xcode/26.0", 1), customAgent},
			want:  wantDefault,
		},
		{name: "High Sierra compatibility boundary", input: highSierra, want: highSierra},
		{name: "Windows metadata", input: windows, want: windows},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v3/client_info" {
					_ = json.NewEncoder(w).Encode(tc.input)
					return
				}
				if got := r.Header.Get("X-Mme-Client-Info"); got != tc.want.ClientInfo {
					t.Errorf("%s X-Mme-Client-Info = %q, want %q", r.URL.Path, got, tc.want.ClientInfo)
				}
				if got := r.Header.Get("User-Agent"); got != tc.want.UserAgent {
					t.Errorf("%s User-Agent = %q, want %q", r.URL.Path, got, tc.want.UserAgent)
				}
				var reply map[string]any
				switch r.URL.Path {
				case "/lookup":
					reply = map[string]any{"urls": map[string]any{"gsService": "/gs"}}
				case "/gs":
					reply = map[string]any{"Response": map[string]any{"accepted": true}}
				case "/auth":
					w.WriteHeader(http.StatusNoContent)
					return
				default:
					http.NotFound(w, r)
					return
				}
				raw, _ := plist.Marshal(reply, plist.XMLFormat)
				_, _ = w.Write(raw)
			}))
			defer srv.Close()

			prov := NewRemoteV3AnisetteProvider(srv.URL, nil)
			if tc.server {
				prov.SetClientInfoOverride(nil)
			} else if tc.input != (ClientInfo{}) {
				prov.SetClientInfoOverride(&tc.input)
			}
			info, err := prov.GetClientInfo(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			gs := NewGrandSlamClientWithHTTP(srv.Client(), info, srv.URL+"/lookup")
			if err := gs.EnsureBag(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := gs.PlistRequest(t.Context(), srv.URL+"/gs", map[string]any{}, nil); err != nil {
				t.Fatal(err)
			}
			// Plist callers can also supply a client identity via extra headers.
			extra := http.Header{}
			extra.Set("X-Mme-Client-Info", info.ClientInfo)
			extra.Set("User-Agent", info.UserAgent)
			gsWithOverride := NewGrandSlamClientWithHTTP(srv.Client(), DefaultMacClientInfo, srv.URL+"/lookup")
			if _, err := gsWithOverride.PlistRequest(t.Context(), srv.URL+"/gs", map[string]any{}, extra); err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/auth", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := gs.DoRequest(req, true)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("auth HTTP %d, want %d", resp.StatusCode, http.StatusNoContent)
			}
		})
	}
}

func TestLoginWithAnisetteResync2FAAndAppToken(t *testing.T) {
	const (
		email    = "user@example.com"
		password = "correct-horse-battery-staple"
		pinCode  = "123456"
		dsid     = "000123456"
	)

	var gotContentTypes []string
	var wsUpgraded atomic.Bool

	// Mock Anisette v3 HTTP + WebSocket server.
	var aniSrv *httptest.Server
	aniSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/client_info":
			_ = json.NewEncoder(w).Encode(DefaultMacClientInfo)
		case "/v3/provisioning_session":
			wsUpgraded.Store(true)
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", 500)
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			key := r.Header.Get("Sec-WebSocket-Key")
			sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			accept := base64.StdEncoding.EncodeToString(sum[:])
			_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+accept+"\r\n\r\n")
			sendText := func(v any) {
				b, _ := json.Marshal(v)
				_ = writeServerWSFrame(conn, 0x1, b)
			}
			readText := func() {
				_, _ = readServerWSFrame(rw.Reader)
			}
			sendText(map[string]string{"result": "GiveIdentifier"})
			readText()
			sendText(map[string]string{"result": "GiveStartProvisioningData"})
			readText()
			sendText(map[string]string{"result": "GiveEndProvisioningData", "cpim": "mock-cpim"})
			readText()
			sendText(map[string]string{
				"result": "ProvisioningSuccess",
				"adi_pb": base64.StdEncoding.EncodeToString([]byte("mock-adi-pb")),
			})
			_ = writeServerWSFrame(conn, 0x8, nil)
		case "/v3/get_headers":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"X-Apple-I-MD":       "mock-otp",
				"X-Apple-I-MD-M":     "mock-machine-id",
				"X-Apple-I-MD-RINFO": "17106176",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer aniSrv.Close()

	// Precompute SRP server verifier (v = g^x mod N) using Apple's G2048 + empty-username x.
	srp := newAppleGSASRPClient()
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	const iters = 100
	pwHash := sha256.Sum256([]byte(password))
	derived := pbkdf2.Key(pwHash[:], salt, iters, 32, sha256.New)
	x := srp.computeX([]byte(email), derived, salt)
	v := new(big.Int).Exp(srp.g, x, srp.n)
	bPriv := big.NewInt(123456789)
	k := srp.computeK()
	// B = k*v + g^b mod N
	kv := new(big.Int).Mul(k, v)
	gb := new(big.Int).Exp(srp.g, bPriv, srp.n)
	bPub := new(big.Int).Mod(new(big.Int).Add(kv, gb), srp.n).Bytes()

	sessionKey := make([]byte, 32)
	for i := range sessionKey {
		sessionKey[i] = byte(i + 1)
	}
	var initCount atomic.Int32
	var twoFACompleted atomic.Bool
	var srvURL string

	gsaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/grandslam/GsService2/lookup" {
			raw, _ := plist.Marshal(map[string]any{
				"urls": map[string]any{
					"gsService":                  srvURL + "/gs",
					"midStartProvisioning":       srvURL + "/startProv",
					"midFinishProvisioning":      srvURL + "/endProv",
					"trustedDeviceSecondaryAuth": srvURL + "/2fa/push",
					"validateCode":               srvURL + "/2fa/validate",
				},
			}, plist.XMLFormat)
			_, _ = w.Write(raw)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			gotContentTypes = append(gotContentTypes, ct)
		}
		switch r.URL.Path {
		case "/startProv":
			raw, _ := plist.Marshal(map[string]any{"Response": map[string]any{"spim": "mock-spim"}}, plist.XMLFormat)
			_, _ = w.Write(raw)
		case "/endProv":
			raw, _ := plist.Marshal(map[string]any{"Response": map[string]any{"ptm": "mock-ptm", "tk": "mock-tk"}}, plist.XMLFormat)
			_, _ = w.Write(raw)
		case "/2fa/push":
			w.WriteHeader(http.StatusOK)
		case "/2fa/validate":
			code := r.Header.Get("security-code")
			if code != pinCode {
				raw, _ := plist.Marshal(map[string]any{"Status": map[string]any{"ec": int64(-21669), "em": "wrong code"}}, plist.XMLFormat)
				_, _ = w.Write(raw)
				return
			}
			twoFACompleted.Store(true)
			raw, _ := plist.Marshal(map[string]any{"Status": map[string]any{"ec": int64(0)}}, plist.XMLFormat)
			_, _ = w.Write(raw)
		case "/gs":
			body, _ := io.ReadAll(r.Body)
			var reqDoc map[string]any
			_, _ = plist.Unmarshal(body, &reqDoc)
			req, _ := reqDoc["Request"].(map[string]any)
			op, _ := req["o"].(string)
			switch op {
			case "init":
				if initCount.Add(1) == 1 {
					raw, _ := plist.Marshal(map[string]any{
						"Response": map[string]any{
							"Status": map[string]any{
								"hsc":               int64(434),
								"X-Apple-I-MD-DATA": []byte("sim"),
							},
						},
					}, plist.XMLFormat)
					_, _ = w.Write(raw)
					return
				}
				raw, _ := plist.Marshal(map[string]any{
					"Response": map[string]any{
						"s":  salt,
						"B":  bPub,
						"i":  int64(iters),
						"c":  "mock-c",
						"sp": "s2k",
					},
				}, plist.XMLFormat)
				_, _ = w.Write(raw)
			case "complete":
				aPubBytes, _ := srp.computePublicEphemeral([]byte{}), []byte{}
				_ = aPubBytes
				// Retrieve client A2k from earlier init? Easier: derive from M1 directly or compute server S:
				// For deterministic test, read M1 and compute server S using stored A2k isn't needed if we keep lastA2k!
				m1Client, _ := req["M1"].([]byte)
				u := srp.computeU(lastInitA2k, bPub)
				// Server S = (A * v^u)^b mod N
				vu := new(big.Int).Exp(v, u, srp.n)
				base := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).SetBytes(lastInitA2k), vu), srp.n)
				srvPremaster := new(big.Int).Exp(base, bPriv, srp.n).Bytes()
				srvKey := srp.hashBytes(srvPremaster)
				nHash := srp.hashBytes(padTo(srp.n.Bytes(), srp.nBytes))
				gHash := srp.hashBytes(padTo(srp.g.Bytes(), srp.nBytes))
				xorNG := make([]byte, len(nHash))
				for i := range xorNG {
					xorNG[i] = nHash[i] ^ gHash[i]
				}
				expectedM1 := srp.hashBytes(xorNG, srp.hashBytes([]byte(email)), salt, lastInitA2k, bPub, srvKey)
				if string(m1Client) != string(expectedM1) {
					t.Fatalf("M1 mismatch")
				}
				m2 := srp.hashBytes(lastInitA2k, m1Client, srvKey)

				spdRaw, _ := plist.Marshal(map[string]any{
					"adsid":       dsid,
					"GsIdmsToken": "idms-tok",
					"fn":          "Ada",
					"ln":          "Lovelace",
					"sk":          sessionKey,
					"c":           []byte("spd-c"),
				}, plist.XMLFormat)
				spdEnc := encryptSPDCBC(srvKey, spdRaw)

				status := map[string]any{"ec": int64(0)}
				if !twoFACompleted.Load() {
					status["au"] = "trustedDeviceSecondaryAuth"
				}
				raw, _ := plist.Marshal(map[string]any{
					"Response": map[string]any{
						"M2":     m2,
						"spd":    spdEnc,
						"Status": status,
					},
				}, plist.XMLFormat)
				_, _ = w.Write(raw)
			case "apptokens":
				tokRaw, _ := plist.Marshal(map[string]any{
					"status-code": int64(200),
					"t": map[string]any{
						"com.apple.gs.xcode.auth": map[string]any{
							"token":    "xcode-auth-secret-token",
							"duration": int64(3600),
							"expiry":   int64(9999999),
						},
					},
				}, plist.XMLFormat)
				et := encryptAppTokenGCM(tokRaw, sessionKey)
				raw, _ := plist.Marshal(map[string]any{
					"Response": map[string]any{
						"et":     et,
						"Status": map[string]any{"ec": int64(0)},
					},
				}, plist.XMLFormat)
				_, _ = w.Write(raw)
			}
		}
	}))
	// Capture A2k from init calls via middleware wrapper
	var origHandler = gsaSrv.Config.Handler
	gsaSrv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gs" {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			var reqDoc map[string]any
			if _, err := plist.Unmarshal(body, &reqDoc); err == nil {
				if req, ok := reqDoc["Request"].(map[string]any); ok {
					if a2k, ok := req["A2k"].([]byte); ok && len(a2k) > 0 {
						lastInitA2k = a2k
					}
				}
			}
		}
		origHandler.ServeHTTP(w, r)
	})
	defer gsaSrv.Close()
	srvURL = gsaSrv.URL

	store := NewMemoryStorage()
	prov := NewRemoteV3AnisetteProvider(aniSrv.URL, store)
	gs := NewGrandSlamClientWithHTTP(gsaSrv.Client(), DefaultMacClientInfo, srvURL+"/grandslam/GsService2/lookup")

	var tfaCalls int
	acc, err := Login(context.Background(), email, password, prov, gs, func(_ context.Context, _ TwoFactorPrompt) (TwoFactorResponse, error) {
		tfaCalls++
		if tfaCalls == 1 {
			return TwoFactorResponse{Action: ActionSubmitCode, Code: "000000"}, nil // trigger -21669 retry
		}
		return TwoFactorResponse{Action: ActionSubmitCode, Code: pinCode}, nil
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if !wsUpgraded.Load() {
		t.Fatal("expected WebSocket Anisette provisioning")
	}
	if acc.ADSID() != dsid || acc.FullName() != "Ada Lovelace" {
		t.Fatalf("unexpected account identity: adsid=%q name=%q", acc.ADSID(), acc.FullName())
	}
	if tfaCalls != 2 {
		t.Fatalf("expected 2 2FA prompts (wrong code then right code), got %d", tfaCalls)
	}
	for _, ct := range gotContentTypes {
		if ct != "text/xml" {
			t.Fatalf("expected Content-Type text/xml per 2026-10 edge fix, got %q", ct)
		}
	}

	tok, err := acc.GetAppToken(context.Background(), "xcode.auth")
	if err != nil {
		t.Fatalf("GetAppToken failed: %v", err)
	}
	if tok.Token != "xcode-auth-secret-token" {
		t.Fatalf("unexpected token %q", tok.Token)
	}
}

var lastInitA2k []byte

func encryptSPDCBC(srvKey, plain []byte) []byte {
	h1 := hmac.New(sha256.New, srvKey)
	_, _ = h1.Write([]byte("extra data key:"))
	key := h1.Sum(nil)

	h2 := hmac.New(sha256.New, srvKey)
	_, _ = h2.Write([]byte("extra data iv:"))
	iv := h2.Sum(nil)[:16]

	pad := aes.BlockSize - (len(plain) % aes.BlockSize)
	padded := append([]byte(nil), plain...)
	for i := 0; i < pad; i++ {
		padded = append(padded, byte(pad))
	}
	block, _ := aes.NewCipher(key)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out
}

func encryptAppTokenGCM(plain, sessionKey []byte) []byte {
	hdr := []byte("XYZ")
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	block, _ := aes.NewCipher(sessionKey)
	aead, _ := cipher.NewGCMWithNonceSize(block, 16)
	ct := aead.Seal(nil, iv, plain, hdr)
	out := append([]byte(nil), hdr...)
	out = append(out, iv...)
	return append(out, ct...)
}

func writeServerWSFrame(w io.Writer, opcode byte, payload []byte) error {
	var hdr [4]byte
	hdr[0] = 0x80 | opcode
	n := 2
	if len(payload) < 126 {
		hdr[1] = byte(len(payload))
	} else {
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(payload)))
		n = 4
	}
	if _, err := w.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readServerWSFrame(r *bufio.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	l := int(hdr[1] & 0x7f)
	if l == 126 {
		var ext [2]byte
		_, _ = io.ReadFull(r, ext[:])
		l = int(binary.BigEndian.Uint16(ext[:]))
	}
	var mask [4]byte
	if hdr[1]&0x80 != 0 {
		_, _ = io.ReadFull(r, mask[:])
	}
	p := make([]byte, l)
	_, _ = io.ReadFull(r, p)
	for i := range p {
		p[i] ^= mask[i%4]
	}
	return p, nil
}

func TestGrandSlamPlistRequestSurfacesStructuredErrorOn503(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-xml-plist")
		w.WriteHeader(http.StatusServiceUnavailable)
		doc := map[string]any{
			"Response": map[string]any{
				"Status": map[string]any{
					"ec": int64(-20101),
					"em": "Your Apple ID or password was entered incorrectly.",
				},
			},
		}
		raw, _ := plist.Marshal(doc, plist.XMLFormat)
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	client := NewGrandSlamClientWithHTTP(srv.Client(), DefaultMacClientInfo, srv.URL)
	_, err := client.PlistRequest(context.Background(), srv.URL, map[string]any{"test": true}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Code != -20101 {
		t.Fatalf("expected *AuthError with code -20101, got %v (%T)", err, err)
	}
}

func TestGrandSlamPlistRequestIncludesPreviewOnRawHTMLError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><head><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway</h1></body></html>"))
	}))
	defer srv.Close()

	client := NewGrandSlamClientWithHTTP(srv.Client(), DefaultMacClientInfo, srv.URL)
	_, err := client.PlistRequest(context.Background(), srv.URL, map[string]any{"test": true}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "502") || !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Fatalf("expected error containing 502 and html preview, got %v", err)
	}
}
