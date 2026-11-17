package appleauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"howett.net/plist"
)

// TwoFactorAction indicates how the caller responds to an Apple 2FA prompt.
type TwoFactorAction int

const (
	ActionSubmitCode TwoFactorAction = iota
	ActionSendSMS
	ActionSendToDevices
	ActionResendCode
	ActionAbort
)

// TrustedNumber is an Apple-registered SMS/voice phone number for 2FA.
type TrustedNumber struct {
	NumberWithDialCode string `json:"numberWithDialCode"`
	LastTwoDigits      string `json:"lastTwoDigits"`
	PushMode           string `json:"pushMode"`
	ID                 uint32 `json:"id"`
}

// TwoFactorPrompt describes what 2FA method Apple requested.
type TwoFactorPrompt struct {
	LastError        string
	UnknownMethod    bool
	SMS              bool
	Numbers          []TrustedNumber
	SelectedNumberID *uint32
}

// TwoFactorResponse is supplied by the UI/CLI callback for 2FA.
type TwoFactorResponse struct {
	Action   TwoFactorAction
	Code     string
	NumberID uint32
}

// TwoFactorFunc blocks until the user provides a 2FA code or picks a delivery method.
type TwoFactorFunc func(ctx context.Context, prompt TwoFactorPrompt) (TwoFactorResponse, error)

// AppToken is an Apple GrandSlam application token (e.g. com.apple.gs.xcode.auth).
type AppToken struct {
	Token    string
	Duration uint64
	Expiry   uint64
}

// AppleAccount holds an authenticated GrandSlam SRP session.
type AppleAccount struct {
	Email      string
	Anisette   AnisetteProvider
	GrandSlam  *GrandSlamClient
	SPD        map[string]any
	TrustedNum []TrustedNumber
	LastError  string
}

type loginState int

const (
	stateLoggedIn loginState = iota
	stateNeedsDevice2FA
	stateNeedsDevice2FAVerify
	stateNeedsSMS2FA
	stateNeedsSMS2FAVerify
	stateNeedsUnknown2FA
	stateNeedsExtraStep
	stateNeedsLogin
)

// Login authenticates email+password against Apple GrandSlam, handling Anisette resync and 2FA.
func Login(ctx context.Context, email, password string, anisette AnisetteProvider, gs *GrandSlamClient, on2FA TwoFactorFunc) (*AppleAccount, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return nil, errors.New("appleauth: Apple ID email and password are required")
	}
	if anisette == nil {
		return nil, errors.New("appleauth: anisette provider is required")
	}
	if gs == nil {
		info, err := anisette.GetClientInfo(ctx)
		if err != nil {
			return nil, err
		}
		gs, err = NewGrandSlamClient(info, nil)
		if err != nil {
			return nil, err
		}
	}
	if err := gs.EnsureBag(ctx); err != nil {
		return nil, err
	}

	acc := &AppleAccount{
		Email:     email,
		Anisette:  anisette,
		GrandSlam: gs,
	}

	st, selectedSMSID, extraStep, err := acc.loginInner(ctx, password)
	if err != nil {
		return nil, err
	}

	for attempts := 0; attempts < 15; attempts++ {
		switch st {
		case stateLoggedIn:
			return acc, nil
		case stateNeedsDevice2FA:
			acc.refreshTrustedNumbers(ctx)
			if err := acc.sendTrustedDevice2FA(ctx); err != nil {
				// Apple sometimes auto-pushes without trustedDeviceSecondaryAuth (returning HTTP 403/412).
				// Fall through to verification if a trusted-device code was already pushed.
				acc.LastError = err.Error()
			}
			st = stateNeedsDevice2FAVerify
		case stateNeedsDevice2FAVerify:
			if on2FA == nil {
				return nil, errors.New("appleauth: 2FA required but no callback provided")
			}
			resp, err := on2FA(ctx, TwoFactorPrompt{
				LastError: acc.LastError,
				Numbers:   acc.TrustedNum,
			})
			if err != nil {
				return nil, err
			}
			acc.LastError = ""
			switch resp.Action {
			case ActionSubmitCode:
				st, err = acc.verifyTrustedDevice2FA(ctx, strings.TrimSpace(resp.Code))
				if err != nil {
					return nil, err
				}
			case ActionSendSMS:
				selectedSMSID = resp.NumberID
				st = stateNeedsSMS2FA
			case ActionSendToDevices, ActionResendCode:
				st = stateNeedsDevice2FA
			default:
				return nil, errors.New("appleauth: 2FA canceled")
			}
		case stateNeedsSMS2FA:
			acc.refreshTrustedNumbers(ctx)
			nextSt, err := acc.sendSMS2FA(ctx, selectedSMSID)
			if err != nil {
				return nil, err
			}
			st = nextSt
		case stateNeedsSMS2FAVerify:
			if on2FA == nil {
				return nil, errors.New("appleauth: SMS 2FA required but no callback provided")
			}
			idCopy := selectedSMSID
			resp, err := on2FA(ctx, TwoFactorPrompt{
				LastError:        acc.LastError,
				SMS:              true,
				Numbers:          acc.TrustedNum,
				SelectedNumberID: &idCopy,
			})
			if err != nil {
				return nil, err
			}
			acc.LastError = ""
			switch resp.Action {
			case ActionSubmitCode:
				st, err = acc.verifySMS2FA(ctx, strings.TrimSpace(resp.Code), selectedSMSID)
				if err != nil {
					return nil, err
				}
			case ActionSendSMS:
				selectedSMSID = resp.NumberID
				st = stateNeedsSMS2FA
			case ActionResendCode:
				st = stateNeedsSMS2FA
			case ActionSendToDevices:
				st = stateNeedsDevice2FA
			default:
				return nil, errors.New("appleauth: 2FA canceled")
			}
		case stateNeedsUnknown2FA:
			if on2FA == nil {
				return nil, errors.New("appleauth: 2FA required")
			}
			resp, err := on2FA(ctx, TwoFactorPrompt{
				LastError:     acc.LastError,
				UnknownMethod: true,
				Numbers:       acc.TrustedNum,
			})
			if err != nil {
				return nil, err
			}
			acc.LastError = ""
			switch resp.Action {
			case ActionSendSMS:
				selectedSMSID = resp.NumberID
				st = stateNeedsSMS2FA
			case ActionSendToDevices:
				st = stateNeedsDevice2FA
			default:
				return nil, errors.New("appleauth: 2FA canceled")
			}
		case stateNeedsExtraStep:
			if _, ok := acc.petToken(); !ok {
				return nil, fmt.Errorf("appleauth: additional authentication required (%s)", extraStep)
			}
			st = stateLoggedIn
		case stateNeedsLogin:
			st, selectedSMSID, extraStep, err = acc.loginInner(ctx, password)
			if err != nil {
				return nil, err
			}
		}
	}
	return nil, errors.New("appleauth: exceeded 2FA attempts")
}

// ADSID returns the Apple Directory Services ID from SPD.
func (a *AppleAccount) ADSID() string {
	s, _ := a.SPD["adsid"].(string)
	return s
}

// FullName returns the account's first and last name from SPD if present.
func (a *AppleAccount) FullName() string {
	fn, _ := a.SPD["fn"].(string)
	ln, _ := a.SPD["ln"].(string)
	return strings.TrimSpace(fn + " " + ln)
}

func (a *AppleAccount) petToken() (string, bool) {
	tMap, _ := a.SPD["t"].(map[string]any)
	petMap, _ := tMap["com.apple.gs.idms.pet"].(map[string]any)
	tok, _ := petMap["token"].(string)
	return tok, tok != ""
}

// GetAppToken requests and decrypts an application token (e.g. "xcode.auth").
func (a *AppleAccount) GetAppToken(ctx context.Context, app string) (AppToken, error) {
	if !strings.Contains(app, "com.apple.gs.") {
		app = "com.apple.gs." + app
	}
	if a.SPD == nil {
		return AppToken{}, errors.New("appleauth: SPD not available")
	}
	dsid, _ := a.SPD["adsid"].(string)
	authToken, _ := a.SPD["GsIdmsToken"].(string)
	sessionKey, _ := a.SPD["sk"].([]byte)
	c, _ := a.SPD["c"].([]byte)
	if dsid == "" || authToken == "" || len(sessionKey) != 32 || len(c) == 0 {
		return AppToken{}, errors.New("appleauth: incomplete SPD session material")
	}

	anisetteData, err := a.Anisette.GetAnisetteData(ctx, a.GrandSlam)
	if err != nil {
		return AppToken{}, err
	}

	mac := hmac.New(sha256.New, sessionKey)
	_, _ = mac.Write([]byte("apptokens"))
	_, _ = mac.Write([]byte(dsid))
	_, _ = mac.Write([]byte(app))
	checksum := mac.Sum(nil)

	gsURL, err := a.GrandSlam.URL("gsService")
	if err != nil {
		return AppToken{}, err
	}

	req := map[string]any{
		"Header": map[string]any{"Version": "1.0.1"},
		"Request": map[string]any{
			"app":      []string{app},
			"c":        c,
			"checksum": checksum,
			"cpd":      anisetteData.ClientProvidedData(),
			"o":        "apptokens",
			"u":        dsid,
			"t":        authToken,
		},
	}

	resp, err := a.GrandSlam.PlistRequest(ctx, gsURL, req, nil)
	if err != nil {
		return AppToken{}, err
	}
	if err := checkGrandSlamStatus(resp); err != nil {
		return AppToken{}, err
	}
	et, _ := resp["et"].([]byte)
	if len(et) == 0 {
		return AppToken{}, errors.New("appleauth: apptokens response missing et")
	}
	decrypted, err := decryptAppTokenGCM(et, sessionKey)
	if err != nil {
		return AppToken{}, err
	}
	var tokenPlist map[string]any
	if _, err := plist.Unmarshal(decrypted, &tokenPlist); err != nil {
		return AppToken{}, fmt.Errorf("appleauth: parse decrypted app token: %w", err)
	}
	if sc, ok := int64Value(tokenPlist["status-code"]); ok && sc != 200 {
		return AppToken{}, fmt.Errorf("appleauth: app token status-code %d", sc)
	}
	tMap, _ := tokenPlist["t"].(map[string]any)
	appMap, _ := tMap[app].(map[string]any)
	tok, _ := appMap["token"].(string)
	if tok == "" {
		return AppToken{}, fmt.Errorf("appleauth: missing token for %s", app)
	}
	dur, _ := int64Value(appMap["duration"])
	exp, _ := int64Value(appMap["expiry"])
	return AppToken{
		Token:    tok,
		Duration: uint64(dur),
		Expiry:   uint64(exp),
	}, nil
}

func (a *AppleAccount) loginInner(ctx context.Context, password string) (loginState, uint32, string, error) {
	anisetteData, err := a.Anisette.GetAnisetteData(ctx, a.GrandSlam)
	if err != nil {
		return 0, 0, "", err
	}
	gsURL, err := a.GrandSlam.URL("gsService")
	if err != nil {
		return 0, 0, "", err
	}

	srpClient := newAppleGSASRPClient()
	privA, err := srpClient.randomSecret(32)
	if err != nil {
		return 0, 0, "", err
	}
	pubA := srpClient.computePublicEphemeral(privA)
	cpd := anisetteData.ClientProvidedData()

	rawResp, err := a.sendInit(ctx, gsURL, cpd, pubA)
	if err != nil {
		return 0, 0, "", err
	}
	if sim := extractResyncSIM(rawResp); sim != "" {
		fresh, resyncErr := a.Anisette.Resync(ctx, a.GrandSlam, sim)
		if resyncErr != nil {
			return 0, 0, "", fmt.Errorf("appleauth: anisette resync failed: %w", resyncErr)
		}
		cpd = fresh.ClientProvidedData()
		rawResp, err = a.sendInit(ctx, gsURL, cpd, pubA)
		if err != nil {
			return 0, 0, "", err
		}
	}
	if err := checkGrandSlamStatus(rawResp); err != nil {
		return 0, 0, "", err
	}

	salt, _ := rawResp["s"].([]byte)
	bPub, _ := rawResp["B"].([]byte)
	iters, _ := int64Value(rawResp["i"])
	cVal, _ := rawResp["c"].(string)
	proto, _ := rawResp["sp"].(string)
	if len(salt) == 0 || len(bPub) == 0 || iters <= 0 || cVal == "" {
		return 0, 0, "", errors.New("appleauth: incomplete GrandSlam init response")
	}
	if proto != "s2k" && proto != "s2k_fo" {
		return 0, 0, "", fmt.Errorf("appleauth: unsupported SRP protocol %q", proto)
	}

	hashedPw := sha256.Sum256([]byte(password))
	pwInput := hashedPw[:]
	if proto == "s2k_fo" {
		pwInput = []byte(hex.EncodeToString(hashedPw[:]))
	}
	derivedPw := pbkdf2.Key(pwInput, salt, int(iters), 32, sha256.New)

	verifier, err := srpClient.processReply(privA, []byte(a.Email), derivedPw, salt, bPub)
	if err != nil {
		return 0, 0, "", err
	}

	req2 := map[string]any{
		"Header": map[string]any{"Version": "1.0.1"},
		"Request": map[string]any{
			"M1":  verifier.m1,
			"c":   cVal,
			"cpd": cpd,
			"o":   "complete",
			"u":   a.Email,
		},
	}
	resp2, err := a.GrandSlam.PlistRequest(ctx, gsURL, req2, nil)
	if err != nil {
		return 0, 0, "", err
	}
	if err := checkGrandSlamStatus(resp2); err != nil {
		return 0, 0, "", err
	}

	m2, _ := resp2["M2"].([]byte)
	if err := verifier.verifyServer(m2); err != nil {
		return 0, 0, "", err
	}

	spdEnc, _ := resp2["spd"].([]byte)
	if len(spdEnc) == 0 {
		return 0, 0, "", errors.New("appleauth: login response missing spd")
	}
	spdRaw, err := decryptSPDCBC(verifier, spdEnc)
	if err != nil {
		return 0, 0, "", err
	}
	var spd map[string]any
	if _, err := plist.Unmarshal(spdRaw, &spd); err != nil {
		return 0, 0, "", fmt.Errorf("appleauth: parse decrypted spd: %w", err)
	}
	a.SPD = spd

	status, _ := resp2["Status"].(map[string]any)
	if au, _ := status["au"].(string); au != "" {
		switch au {
		case "trustedDeviceSecondaryAuth":
			return stateNeedsDevice2FA, 0, "", nil
		case "secondaryAuth":
			return stateNeedsSMS2FA, 1, "", nil
		case "repair":
			return stateLoggedIn, 0, "", nil
		default:
			return stateNeedsExtraStep, 0, au, nil
		}
	}
	if hsc, ok := int64Value(status["hsc"]); ok && hsc == 409 {
		a.refreshTrustedNumbers(ctx)
		return stateNeedsDevice2FAVerify, 0, "", nil
	}
	return stateLoggedIn, 0, "", nil
}

func (a *AppleAccount) sendInit(ctx context.Context, gsURL string, cpd map[string]any, pubA []byte) (map[string]any, error) {
	req := map[string]any{
		"Header": map[string]any{"Version": "1.0.1"},
		"Request": map[string]any{
			"A2k": pubA,
			"cpd": cpd,
			"o":   "init",
			"ps":  []string{"s2k", "s2k_fo"},
			"u":   a.Email,
		},
	}
	return a.GrandSlam.PlistRequest(ctx, gsURL, req, nil)
}

func (a *AppleAccount) build2FAHeaders(d AnisetteData) (http.Header, error) {
	h := http.Header{}
	d.ApplyHeaders(h)
	adsid, _ := a.SPD["adsid"].(string)
	tok, _ := a.SPD["GsIdmsToken"].(string)
	if adsid == "" || tok == "" {
		return nil, errors.New("appleauth: missing adsid/GsIdmsToken for 2FA")
	}
	identity := base64.StdEncoding.EncodeToString([]byte(adsid + ":" + tok))
	h.Set("X-Apple-Identity-Token", identity)
	return h, nil
}

func (a *AppleAccount) sendTrustedDevice2FA(ctx context.Context) error {
	d, err := a.Anisette.GetAnisetteData(ctx, a.GrandSlam)
	if err != nil {
		return err
	}
	h, err := a.build2FAHeaders(d)
	if err != nil {
		return err
	}
	target, err := a.GrandSlam.URL("trustedDeviceSecondaryAuth")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header = h
	resp, err := a.GrandSlam.DoRequest(req, false)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("appleauth: trusted device 2FA HTTP %d", resp.StatusCode)
	}
	return nil
}

func (a *AppleAccount) verifyTrustedDevice2FA(ctx context.Context, code string) (loginState, error) {
	d, err := a.Anisette.GetAnisetteData(ctx, a.GrandSlam)
	if err != nil {
		return 0, err
	}
	h, err := a.build2FAHeaders(d)
	if err != nil {
		return 0, err
	}
	h.Set("security-code", code)
	target, err := a.GrandSlam.URL("validateCode")
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header = h
	resp, err := a.GrandSlam.DoRequest(req, false)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("appleauth: validateCode HTTP %d", resp.StatusCode)
	}
	var root map[string]any
	if _, err := plist.Unmarshal(body, &root); err != nil {
		return 0, fmt.Errorf("appleauth: invalid validateCode plist: %w", err)
	}
	if err := checkGrandSlamStatus(root); err != nil {
		var authErr *AuthError
		if errors.As(err, &authErr) && authErr.Code == -21669 {
			a.LastError = authErr.Error()
			return stateNeedsDevice2FAVerify, nil
		}
		return 0, err
	}
	return stateNeedsLogin, nil
}

func (a *AppleAccount) refreshTrustedNumbers(ctx context.Context) {
	if len(a.TrustedNum) > 0 {
		return
	}
	d, err := a.Anisette.GetAnisetteData(ctx, a.GrandSlam)
	if err != nil {
		return
	}
	h, err := a.build2FAHeaders(d)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://gsa.apple.com/auth", nil)
	if err != nil {
		return
	}
	req.Header = h
	resp, err := a.GrandSlam.DoRequest(req, true)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var parsed struct {
		TrustedPhoneNumbers []TrustedNumber `json:"trustedPhoneNumbers"`
	}
	if json.NewDecoder(resp.Body).Decode(&parsed) == nil && len(parsed.TrustedPhoneNumbers) > 0 {
		a.TrustedNum = parsed.TrustedPhoneNumbers
	}
}

func (a *AppleAccount) sendSMS2FA(ctx context.Context, id uint32) (loginState, error) {
	d, err := a.Anisette.GetAnisetteData(ctx, a.GrandSlam)
	if err != nil {
		return 0, err
	}
	h, err := a.build2FAHeaders(d)
	if err != nil {
		return 0, err
	}
	bodyBytes, _ := json.Marshal(map[string]any{
		"phoneNumber": map[string]any{"id": id},
		"mode":        "sms",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://gsa.apple.com/auth/verify/phone", bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, err
	}
	req.Header = h
	resp, err := a.GrandSlam.DoRequest(req, true)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return stateNeedsSMS2FAVerify, nil
	}
	if code, msg := parseSMSServiceError(raw); code != "" {
		switch code {
		case "-28248":
			a.LastError = msg
			return stateNeedsUnknown2FA, nil
		case "-22979", "-22981":
			a.LastError = msg
			return stateNeedsSMS2FAVerify, nil
		default:
			return 0, fmt.Errorf("appleauth: SMS 2FA error %s: %s", code, msg)
		}
	}
	if resp.StatusCode == http.StatusPreconditionFailed {
		return stateNeedsSMS2FAVerify, nil
	}
	return 0, fmt.Errorf("appleauth: SMS 2FA HTTP %d", resp.StatusCode)
}

func (a *AppleAccount) verifySMS2FA(ctx context.Context, code string, id uint32) (loginState, error) {
	d, err := a.Anisette.GetAnisetteData(ctx, a.GrandSlam)
	if err != nil {
		return 0, err
	}
	h, err := a.build2FAHeaders(d)
	if err != nil {
		return 0, err
	}
	bodyBytes, _ := json.Marshal(map[string]any{
		"securityCode": map[string]any{"code": code},
		"phoneNumber":  map[string]any{"id": id},
		"mode":         "sms",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://gsa.apple.com/auth/verify/phone/securitycode", bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, err
	}
	req.Header = h
	resp, err := a.GrandSlam.DoRequest(req, true)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return stateNeedsLogin, nil
	}
	if errCode, msg := parseSMSServiceError(raw); errCode != "" {
		if errCode == "-21669" {
			a.LastError = msg
			return stateNeedsSMS2FAVerify, nil
		}
		return 0, fmt.Errorf("appleauth: SMS verify error %s: %s", errCode, msg)
	}
	return 0, fmt.Errorf("appleauth: SMS verify HTTP %d", resp.StatusCode)
}

func parseSMSServiceError(raw []byte) (string, string) {
	var body struct {
		ServiceErrors []struct {
			Code    string `json:"code"`
			Title   string `json:"title"`
			Message string `json:"message"`
		} `json:"serviceErrors"`
	}
	if json.Unmarshal(raw, &body) == nil && len(body.ServiceErrors) > 0 {
		se := body.ServiceErrors[0]
		return se.Code, strings.TrimSpace(se.Title + " " + se.Message)
	}
	return "", ""
}

func extractResyncSIM(resp map[string]any) string {
	status, _ := resp["Status"].(map[string]any)
	if status == nil {
		return ""
	}
	hsc, ok := int64Value(status["hsc"])
	if !ok || hsc != 434 {
		return ""
	}
	switch v := status["X-Apple-I-MD-DATA"].(type) {
	case []byte:
		return base64.StdEncoding.EncodeToString(v)
	case string:
		return v
	default:
		return ""
	}
}

func decryptSPDCBC(v *srpVerifier, ciphertext []byte) ([]byte, error) {
	key := v.hmacSessionKey("extra data key:")
	iv := v.hmacSessionKey("extra data iv:")[:16]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("appleauth: invalid encrypted SPD length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	pad := int(plain[len(plain)-1])
	if pad <= 0 || pad > aes.BlockSize || pad > len(plain) {
		return nil, errors.New("appleauth: invalid PKCS7 padding on SPD")
	}
	for i := len(plain) - pad; i < len(plain); i++ {
		if int(plain[i]) != pad {
			return nil, errors.New("appleauth: corrupt PKCS7 padding on SPD")
		}
	}
	return plain[:len(plain)-pad], nil
}

func decryptAppTokenGCM(data, sessionKey []byte) ([]byte, error) {
	if len(data) < 3+16+16 {
		return nil, fmt.Errorf("appleauth: encrypted app token too short (%d)", len(data))
	}
	hdr := data[:3]
	if string(hdr) != "XYZ" {
		return nil, fmt.Errorf("appleauth: unknown app token envelope %q", string(hdr))
	}
	iv := data[3:19]
	ct := data[19:]
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, iv, ct, hdr)
}
