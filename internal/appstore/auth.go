package appstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"howett.net/plist"

	"koiside/internal/appstore/sap"
)

const (
	authRequestAttempts   = 4
	authRetryDelay        = 3 * time.Second
	maxAuthRetryDelay     = 30 * time.Second
	sapSetupMaxBytes      = 2 * 1024 * 1024
	sapSetupFieldMaxBytes = 1048576
)

var approvedAuthHostRe = regexp.MustCompile(`^(?:auth|buy|p\d+-buy)\.itunes\.apple\.com$`)

// AuthError represents an App Store authentication failure, optionally indicating 2FA code entry is required.
type AuthError struct {
	Message      string
	CodeRequired bool
}

func (e *AuthError) Error() string { return e.Message }

// AuthRetry describes an impending retry after a transient HTTP response.
type AuthRetry struct {
	Status   int
	Attempt  int
	Attempts int
	Delay    time.Duration
}

type authSession struct {
	signer      sap.Signer
	cookies     []Cookie
	storeFront  string
	requestHost string
	requestPath string
	pod         string
}

// Authenticator manages one App Store login session across initial password submission and 2FA continuation.
type Authenticator struct {
	client          *Client
	deviceID        string
	existingCookies []Cookie

	mu      sync.Mutex
	busy    bool
	session *authSession

	// Optional test hooks; nil uses real endpoints and sap.CreateHandshake/CreateSigner.
	connectSAPFunc func(ctx context.Context) (sap.Signer, error)
}

// NewAuthenticator creates an Authenticator bound to deviceID and optional existing cookies.
func NewAuthenticator(client *Client, deviceID string, existingCookies []Cookie) *Authenticator {
	if client == nil {
		client = NewClient()
	}
	return &Authenticator{
		client:          client,
		deviceID:        deviceID,
		existingCookies: append([]Cookie(nil), existingCookies...),
	}
}

// ConnectSAP performs a fresh SAP certificate fetch and setup exchange with Apple.
func (c *Client) ConnectSAP(ctx context.Context) (sap.Signer, error) {
	certURL := "https://s.mzstatic.com/sap/setupCert.plist"
	if c != nil && c.SAPCertURL != "" {
		certURL = c.SAPCertURL
	}
	setupURL := "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy"
	if c != nil && c.SAPSetupURL != "" {
		setupURL = c.SAPSetupURL
	}

	exchange := func(method, targetURL, key string, payload []byte) ([]byte, error) {
		var body []byte
		if payload != nil {
			var err error
			body, err = plist.Marshal(map[string]any{
				"sign-sap-setup-buffer": payload,
			}, plist.XMLFormat)
			if err != nil {
				return nil, err
			}
		}
		resp, err := c.doAppleRequest(ctx, method, targetURL, map[string]string{
			"Content-Type": "application/x-apple-plist",
		}, body, nil)
		if err != nil {
			return nil, err
		}
		if resp.Status != http.StatusOK || len(resp.Body) > sapSetupMaxBytes {
			return nil, fmt.Errorf("appstore: SAP setup failed (HTTP %d)", resp.Status)
		}
		var dict map[string]any
		if _, err := plist.Unmarshal(resp.Body, &dict); err != nil {
			return nil, fmt.Errorf("appstore: invalid SAP setup plist: %w", err)
		}
		rawVal, ok := dict[key].([]byte)
		if !ok || len(rawVal) == 0 || len(rawVal) > sapSetupFieldMaxBytes {
			return nil, errors.New("appstore: invalid SAP setup service response")
		}
		return rawVal, nil
	}

	cert, err := exchange("GET", certURL, "sign-sap-setup-cert", nil)
	if err != nil {
		return nil, err
	}
	hs, err := sap.CreateHandshake(cert, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	reply, err := exchange("POST", setupURL, "sign-sap-setup-buffer", hs.Request)
	if err != nil {
		return nil, err
	}
	sess, err := hs.Complete(reply)
	if err != nil {
		return nil, err
	}
	return sap.CreateSigner(sess, 1)
}

func approvedAuthEndpoint(raw string, allowTestHosts bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("appstore: authentication requires a valid URL")
	}
	if allowTestHosts && (u.Scheme == "http" || u.Scheme == "https") {
		return u, nil
	}
	if u.Scheme != "https" || u.User != nil || u.Port() != "" || !approvedAuthHostRe.MatchString(u.Hostname()) {
		return nil, errors.New("appstore: authentication requires an approved Apple HTTPS endpoint")
	}
	return u, nil
}

func (a *Authenticator) connect(ctx context.Context) (*authSession, error) {
	bag := a.client.FetchBag(ctx, a.deviceID)
	allowTest := a.client != nil && a.client.BagURL != ""
	endpoint, err := approvedAuthEndpoint(NormalizeAuthURL(bag.AuthURL), allowTest)
	if err != nil {
		return nil, err
	}
	q := endpoint.Query()
	q.Set("guid", a.deviceID)
	endpoint.RawQuery = q.Encode()

	var signer sap.Signer
	if a.connectSAPFunc != nil {
		signer, err = a.connectSAPFunc(ctx)
	} else {
		signer, err = a.client.ConnectSAP(ctx)
	}
	if err != nil {
		return nil, err
	}

	schemeHost := endpoint.Scheme + "://" + endpoint.Host
	return &authSession{
		signer:      signer,
		cookies:     append([]Cookie(nil), a.existingCookies...),
		requestHost: schemeHost,
		requestPath: endpoint.RequestURI(),
	}, nil
}

// Authenticate signs in to the App Store, returning AuthError{CodeRequired: true} when 2FA is needed.
// Retain the same Authenticator instance when retrying with the 2FA verification code.
func (a *Authenticator) Authenticate(ctx context.Context, email, password, code string, onRetry func(AuthRetry)) (Account, error) {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return Account{}, errors.New("appstore: an authentication request is already in progress")
	}
	a.busy = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.busy = false
		a.mu.Unlock()
	}()

	if a.session == nil {
		sess, err := a.connect(ctx)
		if err != nil {
			return Account{}, err
		}
		a.session = sess
	}

	sess := a.session
	cookies := append([]Cookie(nil), sess.cookies...)
	storeFront := sess.storeFront
	requestHost := sess.requestHost
	requestPath := sess.requestPath
	pod := sess.pod

	defer func() {
		sess.cookies = cookies
		sess.storeFront = storeFront
		sess.requestHost = requestHost
		sess.requestPath = requestPath
		sess.pod = pod
	}()

	attemptVal := "4"
	pwVal := password
	if code != "" {
		attemptVal = "2"
		pwVal = password + code
	}

	bodyDict := map[string]any{
		"appleId":  email,
		"attempt":  attemptVal,
		"guid":     a.deviceID,
		"password": pwVal,
		"rmp":      "0",
		"why":      "signIn",
	}
	plistBody, err := plist.Marshal(bodyDict, plist.XMLFormat)
	if err != nil {
		return Account{}, err
	}

	allowTest := a.client != nil && a.client.BagURL != ""
	var lastErr error
	currentAttempt := 0
	redirectAttempt := 0

	for currentAttempt < 2 && redirectAttempt <= 3 {
		currentAttempt++

		resp, err := a.sendWithTransientRetry(ctx, func() (rawResponse, error) {
			sig, err := sess.signer.Sign(plistBody)
			if err != nil {
				return rawResponse{}, err
			}
			r, err := a.client.doAppleRequest(ctx, "POST", requestHost+requestPath, map[string]string{
				"Content-Type":            "application/x-apple-plist",
				"X-Apple-ActionSignature": base64.StdEncoding.EncodeToString(sig),
			}, plistBody, cookies)
			if err != nil {
				return rawResponse{}, err
			}
			cookies = ExtractAndMergeCookies(r.SetCookies, cookies)
			return r, nil
		}, onRetry)
		if err != nil {
			var authErr *AuthError
			if errors.As(err, &authErr) {
				return Account{}, authErr
			}
			if pod != "" && !allowTest && requestHost == "https://buy.itunes.apple.com" {
				requestHost = "https://" + PurchaseAPIHost(pod)
				currentAttempt--
				redirectAttempt++
				lastErr = err
				continue
			}
			lastErr = err
			continue
		}
		if storeHdr := resp.Headers.Get("x-set-apple-store-front"); storeHdr != "" {
			if parts := strings.SplitN(storeHdr, "-", 2); parts[0] != "" {
				storeFront = parts[0]
			}
		}
		if p := resp.Headers.Get("pod"); p != "" {
			pod = p
			if !allowTest && requestHost == "https://buy.itunes.apple.com" {
				requestHost = "https://" + PurchaseAPIHost(pod)
			}
		}

		if isRedirectStatus(resp.Status) {
			loc := resp.Headers.Get("location")
			if loc == "" {
				lastErr = errors.New("appstore: missing authentication redirect location")
				continue
			}
			baseURL, _ := url.Parse(requestHost + requestPath)
			relURL, err := url.Parse(loc)
			if err != nil {
				lastErr = err
				continue
			}
			resolved := baseURL.ResolveReference(relURL)
			approved, err := approvedAuthEndpoint(NormalizeAuthURL(resolved.String()), allowTest)
			if err != nil {
				lastErr = err
				continue
			}
			requestHost = approved.Scheme + "://" + approved.Host
			requestPath = approved.RequestURI()
			currentAttempt--
			redirectAttempt++
			continue
		}

		if resp.Status != http.StatusOK {
			lastErr = fmt.Errorf("appstore: authentication failed (HTTP %d)", resp.Status)
			continue
		}

		if len(strings.TrimSpace(string(resp.Body))) == 0 {
			lastErr = fmt.Errorf("appstore: authentication returned empty response (HTTP %d)", resp.Status)
			continue
		}

		var dict map[string]any
		if _, err := plist.Unmarshal(resp.Body, &dict); err != nil {
			lastErr = fmt.Errorf("appstore: invalid authentication plist: %w", err)
			continue
		}

		failureType := stringify(dict["failureType"])
		customerMsg, _ := dict["customerMessage"].(string)
		if failureType == "" && code == "" && customerMsg == "MZFinance.BadLogin.Configurator_message" {
			return Account{}, &AuthError{
				Message:      "two-factor authentication verification code required",
				CodeRequired: true,
			}
		}

		failureMessage := customerMsg
		if dialog, ok := dict["dialog"].(map[string]any); ok {
			if exp, ok := dialog["explanation"].(string); ok && exp != "" {
				failureMessage = exp
			}
		}

		accountInfo, ok := dict["accountInfo"].(map[string]any)
		if !ok {
			if failureMessage != "" {
				lastErr = errors.New(failureMessage)
			} else {
				lastErr = errors.New("appstore: missing accountInfo in response")
			}
			continue
		}
		address, ok := accountInfo["address"].(map[string]any)
		if !ok {
			if failureMessage != "" {
				lastErr = errors.New(failureMessage)
			} else {
				lastErr = errors.New("appstore: missing address in response")
			}
			continue
		}

		appleID, _ := accountInfo["appleId"].(string)
		firstName, _ := address["firstName"].(string)
		lastName, _ := address["lastName"].(string)
		passwordToken, _ := dict["passwordToken"].(string)
		dsid := stringify(dict["dsPersonId"])

		return Account{
			Email:            email,
			AppleID:          appleID,
			Store:            storeFront,
			FirstName:        firstName,
			LastName:         lastName,
			PasswordToken:    passwordToken,
			DSID:             dsid,
			Cookies:          append([]Cookie(nil), cookies...),
			DeviceIdentifier: a.deviceID,
			Pod:              pod,
		}, nil
	}

	if lastErr != nil {
		return Account{}, lastErr
	}
	return Account{}, errors.New("appstore: authentication failed for unknown reason")
}

func (a *Authenticator) sendWithTransientRetry(ctx context.Context, send func() (rawResponse, error), onRetry func(AuthRetry)) (rawResponse, error) {
	var statuses []string
	for {
		resp, err := send()
		if err != nil {
			return rawResponse{}, err
		}
		if !isTransientAuthResponse(resp) {
			return resp, nil
		}
		statuses = append(statuses, strconv.Itoa(resp.Status))
		if len(statuses) == authRequestAttempts {
			return rawResponse{}, &AuthError{
				Message: fmt.Sprintf("appstore: Apple edge refused authentication after %d attempts (HTTP %s); try again or switch network", authRequestAttempts, strings.Join(statuses, ", ")),
			}
		}

		if a.client != nil && a.client.HTTPClient != nil {
			a.client.HTTPClient.CloseIdleConnections()
		}

		delay := authRetryDelay << (len(statuses) - 1)
		if delay > maxAuthRetryDelay {
			delay = maxAuthRetryDelay
		}
		if reqDelay, ok := parseRetryAfter(resp.Headers.Get("retry-after")); ok {
			if reqDelay > maxAuthRetryDelay {
				return rawResponse{}, &AuthError{
					Message: fmt.Sprintf("appstore: authentication rate limited; retry after %d seconds", int((reqDelay+999*time.Millisecond)/time.Second)),
				}
			}
			if reqDelay < time.Second {
				reqDelay = time.Second
			}
			delay = reqDelay
		}

		if onRetry != nil {
			onRetry(AuthRetry{
				Status:   resp.Status,
				Attempt:  len(statuses) + 1,
				Attempts: authRequestAttempts,
				Delay:    delay,
			})
		}
		if err := a.client.sleep(ctx, delay); err != nil {
			return rawResponse{}, err
		}
	}
}

func isTransientAuthResponse(resp rawResponse) bool {
	if resp.Status == 204 || resp.Status == 404 || resp.Status == 429 || resp.Status/100 == 5 {
		return true
	}
	// Apple's edge proxy intermittently returns 301/302 HTML without Location or 403 HTML/empty body before MZFinance.
	if isRedirectStatus(resp.Status) && strings.TrimSpace(resp.Headers.Get("location")) == "" {
		return true
	}
	if resp.Status == http.StatusForbidden && !bytes.Contains(resp.Body, []byte("<plist")) {
		return true
	}
	return false
}

func isRedirectStatus(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	default:
		return false
	}
}

func parseRetryAfter(val string) (time.Duration, bool) {
	val = strings.TrimSpace(val)
	if val == "" {
		return 0, false
	}
	if sec, err := strconv.Atoi(val); err == nil && sec >= 0 {
		return time.Duration(sec) * time.Second, true
	}
	if t, err := http.ParseTime(val); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

func stringify(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	default:
		return ""
	}
}
