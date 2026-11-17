// Package devportal implements Apple Developer Services endpoints used for
// free Personal Team and paid developer sideloading (teams, certificates,
// devices, app IDs, app groups, and provisioning profiles).
package devportal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"howett.net/plist"
	"software.sslmate.com/src/go-pkcs12"

	"koiside/internal/appleauth"
)

const (
	devBaseURL = "https://developerservices2.apple.com/services/QH65B2/"
	clientID   = "XABBG36SBA"
	protoVer   = "QH65B2"
)

// PortalError represents an Apple Developer portal resultCode != 0 failure.
type PortalError struct {
	Code    int64
	Message string
}

func (e *PortalError) Error() string {
	return fmt.Sprintf("Apple Developer Portal error %d: %s", e.Code, e.Message)
}

// TeamMembership describes one Apple Developer program membership entry on a team.
type TeamMembership struct {
	Name         string `plist:"name"`
	Status       string `plist:"status"`
	MembershipID string `plist:"membershipId"`
}

// Team represents one Apple Developer team.
type Team struct {
	TeamID      string           `plist:"teamId"`
	Name        string           `plist:"name"`
	Type        string           `plist:"type"`
	Status      string           `plist:"status"`
	Memberships []TeamMembership `plist:"memberships"`
}

// IsFreePersonal distinguishes Free Personal Teams from paid Individual/Organization memberships.
// Apple returns Type="Individual" for both free and $99/yr personal accounts; paid accounts
// carry a non-"Free" membership entry (e.g. "Apple Developer Program").
func (t Team) IsFreePersonal() bool {
	if strings.EqualFold(t.Type, "Company/Organization") || strings.Contains(strings.ToLower(t.Type), "enterprise") {
		return false
	}
	if len(t.Memberships) > 0 {
		for _, m := range t.Memberships {
			low := strings.ToLower(strings.TrimSpace(m.Name))
			if low != "" && !strings.Contains(low, "free") {
				return false
			}
		}
		return true
	}
	return true
}

// DevelopmentCertificate represents one certificate record from Apple Developer Portal.
type DevelopmentCertificate struct {
	Name          string    `plist:"name"`
	CertificateID string    `plist:"certificateId"`
	SerialNumber  string    `plist:"serialNumber"`
	MachineID     string    `plist:"machineId"`
	MachineName   string    `plist:"machineName"`
	CertContent   []byte    `plist:"certContent"`
	Platform      string    `plist:"certificatePlatform"`
	Status        string    `plist:"status"`
	StatusCode    int64     `plist:"statusCode"`
	Expiration    time.Time `plist:"expirationDate"`
}

// Device represents one registered iOS development device.
type Device struct {
	DeviceID     string `plist:"deviceId"`
	Name         string `plist:"name"`
	DeviceNumber string `plist:"deviceNumber"`
	Status       string `plist:"status"`
}

// AppID represents one registered bundle identifier in the developer portal.
type AppID struct {
	AppIDID        string         `plist:"appIdId"`
	Identifier     string         `plist:"identifier"`
	Name           string         `plist:"name"`
	Features       map[string]any `plist:"features"`
	ExpirationDate time.Time      `plist:"expirationDate"`
}

// ListAppIDsResult includes available free-account App ID quota.
type ListAppIDsResult struct {
	AppIDs            []AppID `plist:"appIds"`
	MaxQuantity       int64   `plist:"maxQuantity"`
	AvailableQuantity int64   `plist:"availableQuantity"`
	HasAvailable      bool
}

// AppGroup represents one Apple application group.
type AppGroup struct {
	Name             string `plist:"name"`
	Identifier       string `plist:"identifier"`
	ApplicationGroup string `plist:"applicationGroup"`
}

// Profile represents a downloaded provisioning profile.
type Profile struct {
	EncodedProfile []byte    `plist:"encodedProfile"`
	Filename       string    `plist:"filename"`
	ProfileID      string    `plist:"provisioningProfileId"`
	Name           string    `plist:"name"`
	Status         string    `plist:"status"`
	UUID           string    `plist:"UUID"`
	DateExpire     time.Time `plist:"dateExpire"`
	AppIDID        string    `plist:"appIdId"`
}

// Session authenticates against developerservices2.apple.com using an xcode.auth token.
type Session struct {
	Token    appleauth.AppToken
	ADSID    string
	Client   *appleauth.GrandSlamClient
	Anisette appleauth.AnisetteProvider
	BaseURL  string // optional override for tests
}

// NewSession exchanges the AppleAccount session for an Xcode DeveloperSession.
func NewSession(ctx context.Context, acc *appleauth.AppleAccount) (*Session, error) {
	if acc == nil {
		return nil, errors.New("devportal: nil Apple account")
	}
	tok, err := acc.GetAppToken(ctx, "xcode.auth")
	if err != nil {
		return nil, fmt.Errorf("devportal: get xcode.auth token: %w", err)
	}
	adsid := acc.ADSID()
	if adsid == "" {
		return nil, errors.New("devportal: missing account ADSID")
	}
	return &Session{
		Token:    tok,
		ADSID:    adsid,
		Client:   acc.GrandSlam,
		Anisette: acc.Anisette,
		BaseURL:  devBaseURL,
	}, nil
}

func (s *Session) endpoint(action string, ios bool) string {
	base := s.BaseURL
	if base == "" {
		base = devBaseURL
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	if ios {
		return base + "ios/" + action + ".action"
	}
	return base + action + ".action"
}

func (s *Session) headers(ctx context.Context) (http.Header, error) {
	d, err := s.Anisette.GetAnisetteData(ctx, s.Client)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	d.ApplyHeaders(h)
	h.Set("X-Apple-GS-Token", s.Token.Token)
	h.Set("X-Apple-I-Identity-Id", s.ADSID)
	return h, nil
}

func (s *Session) doPlist(ctx context.Context, action string, ios bool, params map[string]any) (map[string]any, []byte, error) {
	body := map[string]any{
		"clientId":        clientID,
		"protocolVersion": protoVer,
		"requestId":       strings.ToUpper(newUUID()),
		"userLocale":      []string{"en_US"},
	}
	for k, v := range params {
		body[k] = v
	}
	rawReq, err := plist.Marshal(body, plist.XMLFormat)
	if err != nil {
		return nil, nil, err
	}
	hdrs, err := s.headers(ctx)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint(action, ios), bytes.NewReader(rawReq))
	if err != nil {
		return nil, nil, err
	}
	req.Header = hdrs
	req.Header.Set("Content-Type", "text/x-xml-plist")
	resp, err := s.Client.DoRequest(req, false)
	if err != nil {
		return nil, nil, fmt.Errorf("devportal: %s failed: %w", action, err)
	}
	defer resp.Body.Close()
	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("devportal: %s HTTP %d: %s", action, resp.StatusCode, strings.TrimSpace(string(rawResp)))
	}
	var dict map[string]any
	if _, err := plist.Unmarshal(rawResp, &dict); err != nil {
		return nil, nil, fmt.Errorf("devportal: parse %s plist: %w", action, err)
	}
	var portalErr error
	if code, ok := int64Value(dict["resultCode"]); ok && code != 0 {
		msg, _ := dict["userString"].(string)
		if msg == "" {
			msg, _ = dict["resultString"].(string)
		}
		if msg == "" {
			msg = "Developer portal request rejected"
		}
		portalErr = &PortalError{Code: code, Message: msg}
	}
	return dict, rawResp, portalErr
}

func (s *Session) ListTeams(ctx context.Context) ([]Team, error) {
	_, raw, portalErr := s.doPlist(ctx, "listTeams", false, nil)
	var envelope struct {
		Teams []Team `plist:"teams"`
	}
	if _, err := plist.Unmarshal(raw, &envelope); err == nil && len(envelope.Teams) > 0 {
		return envelope.Teams, nil
	}
	if portalErr != nil {
		return nil, portalErr
	}
	return envelope.Teams, nil
}

func (s *Session) ListAllDevelopmentCerts(ctx context.Context, teamID string, iosOnly bool) ([]DevelopmentCertificate, error) {
	_, raw, portalErr := s.doPlist(ctx, "listAllDevelopmentCerts", iosOnly, map[string]any{"teamId": teamID})
	var envelope struct {
		Certificates []DevelopmentCertificate `plist:"certificates"`
	}
	if _, err := plist.Unmarshal(raw, &envelope); err == nil && envelope.Certificates != nil {
		if !iosOnly {
			return envelope.Certificates, nil
		}
		var out []DevelopmentCertificate
		for _, c := range envelope.Certificates {
			if c.Platform == "" || strings.EqualFold(c.Platform, "ios") {
				out = append(out, c)
			}
		}
		return out, nil
	}
	if portalErr != nil {
		return nil, portalErr
	}
	return nil, nil
}

func (s *Session) RevokeDevelopmentCert(ctx context.Context, teamID, serialNumber string) error {
	_, _, err := s.doPlist(ctx, "revokeDevelopmentCert", true, map[string]any{
		"teamId":       teamID,
		"serialNumber": serialNumber,
	})
	return err
}

func (s *Session) SubmitDevelopmentCSR(ctx context.Context, teamID, csrPEM, machineName string) (string, error) {
	dict, _, portalErr := s.doPlist(ctx, "submitDevelopmentCSR", true, map[string]any{
		"teamId":      teamID,
		"csrContent":  csrPEM,
		"machineName": machineName,
		"machineId":   strings.ToUpper(newUUID()),
	})
	if cr, _ := dict["certRequest"].(map[string]any); cr != nil {
		if id, _ := cr["certRequestId"].(string); id != "" {
			return id, nil
		}
	}
	if portalErr != nil {
		return "", portalErr
	}
	return "", errors.New("devportal: submitDevelopmentCSR missing certRequestId")
}

func (s *Session) ListDevices(ctx context.Context, teamID string) ([]Device, error) {
	_, raw, portalErr := s.doPlist(ctx, "listDevices", true, map[string]any{"teamId": teamID})
	var envelope struct {
		Devices []Device `plist:"devices"`
	}
	if _, err := plist.Unmarshal(raw, &envelope); err == nil && envelope.Devices != nil {
		return envelope.Devices, nil
	}
	if portalErr != nil {
		return nil, portalErr
	}
	return nil, nil
}

func (s *Session) AddDevice(ctx context.Context, teamID, name, udid string) (Device, error) {
	_, raw, portalErr := s.doPlist(ctx, "addDevice", true, map[string]any{
		"teamId":       teamID,
		"name":         name,
		"deviceNumber": udid,
	})
	var envelope struct {
		Device Device `plist:"device"`
	}
	if _, err := plist.Unmarshal(raw, &envelope); err == nil && envelope.Device.DeviceNumber != "" {
		return envelope.Device, nil
	}
	if portalErr != nil {
		return Device{}, portalErr
	}
	return Device{}, errors.New("devportal: addDevice missing device")
}

func (s *Session) EnsureDeviceRegistered(ctx context.Context, teamID, name, udid string) error {
	devs, err := s.ListDevices(ctx, teamID)
	if err != nil {
		return err
	}
	for _, d := range devs {
		if strings.EqualFold(d.DeviceNumber, udid) {
			return nil
		}
	}
	if name == "" {
		name = "iPhone"
	}
	_, err = s.AddDevice(ctx, teamID, name, udid)
	if err != nil {
		var pe *PortalError
		if errors.As(err, &pe) && pe.Code == 35 {
			return nil
		}
		return err
	}
	return nil
}

func (s *Session) ListAppIDs(ctx context.Context, teamID string) (ListAppIDsResult, error) {
	dict, raw, portalErr := s.doPlist(ctx, "listAppIds", true, map[string]any{"teamId": teamID})
	var envelope ListAppIDsResult
	if _, err := plist.Unmarshal(raw, &envelope); err == nil && envelope.AppIDs != nil {
		if _, ok := dict["availableQuantity"]; ok {
			envelope.HasAvailable = true
		}
		return envelope, nil
	}
	if portalErr != nil {
		return ListAppIDsResult{}, portalErr
	}
	return envelope, nil
}

func (s *Session) AddAppID(ctx context.Context, teamID, name, bundleID string) (AppID, error) {
	_, raw, portalErr := s.doPlist(ctx, "addAppId", true, map[string]any{
		"teamId":     teamID,
		"identifier": bundleID,
		"name":       normalizePortalName(name),
	})
	var envelope struct {
		AppID AppID `plist:"appId"`
	}
	if _, err := plist.Unmarshal(raw, &envelope); err == nil && envelope.AppID.AppIDID != "" {
		return envelope.AppID, nil
	}
	if portalErr != nil {
		return AppID{}, portalErr
	}
	return AppID{}, errors.New("devportal: addAppId missing appId")
}

// DeleteAppID removes an App ID from the Developer Portal (paid teams free quota immediately;
// free Personal Teams still enforce Apple's 7-day rolling registration window).
func (s *Session) DeleteAppID(ctx context.Context, teamID, appIDID string) error {
	_, _, err := s.doPlist(ctx, "deleteAppId", true, map[string]any{
		"teamId":  teamID,
		"appIdId": appIDID,
	})
	return err
}

func (s *Session) UpdateAppIDFeatures(ctx context.Context, teamID, appIDID string, features map[string]any) (AppID, error) {
	params := map[string]any{
		"teamId":  teamID,
		"appIdId": appIDID,
	}
	for k, v := range features {
		params[k] = v
	}
	_, raw, portalErr := s.doPlist(ctx, "updateAppId", true, params)
	var envelope struct {
		AppID AppID `plist:"appId"`
	}
	if _, err := plist.Unmarshal(raw, &envelope); err == nil && envelope.AppID.AppIDID != "" {
		return envelope.AppID, nil
	}
	if portalErr != nil {
		return AppID{}, portalErr
	}
	return AppID{}, nil
}

func (s *Session) EnsureAppGroupFeature(ctx context.Context, teamID string, id *AppID) error {
	enabled, _ := id.Features["APG3427HIY"].(bool)
	if enabled {
		return nil
	}
	updated, err := s.UpdateAppIDFeatures(ctx, teamID, id.AppIDID, map[string]any{
		"APG3427HIY": true,
	})
	if err != nil {
		return err
	}
	if updated.Features != nil {
		id.Features = updated.Features
	}
	return nil
}

func (s *Session) ListAppGroups(ctx context.Context, teamID string) ([]AppGroup, error) {
	_, raw, portalErr := s.doPlist(ctx, "listApplicationGroups", true, map[string]any{"teamId": teamID})
	var envelope struct {
		Groups []AppGroup `plist:"applicationGroupList"`
	}
	if _, err := plist.Unmarshal(raw, &envelope); err == nil && envelope.Groups != nil {
		return envelope.Groups, nil
	}
	if portalErr != nil {
		return nil, portalErr
	}
	return nil, nil
}

func (s *Session) AddAppGroup(ctx context.Context, teamID, name, identifier string) (AppGroup, error) {
	_, raw, portalErr := s.doPlist(ctx, "addApplicationGroup", true, map[string]any{
		"teamId":     teamID,
		"name":       normalizePortalName(name),
		"identifier": identifier,
	})
	var envelope struct {
		Group AppGroup `plist:"applicationGroup"`
	}
	if _, err := plist.Unmarshal(raw, &envelope); err == nil && envelope.Group.ApplicationGroup != "" {
		return envelope.Group, nil
	}
	if portalErr != nil {
		return AppGroup{}, portalErr
	}
	return AppGroup{}, errors.New("devportal: addApplicationGroup missing applicationGroup")
}

func (s *Session) EnsureAppGroup(ctx context.Context, teamID, name, identifier string) (AppGroup, error) {
	groups, err := s.ListAppGroups(ctx, teamID)
	if err != nil {
		return AppGroup{}, err
	}
	for _, g := range groups {
		if g.Identifier == identifier {
			return g, nil
		}
	}
	return s.AddAppGroup(ctx, teamID, name, identifier)
}

func (s *Session) AssignAppGroup(ctx context.Context, teamID, appGroupID, appIDID string) error {
	_, _, err := s.doPlist(ctx, "assignApplicationGroupToAppId", true, map[string]any{
		"teamId":            teamID,
		"applicationGroups": appGroupID,
		"appIdId":           appIDID,
	})
	return err
}

func (s *Session) AddIncreasedMemoryLimit(ctx context.Context, teamID string, appID AppID) error {
	hdrs, err := s.headers(ctx)
	if err != nil {
		return err
	}
	hdrs.Set("Content-Type", "application/vnd.api+json")
	hdrs.Set("Accept", "application/vnd.api+json")
	payload := map[string]any{
		"data": map[string]any{
			"id":   appID.AppIDID,
			"type": "bundleIds",
			"attributes": map[string]any{
				"hasExclusiveManagedCapabilities": false,
				"teamId":                        teamID,
				"bundleType":                    "bundle",
				"identifier":                    appID.Identifier,
				"seedId":                        teamID,
				"name":                          appID.Name,
			},
			"relationships": map[string]any{
				"bundleIdCapabilities": map[string]any{
					"data": []map[string]any{
						{
							"type":       "bundleIdCapabilities",
							"attributes": map[string]any{"settings": []any{}, "enabled": true},
							"relationships": map[string]any{
								"capability": map[string]any{
									"data": map[string]any{"id": "INCREASED_MEMORY_LIMIT", "type": "capabilities"},
								},
							},
						},
					},
				},
			},
		},
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, "https://developerservices2.apple.com/services/v1/bundleIds/"+appID.AppIDID, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header = hdrs
	resp, err := s.Client.DoRequest(req, true)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("devportal: increased memory limit HTTP %d", resp.StatusCode)
	}
	return nil
}

func (s *Session) DownloadTeamProvisioningProfile(ctx context.Context, teamID, appIDID string) (Profile, error) {
	_, raw, portalErr := s.doPlist(ctx, "downloadTeamProvisioningProfile", true, map[string]any{
		"teamId":  teamID,
		"appIdId": appIDID,
	})
	var envelope struct {
		Profile Profile `plist:"provisioningProfile"`
	}
	if _, err := plist.Unmarshal(raw, &envelope); err == nil && len(envelope.Profile.EncodedProfile) > 0 {
		return envelope.Profile, nil
	}
	if portalErr != nil {
		return Profile{}, portalErr
	}
	return Profile{}, errors.New("devportal: provisioningProfile missing encodedProfile")
}

// CertificateIdentity holds an active iOS Development certificate, private key, and machine ID.
type CertificateIdentity struct {
	MachineID   string
	MachineName string
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

// SerialNumberHex returns the uppercase hex serial number without leading zeroes (as expected by SideStore ALTCertificateID).
func (c *CertificateIdentity) SerialNumberHex() string {
	b := c.Certificate.SerialNumber.Bytes()
	s := strings.ToUpper(strings.TrimLeft(hex.EncodeToString(b), "0"))
	if s == "" {
		return "0"
	}
	return s
}

// ExportP12 encodes the private key and certificate as PKCS#12 protected by password (machine ID for SideStore).
func (c *CertificateIdentity) ExportP12(password string) ([]byte, error) {
	return pkcs12.Modern.Encode(c.PrivateKey, c.Certificate, nil, password)
}

var ErrMaxCertificatesReached = errors.New("devportal: maximum development certificates reached")

// MaxCertsHandler is called when Apple rejects certificate creation due to max active certs.
// Returning non-empty serial numbers revokes them and retries; returning nil aborts.
type MaxCertsHandler func(certs []DevelopmentCertificate) ([]string, error)

// EnsureCertificate loads or creates an RSA-2048 private key in storage, matches an existing
// Apple development certificate for machineName, or submits a new CSR.
func EnsureCertificate(ctx context.Context, sess *Session, teamID, appleEmail, machineName string, store appleauth.Storage, onMaxCerts MaxCertsHandler) (*CertificateIdentity, error) {
	key, err := loadOrCreateRSAKey(appleEmail, store)
	if err != nil {
		return nil, err
	}
	if id, ok := findMatchingCert(ctx, sess, teamID, machineName, key); ok {
		return id, nil
	}

	csrPEM, err := buildCSR(key, appleEmail)
	if err != nil {
		return nil, err
	}

	_, err = sess.SubmitDevelopmentCSR(ctx, teamID, csrPEM, machineName)
	if err != nil {
		var pe *PortalError
		if errors.As(err, &pe) && pe.Code == 7460 {
			certs, listErr := sess.ListAllDevelopmentCerts(ctx, teamID, false)
			if listErr != nil {
				return nil, listErr
			}
			if onMaxCerts == nil {
				return nil, fmt.Errorf("%w (%d existing)", ErrMaxCertificatesReached, len(certs))
			}
			toRevoke, cbErr := onMaxCerts(certs)
			if cbErr != nil {
				return nil, cbErr
			}
			if len(toRevoke) == 0 {
				return nil, ErrMaxCertificatesReached
			}
			for _, serial := range toRevoke {
				if revErr := sess.RevokeDevelopmentCert(ctx, teamID, serial); revErr != nil {
					return nil, revErr
				}
			}
			if _, err = sess.SubmitDevelopmentCSR(ctx, teamID, csrPEM, machineName); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if id, ok := findMatchingCert(ctx, sess, teamID, machineName, key); ok {
		return id, nil
	}
	return nil, errors.New("devportal: submitted CSR but matching certificate not returned")
}

func findMatchingCert(ctx context.Context, sess *Session, teamID, machineName string, key *rsa.PrivateKey) (*CertificateIdentity, bool) {
	certs, err := sess.ListAllDevelopmentCerts(ctx, teamID, true)
	if err != nil {
		return nil, false
	}
	wantPub := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	var fallback *CertificateIdentity
	for _, c := range certs {
		if len(c.CertContent) == 0 || c.MachineID == "" {
			continue
		}
		x509Cert, err := x509.ParseCertificate(c.CertContent)
		if err != nil {
			continue
		}
		rsaPub, ok := x509Cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if !bytes.Equal(x509.MarshalPKCS1PublicKey(rsaPub), wantPub) {
			continue
		}
		id := &CertificateIdentity{
			MachineID:   c.MachineID,
			MachineName: c.MachineName,
			PrivateKey:  key,
			Certificate: x509Cert,
		}
		if machineName == "" || c.MachineName == machineName {
			return id, true
		}
		if fallback == nil {
			fallback = id
		}
	}
	if fallback != nil {
		return fallback, true
	}
	return nil, false
}

// HasLocalRSAKeyForCert reports whether storage holds the RSA private key matching cert.
func HasLocalRSAKeyForCert(appleEmail string, cert DevelopmentCertificate, store appleauth.Storage) bool {
	if store == nil || strings.TrimSpace(appleEmail) == "" || len(cert.CertContent) == 0 {
		return false
	}
	sum := sha1.Sum([]byte(strings.ToLower(strings.TrimSpace(appleEmail))))
	keyName := "dev_key_" + hex.EncodeToString(sum[:])
	raw, err := store.Get(keyName)
	if err != nil || len(raw) == 0 {
		return false
	}
	k, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return false
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return false
	}
	x509Cert, err := x509.ParseCertificate(cert.CertContent)
	if err != nil {
		return false
	}
	rsaPub, ok := x509Cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(x509.MarshalPKCS1PublicKey(rsaPub), x509.MarshalPKCS1PublicKey(&rk.PublicKey))
}

func loadOrCreateRSAKey(appleEmail string, store appleauth.Storage) (*rsa.PrivateKey, error) {
	sum := sha1.Sum([]byte(strings.ToLower(strings.TrimSpace(appleEmail))))
	keyName := "dev_key_" + hex.EncodeToString(sum[:])
	if store != nil {
		if raw, err := store.Get(keyName); err == nil && len(raw) > 0 {
			if k, err := x509.ParsePKCS8PrivateKey(raw); err == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					return rk, nil
				}
			}
		}
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if store != nil {
		if der, err := x509.MarshalPKCS8PrivateKey(rk); err == nil {
			_ = store.Set(keyName, der)
		}
	}
	return rk, nil
}

func buildCSR(key *rsa.PrivateKey, email string) (string, error) {
	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   email,
			Organization: []string{"KoiSide"},
			Country:      []string{"US"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func normalizePortalName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "KoiSideApp"
	}
	return out
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
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
