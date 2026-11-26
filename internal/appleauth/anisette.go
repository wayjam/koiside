package appleauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"howett.net/plist"
)

const (
	// DefaultAnisetteV3URL is the default community-compatible Anisette v3 endpoint.
	// Only provisioning/header metadata is sent here; Apple ID passwords are never sent to Anisette servers.
	DefaultAnisetteV3URL = "https://ani.iloader.app"
	AnisetteStateKey     = "anisette_state"
)

// DefaultMacClientInfo mimics a modern macOS AuthKit client for Xcode token & developer portal calls.
var DefaultMacClientInfo = ClientInfo{
	ClientInfo: "<MacBookPro18,3> <Mac OS X;26.6;25F84> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
	UserAgent:  "AuthKit/1 (Macintosh; OS X 26.6) (com.apple.akd/1.0)",
}

// Storage persists non-password state such as Anisette provisioning data.
type Storage interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
	Delete(key string) error
}

// MemoryStorage is an in-memory Storage implementation for tests.
type MemoryStorage struct {
	mu   sync.Mutex
	data map[string][]byte
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{data: map[string][]byte{}}
}

func (m *MemoryStorage) Get(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return nil, nil
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (m *MemoryStorage) Set(key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[key] = cp
	return nil
}

func (m *MemoryStorage) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

// ClientInfo describes the platform identity headers required by GrandSlam.
type ClientInfo struct {
	ClientInfo string `json:"client_info"`
	UserAgent  string `json:"user_agent"`
}

func (info ClientInfo) forApple() ClientInfo {
	if strings.Contains(info.ClientInfo, "com.apple.dt.Xcode") {
		return DefaultMacClientInfo
	}
	info.ClientInfo = strings.ReplaceAll(info.ClientInfo, "<macOS;", "<Mac OS X;")
	if _, version, ok := strings.Cut(info.ClientInfo, "<Mac OS X;10."); ok {
		version, _, _ = strings.Cut(version, ";")
		minor, _, _ := strings.Cut(version, ".")
		if n, err := strconv.Atoi(minor); err == nil && n >= 0 && n < 13 {
			return DefaultMacClientInfo
		}
	}
	return info
}

// AnisetteData holds one-time machine attestation headers for Apple requests.
type AnisetteData struct {
	MachineID              string
	OneTimePassword        string
	RoutingInfo            string
	DeviceDescription      string
	DeviceUniqueIdentifier string
	LocalUserID            string
	SerialNumber           string
	GeneratedAt            time.Time
}

// ApplyHeaders adds the required X-Apple-I-* and X-Mme-* headers to req.
func (d AnisetteData) ApplyHeaders(h http.Header) {
	t := d.GeneratedAt.UTC()
	if t.IsZero() {
		t = time.Now().UTC()
	}
	h.Set("X-Apple-I-Client-Time", t.Format("2006-01-02T15:04:05Z"))
	h.Set("X-Apple-I-TimeZone", "UTC")
	h.Set("X-Apple-Locale", "en_US")
	h.Set("X-Apple-I-MD", d.OneTimePassword)
	h.Set("X-Apple-I-MD-M", d.MachineID)
	h.Set("X-Apple-I-MD-RINFO", d.RoutingInfo)
	h.Set("X-Apple-I-MD-LU", d.LocalUserID)
	h.Set("X-Mme-Device-Id", d.DeviceUniqueIdentifier)
	if d.SerialNumber != "" {
		h.Set("X-Apple-I-SRL-NO", d.SerialNumber)
	}
}

// ClientProvidedData builds the GrandSlam "cpd" plist dictionary.
func (d AnisetteData) ClientProvidedData() map[string]any {
	t := d.GeneratedAt.UTC()
	if t.IsZero() {
		t = time.Now().UTC()
	}
	srl := d.SerialNumber
	if srl == "" {
		srl = "0"
	}
	return map[string]any{
		"bootstrap":                 true,
		"icscrec":                   true,
		"loc":                       "en_US",
		"pbe":                       false,
		"prkgen":                    true,
		"svct":                      "iTunes",
		"X-Apple-I-Client-Time":     t.Format("2006-01-02T15:04:05Z"),
		"X-Apple-Locale":            "en_US",
		"X-Apple-I-TimeZone":        "UTC",
		"X-Apple-I-MD":              d.OneTimePassword,
		"X-Apple-I-MD-M":            d.MachineID,
		"X-Apple-I-MD-RINFO":        d.RoutingInfo,
		"X-Apple-I-MD-LU":           d.LocalUserID,
		"X-Apple-I-SRL-NO":          srl,
		"X-Mme-Device-Id":           d.DeviceUniqueIdentifier,
		"X-Apple-I-Device-UserMode": "0",
	}
}

// AnisetteProvider supplies Anisette headers and handles provisioning/resync.
type AnisetteProvider interface {
	GetClientInfo(ctx context.Context) (ClientInfo, error)
	GetAnisetteData(ctx context.Context, gs *GrandSlamClient) (AnisetteData, error)
	Resync(ctx context.Context, gs *GrandSlamClient, sim string) (AnisetteData, error)
	Reset(ctx context.Context) error
}

type anisetteState struct {
	KeychainIdentifier []byte `plist:"keychain_identifier"`
	ADIPB              []byte `plist:"adi_pb,omitempty"`
}

func newAnisetteState() (*anisetteState, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &anisetteState{KeychainIdentifier: id}, nil
}

func (s *anisetteState) provisioned() bool {
	return len(s.KeychainIdentifier) == 16 && len(s.ADIPB) > 0
}

func (s *anisetteState) mdLU() string {
	sum := sha256.Sum256(s.KeychainIdentifier)
	return hex.EncodeToString(sum[:])
}

func (s *anisetteState) deviceID() string {
	b := s.KeychainIdentifier
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// RemoteV3AnisetteProvider talks to an Anisette v3 server over HTTP and WebSocket.
type RemoteV3AnisetteProvider struct {
	mu                 sync.Mutex
	url                string
	serialNumber       string
	storage            Storage
	httpClient         *http.Client
	clientInfoOverride *ClientInfo
	state              *anisetteState
}

// NewRemoteV3AnisetteProvider creates a remote Anisette v3 provider.
func NewRemoteV3AnisetteProvider(serverURL string, storage Storage) *RemoteV3AnisetteProvider {
	u := strings.TrimSpace(serverURL)
	if u == "" {
		u = DefaultAnisetteV3URL
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + u
	}
	u = strings.TrimRight(u, "/")
	if storage == nil {
		storage = NewMemoryStorage()
	}
	override := DefaultMacClientInfo
	return &RemoteV3AnisetteProvider{
		url:                u,
		serialNumber:       "0",
		storage:            storage,
		httpClient:         &http.Client{Timeout: 30 * time.Second},
		clientInfoOverride: &override,
	}
}

func (p *RemoteV3AnisetteProvider) URL() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.url
}

func (p *RemoteV3AnisetteProvider) SetURL(serverURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u := strings.TrimSpace(serverURL)
	if u == "" {
		u = DefaultAnisetteV3URL
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + u
	}
	p.url = strings.TrimRight(u, "/")
}

func (p *RemoteV3AnisetteProvider) SetClientInfoOverride(info *ClientInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if info == nil {
		p.clientInfoOverride = nil
		return
	}
	cp := *info
	p.clientInfoOverride = &cp
}

func (p *RemoteV3AnisetteProvider) Reset(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = nil
	if p.storage != nil {
		return p.storage.Delete(AnisetteStateKey)
	}
	return nil
}

func (p *RemoteV3AnisetteProvider) GetClientInfo(ctx context.Context) (ClientInfo, error) {
	p.mu.Lock()
	override := p.clientInfoOverride
	endpoint := p.url + "/v3/client_info"
	client := p.httpClient
	p.mu.Unlock()

	if override != nil {
		return *override, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ClientInfo{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return ClientInfo{}, fmt.Errorf("appleauth: anisette client_info failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ClientInfo{}, fmt.Errorf("appleauth: anisette client_info HTTP %d", resp.StatusCode)
	}
	var info ClientInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return ClientInfo{}, fmt.Errorf("appleauth: invalid anisette client_info: %w", err)
	}
	return info, nil
}

func (p *RemoteV3AnisetteProvider) GetAnisetteData(ctx context.Context, gs *GrandSlamClient) (AnisetteData, error) {
	return p.fetchWithProvision(ctx, gs, "")
}

func (p *RemoteV3AnisetteProvider) Resync(ctx context.Context, gs *GrandSlamClient, sim string) (AnisetteData, error) {
	return p.fetchWithProvision(ctx, gs, sim)
}

func (p *RemoteV3AnisetteProvider) fetchWithProvision(ctx context.Context, gs *GrandSlamClient, sim string) (AnisetteData, error) {
	for attempt := 0; attempt < 2; attempt++ {
		forceReset := attempt == 1
		st, err := p.ensureState(ctx, gs, forceReset)
		if err != nil {
			return AnisetteData{}, err
		}
		data, needsReprovision, err := p.fetchHeaders(ctx, st, sim)
		if err != nil {
			return AnisetteData{}, err
		}
		if !needsReprovision {
			return data, nil
		}
	}
	return AnisetteData{}, errors.New("appleauth: anisette provisioning rejected after retry")
}

func (p *RemoteV3AnisetteProvider) ensureState(ctx context.Context, gs *GrandSlamClient, forceReset bool) (*anisetteState, error) {
	p.mu.Lock()
	if forceReset {
		p.state = nil
	}
	if p.state == nil && !forceReset && p.storage != nil {
		if raw, err := p.storage.Get(AnisetteStateKey); err == nil && len(raw) > 0 {
			var loaded anisetteState
			if _, err := plist.Unmarshal(raw, &loaded); err == nil && len(loaded.KeychainIdentifier) == 16 {
				p.state = &loaded
			}
		}
	}
	if p.state == nil {
		st, err := newAnisetteState()
		if err != nil {
			p.mu.Unlock()
			return nil, err
		}
		p.state = st
	}
	st := &anisetteState{
		KeychainIdentifier: append([]byte(nil), p.state.KeychainIdentifier...),
		ADIPB:              append([]byte(nil), p.state.ADIPB...),
	}
	endpoint := p.url
	p.mu.Unlock()

	if !st.provisioned() {
		if gs == nil {
			return nil, errors.New("appleauth: GrandSlam client required to provision Anisette")
		}
		if err := p.provision(ctx, st, gs, endpoint); err != nil {
			return nil, err
		}
		encoded, err := plist.Marshal(st, plist.XMLFormat)
		if err == nil && p.storage != nil {
			_ = p.storage.Set(AnisetteStateKey, encoded)
		}
		p.mu.Lock()
		p.state = st
		p.mu.Unlock()
	}
	return st, nil
}

func (p *RemoteV3AnisetteProvider) fetchHeaders(ctx context.Context, st *anisetteState, sim string) (AnisetteData, bool, error) {
	info, err := p.GetClientInfo(ctx)
	if err != nil {
		return AnisetteData{}, false, err
	}
	payload := map[string]any{
		"identifier": base64.StdEncoding.EncodeToString(st.KeychainIdentifier),
		"adi_pb":     base64.StdEncoding.EncodeToString(st.ADIPB),
	}
	if sim != "" {
		payload["sim"] = sim
		payload["device_id"] = st.deviceID()
		payload["md_lu"] = st.mdLU()
	}
	rawBody, err := json.Marshal(payload)
	if err != nil {
		return AnisetteData{}, false, err
	}
	p.mu.Lock()
	endpoint := p.url + "/v3/get_headers"
	client := p.httpClient
	serial := p.serialNumber
	p.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(rawBody))
	if err != nil {
		return AnisetteData{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return AnisetteData{}, false, fmt.Errorf("appleauth: anisette get_headers failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return AnisetteData{}, false, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AnisetteData{}, false, fmt.Errorf("appleauth: anisette get_headers HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var decoded struct {
		Result      string `json:"result"`
		Message     string `json:"message"`
		MachineID   string `json:"X-Apple-I-MD-M"`
		OTP         string `json:"X-Apple-I-MD"`
		RoutingInfo string `json:"X-Apple-I-MD-RINFO"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return AnisetteData{}, false, fmt.Errorf("appleauth: invalid anisette headers JSON: %w", err)
	}
	if decoded.Result == "GetHeadersError" {
		if strings.Contains(decoded.Message, "-45061") {
			return AnisetteData{}, true, nil
		}
		return AnisetteData{}, false, fmt.Errorf("appleauth: anisette error: %s", decoded.Message)
	}
	if decoded.MachineID == "" || decoded.OTP == "" {
		return AnisetteData{}, false, errors.New("appleauth: anisette server returned empty attestation headers")
	}
	return AnisetteData{
		MachineID:              decoded.MachineID,
		OneTimePassword:        decoded.OTP,
		RoutingInfo:            decoded.RoutingInfo,
		DeviceDescription:      info.ClientInfo,
		DeviceUniqueIdentifier: st.deviceID(),
		LocalUserID:            st.mdLU(),
		SerialNumber:           serial,
		GeneratedAt:            time.Now().UTC(),
	}, false, nil
}

func (p *RemoteV3AnisetteProvider) provision(ctx context.Context, st *anisetteState, gs *GrandSlamClient, baseURL string) error {
	startURL, err := gs.URL("midStartProvisioning")
	if err != nil {
		return err
	}
	endURL, err := gs.URL("midFinishProvisioning")
	if err != nil {
		return err
	}

	wsURL := baseURL + "/v3/provisioning_session"
	if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
	} else if strings.HasPrefix(wsURL, "http://") {
		wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
	}

	ws, err := dialWS(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("appleauth: connect anisette provisioning: %w", err)
	}
	defer ws.Close()

	provHeaders := http.Header{}
	provHeaders.Set("X-Apple-I-MD-LU", st.mdLU())
	provHeaders.Set("X-Mme-Device-Id", st.deviceID())

	for {
		text, closed, err := ws.ReadText(ctx)
		if err != nil {
			return fmt.Errorf("appleauth: anisette provisioning read: %w", err)
		}
		if closed {
			return errors.New("appleauth: anisette provisioning socket closed unexpectedly")
		}
		var msg struct {
			Result  string `json:"result"`
			CPIM    string `json:"cpim"`
			ADIPB   string `json:"adi_pb"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(text), &msg); err != nil {
			return fmt.Errorf("appleauth: invalid provisioning message: %w", err)
		}
		switch msg.Result {
		case "GiveIdentifier":
			b, _ := json.Marshal(map[string]string{
				"identifier": base64.StdEncoding.EncodeToString(st.KeychainIdentifier),
			})
			if err := ws.SendText(string(b)); err != nil {
				return err
			}
		case "GiveStartProvisioningData":
			body := map[string]any{
				"Header":  map[string]any{},
				"Request": map[string]any{},
			}
			resp, err := gs.PlistRequest(ctx, startURL, body, provHeaders)
			if err != nil {
				return fmt.Errorf("appleauth: Apple start provisioning failed: %w", err)
			}
			spim, _ := resp["spim"].(string)
			if spim == "" {
				return errors.New("appleauth: Apple start provisioning missing spim")
			}
			b, _ := json.Marshal(map[string]string{"spim": spim})
			if err := ws.SendText(string(b)); err != nil {
				return err
			}
		case "GiveEndProvisioningData":
			body := map[string]any{
				"Header": map[string]any{},
				"Request": map[string]any{
					"cpim": msg.CPIM,
				},
			}
			resp, err := gs.PlistRequest(ctx, endURL, body, provHeaders)
			if err != nil {
				return fmt.Errorf("appleauth: Apple finish provisioning failed: %w", err)
			}
			ptm, _ := resp["ptm"].(string)
			tk, _ := resp["tk"].(string)
			if ptm == "" || tk == "" {
				return errors.New("appleauth: Apple finish provisioning missing ptm/tk")
			}
			b, _ := json.Marshal(map[string]string{"ptm": ptm, "tk": tk})
			if err := ws.SendText(string(b)); err != nil {
				return err
			}
		case "ProvisioningSuccess":
			decoded, err := base64.StdEncoding.DecodeString(msg.ADIPB)
			if err != nil || len(decoded) == 0 {
				return errors.New("appleauth: invalid adi_pb in ProvisioningSuccess")
			}
			st.ADIPB = decoded
			return nil
		case "Timeout":
			return errors.New("appleauth: anisette provisioning timed out")
		case "InvalidIdentifier":
			return errors.New("appleauth: anisette provisioning invalid identifier")
		case "StartProvisioningError", "EndProvisioningError":
			return fmt.Errorf("appleauth: %s: %s", msg.Result, msg.Message)
		}
	}
}
