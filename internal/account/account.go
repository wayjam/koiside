// Package account manages Apple ID sessions for KoiSide.
// Store and Developer sessions remain independent and never leak secrets into logs.
package account

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"koiside/internal/appleauth"
	"koiside/internal/appstore"
	"koiside/internal/devportal"
)

// Manager is the single place the app asks which service is signed in and triggers login/logout.
type Manager interface {
	Store() StoreSession
	Developer() DeveloperSession
	SignInDeveloper(ctx context.Context, email, password string, savePassword bool, on2FA appleauth.TwoFactorFunc) error
	SignInSavedDeveloper(ctx context.Context, email string, on2FA appleauth.TwoFactorFunc) error
	RestoreDeveloperSession(ctx context.Context) error
	SignOutDeveloper()
	ForgetSavedAccount(email string) error
	SavedAccounts() []string
	AnisetteURL() string
	SetAnisetteURL(url string)
	ResetAnisetteState(ctx context.Context) error
	Storage() appleauth.Storage
	DeveloperPortal() (*devportal.Session, error)

	SignInStore(ctx context.Context, email, password string, onCode StoreCodeFunc) error
	RestoreStoreSession(ctx context.Context) error
	SignOutStore()
	SwitchStoreAccount(email string) error
	ForgetStoreAccount(email string) error
	SavedStoreAccounts() []StoreAccountSummary
	StoreClient() *appstore.Client
	UpdateStoreCookies(email string, cookies []appstore.Cookie)
}

// StoreCodeFunc prompts for an App Store 2FA verification code when Apple challenges sign-in.
type StoreCodeFunc func(ctx context.Context, email string) (string, error)

// StoreAccountSummary describes one persisted App Store account without exposing secrets.
type StoreAccountSummary struct {
	Email       string `json:"email"`
	StoreFront  string `json:"store_front"`
	CountryCode string `json:"country_code"`
	Pod         string `json:"pod,omitempty"`
}

// StoreSession exposes the active App Store account session.
type StoreSession interface {
	SignedIn() bool
	Email() string
	StoreFront() string
	CountryCode() string
	DSID() string
	Pod() string
	DeviceID() string
	Account() (appstore.Account, bool)
}

// DeveloperSession exposes active Apple Developer account and team status.
type DeveloperSession interface {
	SignedIn() bool
	Email() string
	FullName() string
	Teams() []devportal.Team
	ActiveTeam() (devportal.Team, bool)
	SelectTeam(teamID string) bool
}

// CredentialStore deletes persisted credentials for one service/account pair.
type CredentialStore interface {
	Delete(service, account string) error
}

// Unavailable is a signed-out placeholder manager.
type Unavailable struct{}

func (Unavailable) Store() StoreSession         { return unavailableSession{} }
func (Unavailable) Developer() DeveloperSession { return unavailableDevSession{} }
func (Unavailable) SignInDeveloper(context.Context, string, string, bool, appleauth.TwoFactorFunc) error {
	return errors.New("account: unavailable")
}
func (Unavailable) SignInSavedDeveloper(context.Context, string, appleauth.TwoFactorFunc) error {
	return errors.New("account: unavailable")
}
func (Unavailable) RestoreDeveloperSession(context.Context) error { return nil }
func (Unavailable) SignOutDeveloper()                             {}
func (Unavailable) ForgetSavedAccount(string) error               { return nil }
func (Unavailable) SavedAccounts() []string                       { return nil }
func (Unavailable) AnisetteURL() string                           { return appleauth.DefaultAnisetteV3URL }
func (Unavailable) SetAnisetteURL(string)                         {}
func (Unavailable) ResetAnisetteState(context.Context) error      { return nil }
func (Unavailable) Storage() appleauth.Storage                    { return nil }
func (Unavailable) DeveloperPortal() (*devportal.Session, error) {
	return nil, errors.New("not signed in")
}
func (Unavailable) SignInStore(context.Context, string, string, StoreCodeFunc) error {
	return errors.New("account: unavailable")
}
func (Unavailable) RestoreStoreSession(context.Context) error    { return nil }
func (Unavailable) SignOutStore()                                {}
func (Unavailable) SwitchStoreAccount(string) error              { return errors.New("account: unavailable") }
func (Unavailable) ForgetStoreAccount(string) error              { return nil }
func (Unavailable) SavedStoreAccounts() []StoreAccountSummary    { return nil }
func (Unavailable) StoreClient() *appstore.Client                { return appstore.NewClient() }
func (Unavailable) UpdateStoreCookies(string, []appstore.Cookie) {}

type unavailableSession struct{}

func (unavailableSession) SignedIn() bool                    { return false }
func (unavailableSession) Email() string                     { return "" }
func (unavailableSession) StoreFront() string                { return "" }
func (unavailableSession) CountryCode() string               { return "" }
func (unavailableSession) DSID() string                      { return "" }
func (unavailableSession) Pod() string                       { return "" }
func (unavailableSession) DeviceID() string                  { return "" }
func (unavailableSession) Account() (appstore.Account, bool) { return appstore.Account{}, false }

type unavailableDevSession struct{}

func (unavailableDevSession) SignedIn() bool                     { return false }
func (unavailableDevSession) Email() string                      { return "" }
func (unavailableDevSession) FullName() string                   { return "" }
func (unavailableDevSession) Teams() []devportal.Team            { return nil }
func (unavailableDevSession) ActiveTeam() (devportal.Team, bool) { return devportal.Team{}, false }
func (unavailableDevSession) SelectTeam(string) bool             { return false }

// LocalManager manages live Developer sessions using pure-Go GrandSlam SRP + Anisette v3.
type LocalManager struct {
	mu           sync.Mutex
	storage      appleauth.Storage
	anisette     *appleauth.RemoteV3AnisetteProvider
	gsFactory    func(info appleauth.ClientInfo) (*appleauth.GrandSlamClient, error)
	devPortalURL string

	appleAccount *appleauth.AppleAccount
	devSession   *devportal.Session
	teams        []devportal.Team
	activeTeamID string

	storeClient   *appstore.Client
	storeAccounts map[string]appstore.Account
	activeStore   string
}

// NewLocalManager builds the desktop account manager backed by Keychain/local secrets.
func NewLocalManager(storage appleauth.Storage) *LocalManager {
	if storage == nil {
		storage = KeychainAppleAuthAdapter{Store: NewKeychainStorage()}
	}
	savedURL := appleauth.DefaultAnisetteV3URL
	if raw, err := storage.Get("anisette_server_url"); err == nil && strings.TrimSpace(string(raw)) != "" {
		savedURL = strings.TrimSpace(string(raw))
	}
	return &LocalManager{
		storage:       storage,
		anisette:      appleauth.NewRemoteV3AnisetteProvider(savedURL, storage),
		storeClient:   appstore.NewClient(),
		storeAccounts: map[string]appstore.Account{},
		gsFactory: func(info appleauth.ClientInfo) (*appleauth.GrandSlamClient, error) {
			return appleauth.NewGrandSlamClient(info, nil)
		},
	}
}

// SetTestOverrides allows unit tests to inject mock GrandSlam and DevPortal endpoints.
func (m *LocalManager) SetTestOverrides(gsFactory func(info appleauth.ClientInfo) (*appleauth.GrandSlamClient, error), devPortalBaseURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gsFactory = gsFactory
	m.devPortalURL = devPortalBaseURL
}

func (m *LocalManager) Storage() appleauth.Storage { return m.storage }

func (m *LocalManager) Store() StoreSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	acc, ok := m.storeAccounts[m.activeStore]
	if !ok || acc.Email == "" {
		return unavailableSession{}
	}
	return liveStoreSession{acc: cloneStoreAccount(acc)}
}

func (m *LocalManager) StoreClient() *appstore.Client {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.storeClient == nil {
		return appstore.NewClient()
	}
	return m.storeClient
}

// SetStoreClient allows tests to inject a mock App Store client.
func (m *LocalManager) SetStoreClient(client *appstore.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storeClient = client
}
func (m *LocalManager) Developer() DeveloperSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.devSession == nil || m.appleAccount == nil {
		return unavailableDevSession{}
	}
	teamsCopy := append([]devportal.Team(nil), m.teams...)
	return &liveDevSession{
		manager:    m,
		email:      m.appleAccount.Email,
		fullName:   m.appleAccount.FullName(),
		teams:      teamsCopy,
		activeTeam: m.activeTeamID,
	}
}

func (m *LocalManager) AnisetteURL() string {
	return m.anisette.URL()
}

func (m *LocalManager) SetAnisetteURL(serverURL string) {
	m.anisette.SetURL(serverURL)
	if m.storage != nil {
		_ = m.storage.Set("anisette_server_url", []byte(m.anisette.URL()))
	}
}

func (m *LocalManager) ResetAnisetteState(ctx context.Context) error {
	return m.anisette.Reset(ctx)
}

func (m *LocalManager) SavedAccounts() []string {
	return loadAccountList(m.storage)
}

func (m *LocalManager) SignInDeveloper(ctx context.Context, email, password string, savePassword bool, on2FA appleauth.TwoFactorFunc) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return errors.New("account: email and password are required")
	}

	info, err := m.anisette.GetClientInfo(ctx)
	if err != nil {
		return err
	}
	gs, err := m.gsFactory(info)
	if err != nil {
		return err
	}
	acc, err := appleauth.Login(ctx, email, password, m.anisette, gs, on2FA)
	if err != nil {
		return err
	}
	devSess, err := devportal.NewSession(ctx, acc)
	if err != nil {
		return err
	}
	if m.devPortalURL != "" {
		devSess.BaseURL = m.devPortalURL
	}
	teams, err := devSess.ListTeams(ctx)
	if err != nil {
		return err
	}

	activeID := ""
	if len(teams) > 0 {
		activeID = teams[0].TeamID
	}

	m.mu.Lock()
	m.appleAccount = acc
	m.devSession = devSess
	m.teams = teams
	m.activeTeamID = activeID
	m.mu.Unlock()

	if m.storage != nil {
		if rawSess, serErr := acc.MarshalSession(); serErr == nil {
			_ = m.storage.Set("active_dev_session", rawSess)
		}
	}
	if savePassword && m.storage != nil {
		_ = m.storage.Set("apple_pw_"+email, []byte(password))
		existing := loadAccountList(m.storage)
		found := false
		for _, item := range existing {
			if item == email {
				found = true
				break
			}
		}
		if !found {
			_ = saveAccountList(m.storage, append(existing, email))
		}
	}
	return nil
}

func (m *LocalManager) SignInSavedDeveloper(ctx context.Context, email string, on2FA appleauth.TwoFactorFunc) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if m.storage == nil {
		return errors.New("account: no credential storage")
	}
	pw, err := m.storage.Get("apple_pw_" + email)
	if err != nil || len(pw) == 0 {
		return errors.New("account: no saved password for " + email)
	}
	return m.SignInDeveloper(ctx, email, string(pw), false, on2FA)
}

// RestoreDeveloperSession restores a persisted GrandSlam SPD session from storage
// without prompting for a password. Returns nil if no persisted session exists.
func (m *LocalManager) RestoreDeveloperSession(ctx context.Context) error {
	if m.Developer().SignedIn() {
		return nil
	}
	if m.storage == nil {
		return nil
	}
	raw, err := m.storage.Get("active_dev_session")
	if err != nil || len(raw) == 0 {
		return nil
	}
	info, err := m.anisette.GetClientInfo(ctx)
	if err != nil {
		return err
	}
	gs, err := m.gsFactory(info)
	if err != nil {
		return err
	}
	if err := gs.EnsureBag(ctx); err != nil {
		return err
	}
	acc, err := appleauth.RestoreSession(raw, m.anisette, gs)
	if err != nil {
		_ = m.storage.Delete("active_dev_session")
		return err
	}
	devSess, err := devportal.NewSession(ctx, acc)
	if err != nil {
		return err
	}
	if m.devPortalURL != "" {
		devSess.BaseURL = m.devPortalURL
	}
	teams, err := devSess.ListTeams(ctx)
	if err != nil {
		return err
	}
	activeID := ""
	if len(teams) > 0 {
		activeID = teams[0].TeamID
	}
	m.mu.Lock()
	m.appleAccount = acc
	m.devSession = devSess
	m.teams = teams
	m.activeTeamID = activeID
	m.mu.Unlock()
	return nil
}
func (m *LocalManager) SignOutDeveloper() {
	m.mu.Lock()
	m.appleAccount = nil
	m.devSession = nil
	m.teams = nil
	m.activeTeamID = ""
	m.mu.Unlock()
	if m.storage != nil {
		_ = m.storage.Delete("active_dev_session")
	}
}

func (m *LocalManager) ForgetSavedAccount(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if m.storage == nil {
		return nil
	}
	_ = m.storage.Delete("apple_pw_" + email)
	_ = m.storage.Delete("active_dev_session")
	existing := loadAccountList(m.storage)
	var kept []string
	for _, item := range existing {
		if item != email {
			kept = append(kept, item)
		}
	}
	if err := saveAccountList(m.storage, kept); err != nil {
		return err
	}
	m.mu.Lock()
	if m.appleAccount != nil && m.appleAccount.Email == email {
		m.appleAccount = nil
		m.devSession = nil
		m.teams = nil
		m.activeTeamID = ""
	}
	m.mu.Unlock()
	return nil
}

func (m *LocalManager) DeveloperPortal() (*devportal.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.devSession == nil {
		return nil, errors.New("account: developer session not signed in")
	}
	return m.devSession, nil
}

type liveDevSession struct {
	manager    *LocalManager
	email      string
	fullName   string
	teams      []devportal.Team
	activeTeam string
}

func (s *liveDevSession) SignedIn() bool          { return s.email != "" }
func (s *liveDevSession) Email() string           { return s.email }
func (s *liveDevSession) FullName() string        { return s.fullName }
func (s *liveDevSession) Teams() []devportal.Team { return append([]devportal.Team(nil), s.teams...) }
func (s *liveDevSession) ActiveTeam() (devportal.Team, bool) {
	for _, t := range s.teams {
		if t.TeamID == s.activeTeam {
			return t, true
		}
	}
	if len(s.teams) > 0 {
		return s.teams[0], true
	}
	return devportal.Team{}, false
}
func (s *liveDevSession) SelectTeam(teamID string) bool {
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()
	for _, t := range s.manager.teams {
		if t.TeamID == teamID {
			s.manager.activeTeamID = teamID
			return true
		}
	}
	return false
}

const (
	storeIndexKey  = "store_account_index"
	storeActiveKey = "store_active_account"
	storeAccPrefix = "store_session_"
	storeDevPrefix = "store_device_id_"
)

type liveStoreSession struct {
	acc appstore.Account
}

func (s liveStoreSession) SignedIn() bool     { return s.acc.Email != "" && s.acc.PasswordToken != "" }
func (s liveStoreSession) Email() string      { return s.acc.Email }
func (s liveStoreSession) StoreFront() string { return s.acc.Store }
func (s liveStoreSession) CountryCode() string {
	c, _ := appstore.StoreIDToCountry(s.acc.Store)
	return c
}
func (s liveStoreSession) DSID() string     { return s.acc.DSID }
func (s liveStoreSession) Pod() string      { return s.acc.Pod }
func (s liveStoreSession) DeviceID() string { return s.acc.DeviceIdentifier }
func (s liveStoreSession) Account() (appstore.Account, bool) {
	return cloneStoreAccount(s.acc), s.SignedIn()
}

func cloneStoreAccount(acc appstore.Account) appstore.Account {
	cp := acc
	cp.Cookies = append([]appstore.Cookie(nil), acc.Cookies...)
	return cp
}

// SignInStore authenticates an App Store account via SAP + Authenticate, prompting for 2FA if needed,
// and persists the resulting session independently from Developer sessions.
func (m *LocalManager) SignInStore(ctx context.Context, email, password string, onCode StoreCodeFunc) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return errors.New("account: email and password are required")
	}

	deviceID := m.loadOrCreateStoreDeviceID(email)
	client := m.StoreClient()
	auth := appstore.NewAuthenticator(client, deviceID, nil)

	acc, err := auth.Authenticate(ctx, email, password, "", nil)
	if err != nil {
		var authErr *appstore.AuthError
		if errors.As(err, &authErr) && authErr.CodeRequired {
			if onCode == nil {
				return authErr
			}
			code, codeErr := onCode(ctx, email)
			if codeErr != nil {
				return codeErr
			}
			code = strings.TrimSpace(code)
			if code == "" {
				return errors.New("account: verification code is required")
			}
			acc, err = auth.Authenticate(ctx, email, password, code, nil)
		}
		if err != nil {
			return err
		}
	}
	acc.Email = email

	m.mu.Lock()
	if m.storeAccounts == nil {
		m.storeAccounts = map[string]appstore.Account{}
	}
	m.storeAccounts[email] = cloneStoreAccount(acc)
	m.activeStore = email
	m.mu.Unlock()

	m.persistStoreAccount(acc)
	return nil
}

// RestoreStoreSession reloads persisted App Store accounts and the active selection from Keychain storage.
func (m *LocalManager) RestoreStoreSession(context.Context) error {
	if m.storage == nil {
		return nil
	}
	emails := loadStoreAccountIndex(m.storage)
	loaded := make(map[string]appstore.Account, len(emails))
	for _, em := range emails {
		raw, err := m.storage.Get(storeAccPrefix + em)
		if err != nil || len(raw) == 0 {
			continue
		}
		var acc appstore.Account
		if err := json.Unmarshal(raw, &acc); err == nil && acc.Email != "" && acc.PasswordToken != "" {
			loaded[em] = acc
		}
	}
	active := ""
	if rawActive, err := m.storage.Get(storeActiveKey); err == nil {
		active = strings.TrimSpace(string(rawActive))
	}
	if _, ok := loaded[active]; !ok {
		active = ""
		for _, em := range emails {
			if _, ok := loaded[em]; ok {
				active = em
				break
			}
		}
	}

	m.mu.Lock()
	m.storeAccounts = loaded
	m.activeStore = active
	m.mu.Unlock()
	return nil
}

// SignOutStore clears the active App Store selection without deleting saved Store sessions.
func (m *LocalManager) SignOutStore() {
	m.mu.Lock()
	m.activeStore = ""
	m.mu.Unlock()
	if m.storage != nil {
		_ = m.storage.Delete(storeActiveKey)
	}
}

// SwitchStoreAccount switches the active persisted App Store account.
func (m *LocalManager) SwitchStoreAccount(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	m.mu.Lock()
	_, ok := m.storeAccounts[email]
	if ok {
		m.activeStore = email
	}
	m.mu.Unlock()
	if !ok {
		return errors.New("account: store account not found: " + email)
	}
	if m.storage != nil {
		_ = m.storage.Set(storeActiveKey, []byte(email))
	}
	return nil
}

// ForgetStoreAccount removes one persisted App Store account and its device ID.
func (m *LocalManager) ForgetStoreAccount(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	m.mu.Lock()
	delete(m.storeAccounts, email)
	if m.activeStore == email {
		m.activeStore = ""
		for em := range m.storeAccounts {
			m.activeStore = em
			break
		}
	}
	nextActive := m.activeStore
	m.mu.Unlock()

	if m.storage != nil {
		_ = m.storage.Delete(storeAccPrefix + email)
		_ = m.storage.Delete(storeDevPrefix + email)
		var kept []string
		for _, item := range loadStoreAccountIndex(m.storage) {
			if item != email {
				kept = append(kept, item)
			}
		}
		_ = saveStoreAccountIndex(m.storage, kept)
		if nextActive != "" {
			_ = m.storage.Set(storeActiveKey, []byte(nextActive))
		} else {
			_ = m.storage.Delete(storeActiveKey)
		}
	}
	return nil
}

// SavedStoreAccounts returns non-secret summaries of all saved App Store accounts.
func (m *LocalManager) SavedStoreAccounts() []StoreAccountSummary {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]StoreAccountSummary, 0, len(m.storeAccounts))
	for _, acc := range m.storeAccounts {
		country, _ := appstore.StoreIDToCountry(acc.Store)
		out = append(out, StoreAccountSummary{
			Email:       acc.Email,
			StoreFront:  acc.Store,
			CountryCode: country,
			Pod:         acc.Pod,
		})
	}
	return out
}

// UpdateStoreCookies refreshes persisted cookies after Store API calls.
func (m *LocalManager) UpdateStoreCookies(email string, cookies []appstore.Cookie) {
	email = strings.ToLower(strings.TrimSpace(email))
	m.mu.Lock()
	acc, ok := m.storeAccounts[email]
	if ok {
		acc.Cookies = append([]appstore.Cookie(nil), cookies...)
		m.storeAccounts[email] = acc
	}
	m.mu.Unlock()
	if ok {
		m.persistStoreAccount(acc)
	}
}

func (m *LocalManager) loadOrCreateStoreDeviceID(email string) string {
	if m.storage != nil {
		if raw, err := m.storage.Get(storeDevPrefix + email); err == nil {
			id := strings.TrimSpace(string(raw))
			if len(id) == 12 {
				return id
			}
		}
	}
	id := appstore.GenerateDeviceID()
	if m.storage != nil {
		_ = m.storage.Set(storeDevPrefix+email, []byte(id))
	}
	return id
}

func (m *LocalManager) persistStoreAccount(acc appstore.Account) {
	if m.storage == nil || acc.Email == "" {
		return
	}
	if raw, err := json.Marshal(acc); err == nil {
		_ = m.storage.Set(storeAccPrefix+acc.Email, raw)
	}
	_ = m.storage.Set(storeActiveKey, []byte(acc.Email))
	existing := loadStoreAccountIndex(m.storage)
	for _, item := range existing {
		if item == acc.Email {
			return
		}
	}
	_ = saveStoreAccountIndex(m.storage, append(existing, acc.Email))
}

func loadStoreAccountIndex(s appleauth.Storage) []string {
	if s == nil {
		return nil
	}
	raw, err := s.Get(storeIndexKey)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func saveStoreAccountIndex(s appleauth.Storage, emails []string) error {
	if s == nil {
		return nil
	}
	raw, err := json.Marshal(emails)
	if err != nil {
		return err
	}
	return s.Set(storeIndexKey, raw)
}
