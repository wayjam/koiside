// Package account manages Apple ID sessions for KoiSide.
// Store and Developer sessions remain independent and never leak secrets into logs.
package account

import (
	"context"
	"errors"
	"strings"
	"sync"

	"koiside/internal/appleauth"
	"koiside/internal/devportal"
)

// Manager is the single place the app asks which service is signed in and triggers login/logout.
type Manager interface {
	Store() StoreSession
	Developer() DeveloperSession
	SignInDeveloper(ctx context.Context, email, password string, savePassword bool, on2FA appleauth.TwoFactorFunc) error
	SignInSavedDeveloper(ctx context.Context, email string, on2FA appleauth.TwoFactorFunc) error
	SignOutDeveloper()
	ForgetSavedAccount(email string) error
	SavedAccounts() []string
	AnisetteURL() string
	SetAnisetteURL(url string)
	ResetAnisetteState(ctx context.Context) error
	Storage() appleauth.Storage
	DeveloperPortal() (*devportal.Session, error)
}

// StoreSession is the App Store sign-in boundary (reserved for optional Store download milestone).
type StoreSession interface {
	SignedIn() bool
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
func (Unavailable) SignOutDeveloper()                  {}
func (Unavailable) ForgetSavedAccount(string) error    { return nil }
func (Unavailable) SavedAccounts() []string            { return nil }
func (Unavailable) AnisetteURL() string                { return appleauth.DefaultAnisetteV3URL }
func (Unavailable) SetAnisetteURL(string)              {}
func (Unavailable) ResetAnisetteState(context.Context) error {
	return nil
}
func (Unavailable) Storage() appleauth.Storage                 { return nil }
func (Unavailable) DeveloperPortal() (*devportal.Session, error) { return nil, errors.New("not signed in") }

type unavailableSession struct{}

func (unavailableSession) SignedIn() bool { return false }

type unavailableDevSession struct{}

func (unavailableDevSession) SignedIn() bool                   { return false }
func (unavailableDevSession) Email() string                    { return "" }
func (unavailableDevSession) FullName() string                 { return "" }
func (unavailableDevSession) Teams() []devportal.Team          { return nil }
func (unavailableDevSession) ActiveTeam() (devportal.Team, bool) { return devportal.Team{}, false }
func (unavailableDevSession) SelectTeam(string) bool           { return false }

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
}

// NewLocalManager builds the desktop account manager backed by Keychain/local secrets.
func NewLocalManager(storage appleauth.Storage) *LocalManager {
	if storage == nil {
		storage = KeychainAppleAuthAdapter{Store: NewKeychainStorage("")}
	}
	savedURL := appleauth.DefaultAnisetteV3URL
	if raw, err := storage.Get("anisette_server_url"); err == nil && strings.TrimSpace(string(raw)) != "" {
		savedURL = strings.TrimSpace(string(raw))
	}
	return &LocalManager{
		storage:  storage,
		anisette: appleauth.NewRemoteV3AnisetteProvider(savedURL, storage),
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

func (m *LocalManager) Store() StoreSession { return unavailableSession{} }

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

func (m *LocalManager) SignOutDeveloper() {
	m.mu.Lock()
	m.appleAccount = nil
	m.devSession = nil
	m.teams = nil
	m.activeTeamID = ""
	m.mu.Unlock()
}

func (m *LocalManager) ForgetSavedAccount(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if m.storage == nil {
		return nil
	}
	_ = m.storage.Delete("apple_pw_" + email)
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
