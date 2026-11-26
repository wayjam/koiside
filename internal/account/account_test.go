package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"howett.net/plist"

	"koiside/internal/appleauth"
	"koiside/internal/appstore"
)

func TestUnavailableIsSignedOut(t *testing.T) {
	var manager Unavailable
	if manager.Store().SignedIn() || manager.Developer().SignedIn() {
		t.Fatal("unavailable account is signed in")
	}
}

func TestLocalManagerStorageBoundaryAndAnisetteURL(t *testing.T) {
	store := appleauth.NewMemoryStorage()
	mgr := NewLocalManager(store)
	if mgr.Store().SignedIn() || mgr.Developer().SignedIn() {
		t.Fatal("fresh manager should start signed out")
	}
	if mgr.AnisetteURL() != appleauth.DefaultAnisetteV3URL {
		t.Fatalf("unexpected default anisette url %q", mgr.AnisetteURL())
	}
	mgr.SetAnisetteURL("ani.example.com/")
	if mgr.AnisetteURL() != "https://ani.example.com" {
		t.Fatalf("expected normalized https URL, got %q", mgr.AnisetteURL())
	}

	// Reloading manager from same storage must keep normalized Anisette URL.
	mgr2 := NewLocalManager(store)
	if mgr2.AnisetteURL() != "https://ani.example.com" {
		t.Fatalf("expected persisted anisette url, got %q", mgr2.AnisetteURL())
	}
	if mgr2.Store().SignedIn() {
		t.Fatal("Store session must stay separate and signed out")
	}
}

func TestRestoreDeveloperSessionSkipsWhenEmptyAndRestoresFromStorage(t *testing.T) {
	store := appleauth.NewMemoryStorage()
	mgr := NewLocalManager(store)
	if err := mgr.RestoreDeveloperSession(t.Context()); err != nil {
		t.Fatalf("empty restore should return nil, got %v", err)
	}
	if mgr.Developer().SignedIn() {
		t.Fatal("should remain signed out with empty storage")
	}
}

func TestDeveloperSignInStaleAnisettePreservesStoredState(t *testing.T) {
	var signInRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var response map[string]any
		switch r.URL.Path {
		case "/lookup":
			response = map[string]any{"urls": map[string]any{"gsService": "http://" + r.Host + "/gs"}}
		case "/v3/get_headers":
			_ = json.NewEncoder(w).Encode(map[string]string{"X-Apple-I-MD-M": "test-machine", "X-Apple-I-MD": "test-otp"})
			return
		case "/gs":
			signInRequests.Add(1)
			response = map[string]any{"Response": map[string]any{
				"Status": map[string]any{"ec": int64(-22410), "em": "This action could not be completed"},
			}}
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		raw, _ := plist.Marshal(response, plist.XMLFormat)
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	state, err := plist.Marshal(map[string]any{
		"keychain_identifier": make([]byte, 16),
		"adi_pb":              []byte("stored attestation"),
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string][]byte{
		appleauth.AnisetteStateKey: state,
		"active_dev_session":      []byte("stored developer session"),
	}
	store := appleauth.NewMemoryStorage()
	for key, value := range stored {
		if err := store.Set(key, value); err != nil {
			t.Fatal(err)
		}
	}
	mgr := NewLocalManager(store)
	mgr.SetAnisetteURL(srv.URL)
	mgr.SetTestOverrides(func(info appleauth.ClientInfo) (*appleauth.GrandSlamClient, error) {
		return appleauth.NewGrandSlamClientWithHTTP(srv.Client(), info, srv.URL+"/lookup"), nil
	}, "")

	err = mgr.SignInDeveloper(t.Context(), "test@example.com", "test-password", false, nil)
	var authErr *appleauth.AuthError
	if !errors.As(err, &authErr) || authErr.Code != -22410 || !strings.Contains(err.Error(), "Reset Attestation State") {
		t.Fatalf("expected Apple error -22410 with manual recovery guidance, got %v", err)
	}
	if got := signInRequests.Load(); got != 1 {
		t.Errorf("got %d sign-in requests, want 1", got)
	}
	for key, want := range stored {
		if got, err := store.Get(key); err != nil || !bytes.Equal(got, want) {
			t.Errorf("sign-in failure changed stored %s", key)
		}
	}
}

func TestStoreSessionPersistenceSwitchAndForget(t *testing.T) {
	store := appleauth.NewMemoryStorage()
	mgr := NewLocalManager(store)

	accUS := appstore.Account{
		Email:            "us@example.invalid",
		Store:            "143441",
		PasswordToken:    "tok-us",
		DSID:             "101",
		DeviceIdentifier: "aabbccddeeff",
		Pod:              "25",
	}
	accJP := appstore.Account{
		Email:            "jp@example.invalid",
		Store:            "143462",
		PasswordToken:    "tok-jp",
		DSID:             "102",
		DeviceIdentifier: "112233445566",
		Pod:              "10",
	}

	// Persist via helper and verify RestoreStoreSession reloads both accounts.
	mgr.persistStoreAccount(accUS)
	mgr.persistStoreAccount(accJP)

	mgr2 := NewLocalManager(store)
	if err := mgr2.RestoreStoreSession(context.Background()); err != nil {
		t.Fatalf("RestoreStoreSession failed: %v", err)
	}
	if !mgr2.Store().SignedIn() || mgr2.Store().Email() != "jp@example.invalid" || mgr2.Store().CountryCode() != "JP" {
		t.Fatalf("unexpected restored active store session: signedIn=%v email=%s country=%s",
			mgr2.Store().SignedIn(), mgr2.Store().Email(), mgr2.Store().CountryCode())
	}
	if mgr2.Developer().SignedIn() {
		t.Fatal("Store restore must not sign in Developer session")
	}
	if len(mgr2.SavedStoreAccounts()) != 2 {
		t.Fatalf("expected 2 saved store accounts, got %d", len(mgr2.SavedStoreAccounts()))
	}

	if err := mgr2.SwitchStoreAccount("us@example.invalid"); err != nil {
		t.Fatalf("SwitchStoreAccount failed: %v", err)
	}
	if mgr2.Store().Email() != "us@example.invalid" || mgr2.Store().CountryCode() != "US" {
		t.Fatalf("expected US account active, got %s", mgr2.Store().Email())
	}

	mgr2.UpdateStoreCookies("us@example.invalid", []appstore.Cookie{{Name: "s", Value: "v"}})
	raw, _ := store.Get(storeAccPrefix + "us@example.invalid")
	var decoded appstore.Account
	if err := json.Unmarshal(raw, &decoded); err != nil || len(decoded.Cookies) != 1 {
		t.Fatalf("expected updated cookies persisted, got %s", string(raw))
	}

	if err := mgr2.ForgetStoreAccount("us@example.invalid"); err != nil {
		t.Fatalf("ForgetStoreAccount failed: %v", err)
	}
	if len(mgr2.SavedStoreAccounts()) != 1 || mgr2.Store().Email() != "jp@example.invalid" {
		t.Fatalf("expected fallback to jp account after forgetting us, got active=%s saved=%d",
			mgr2.Store().Email(), len(mgr2.SavedStoreAccounts()))
	}

	mgr2.SignOutStore()
	if mgr2.Store().SignedIn() {
		t.Fatal("expected signed out after SignOutStore")
	}
}
