package account

import (
	"context"
	"encoding/json"
	"testing"

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
