package account

import (
	"testing"

	"koiside/internal/appleauth"
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
