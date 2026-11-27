package account

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"koiside/internal/appleauth"
)

const (
	keychainServicePrefix = "me.koiside.KoiSide"
	savedAccountsKey      = "saved_apple_accounts"
)

var errKeychainItemNotFound = errors.New("keychain item not found")

// KeychainStorage stores secrets (Anisette state, developer keys, pairing files,
// and opt-in saved Apple passwords) in macOS Keychain.
// It fails closed when Keychain is unavailable and never writes secrets to files.
type KeychainStorage struct {
	mu      sync.Mutex
	service string
}

func NewKeychainStorage() *KeychainStorage {
	return &KeychainStorage{service: keychainServicePrefix}
}

func (k *KeychainStorage) Get(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key == "" {
		return nil, errors.New("account: empty storage key")
	}
	value, err := readNativeKeychainItem(k.service+".native", key)
	// Earlier builds created items with the security CLI's access controls.
	if !errors.Is(err, errKeychainItemNotFound) {
		return value, err
	}
	return k.readLegacyItem(key)
}

func (k *KeychainStorage) readLegacyItem(key string) ([]byte, error) {
	out, err := exec.Command("/usr/bin/security", "find-generic-password",
		"-s", k.service, "-a", key, "-w").Output()
	if err != nil {
		return nil, fmt.Errorf("account: read Keychain item: %w", err)
	}
	raw := strings.TrimSpace(string(out))
	if strings.HasPrefix(raw, "b64:") {
		dec, decErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "b64:"))
		if decErr == nil {
			return dec, nil
		}
	}
	return []byte(raw), nil
}

func (k *KeychainStorage) Set(key string, value []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key == "" {
		return errors.New("account: empty storage key")
	}
	if err := writeNativeKeychainItem(k.service+".native", key, value); err != nil {
		return fmt.Errorf("account: write Keychain item: %w", err)
	}
	return nil
}

func (k *KeychainStorage) DeleteKey(key string) error {
	if key == "" {
		return errors.New("account: empty storage key")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := deleteNativeKeychainItem(k.service+".native", key); err != nil && !errors.Is(err, errKeychainItemNotFound) {
		return err
	}
	_ = exec.Command("/usr/bin/security", "delete-generic-password", "-s", k.service, "-a", key).Run()
	return nil
}

// KeychainAppleAuthAdapter wraps KeychainStorage as appleauth.Storage.
type KeychainAppleAuthAdapter struct {
	Store *KeychainStorage
}

func (a KeychainAppleAuthAdapter) Get(key string) ([]byte, error) { return a.Store.Get(key) }
func (a KeychainAppleAuthAdapter) Set(key string, val []byte) error {
	return a.Store.Set(key, val)
}
func (a KeychainAppleAuthAdapter) Delete(key string) error { return a.Store.DeleteKey(key) }

// AccountIndex persists the list of remembered Apple ID emails (non-secret metadata).
func loadAccountList(s appleauth.Storage) []string {
	if s == nil {
		return nil
	}
	raw, err := s.Get(savedAccountsKey)
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil {
		return nil
	}
	return list
}

func saveAccountList(s appleauth.Storage, emails []string) error {
	if s == nil {
		return nil
	}
	raw, err := json.Marshal(emails)
	if err != nil {
		return err
	}
	return s.Set(savedAccountsKey, raw)
}
