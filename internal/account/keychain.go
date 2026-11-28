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


// KeychainStorage stores secrets (Anisette state, developer keys, pairing files,
// and opt-in saved Apple passwords) in macOS Keychain.
// It fails closed when Keychain is unavailable and never writes secrets to files.
type KeychainStorage struct {
	mu           sync.Mutex
	service      string
	keychainPath string
}

func NewKeychainStorage() *KeychainStorage {
	return &KeychainStorage{service: keychainServicePrefix}
}

func (k *KeychainStorage) securityCommand(args ...string) *exec.Cmd {
	if k.keychainPath != "" {
		args = append(args, k.keychainPath)
	}
	return exec.Command("/usr/bin/security", args...)
}

func (k *KeychainStorage) Get(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key == "" {
		return nil, errors.New("account: empty storage key")
	}
	out, err := k.securityCommand("find-generic-password", "-s", k.service, "-a", key, "-w").Output()
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
	encoded := "b64:" + base64.StdEncoding.EncodeToString(value)
	// With -U, supplying an ACL makes security ask to change the existing item's access.
	cmd := k.securityCommand("add-generic-password", "-U", "-s", k.service, "-a", key, "-w", encoded)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("account: write Keychain item: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (k *KeychainStorage) DeleteKey(key string) error {
	if key == "" {
		return errors.New("account: empty storage key")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	_ = k.securityCommand("delete-generic-password", "-s", k.service, "-a", key).Run()
	_ = k.securityCommand("delete-generic-password", "-s", k.service+".native", "-a", key).Run()
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
