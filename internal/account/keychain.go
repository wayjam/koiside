package account

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"koiside/internal/appleauth"
)

const (
	keychainServicePrefix = "me.koiside.KoiSide"
	savedAccountsKey      = "saved_apple_accounts"
)

// KeychainStorage stores small secrets (Anisette state, dev RSA keys, pairing files,
// and opt-in saved Apple passwords) in macOS Keychain via /usr/bin/security, with
// file-backed metadata index for account discovery.
type KeychainStorage struct {
	mu      sync.Mutex
	service string
	baseDir string
}

func NewKeychainStorage(baseDir string) *KeychainStorage {
	if baseDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			baseDir = filepath.Join(home, "Library", "Application Support", "KoiSide")
		} else {
			baseDir = filepath.Join(os.TempDir(), "koiside")
		}
	}
	return &KeychainStorage{
		service: keychainServicePrefix,
		baseDir: baseDir,
	}
}

func (k *KeychainStorage) Get(key string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key == "" {
		return nil, errors.New("account: empty storage key")
	}
	out, err := exec.Command("/usr/bin/security", "find-generic-password",
		"-s", k.service, "-a", key, "-w").Output()
	if err == nil {
		raw := strings.TrimSpace(string(out))
		if strings.HasPrefix(raw, "b64:") {
			dec, decErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, "b64:"))
			if decErr == nil {
				return dec, nil
			}
		}
		return []byte(raw), nil
	}
	// Fallback to 0600 file inside user data dir when running headless / non-keychain CI.
	p := k.fallbackPath(key)
	b, readErr := os.ReadFile(p)
	if os.IsNotExist(readErr) {
		return nil, nil
	}
	return b, readErr
}

func (k *KeychainStorage) Set(key string, value []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key == "" {
		return errors.New("account: empty storage key")
	}
	encoded := "b64:" + base64.StdEncoding.EncodeToString(value)
	cmd := exec.Command("/usr/bin/security", "add-generic-password",
		"-U", "-s", k.service, "-a", key, "-w", encoded)
	if err := cmd.Run(); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(k.fallbackPath(key)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(k.fallbackPath(key), value, 0o600)
}

func (k *KeychainStorage) Delete(serviceOrKey, account string) error {
	key := serviceOrKey
	if account != "" && serviceOrKey != k.service {
		key = serviceOrKey + ":" + account
	} else if account != "" {
		key = account
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	_ = exec.Command("/usr/bin/security", "delete-generic-password", "-s", k.service, "-a", key).Run()
	_ = os.Remove(k.fallbackPath(key))
	return nil
}

func (k *KeychainStorage) DeleteKey(key string) error {
	return k.Delete("", key)
}

func (k *KeychainStorage) fallbackPath(key string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "..", "_").Replace(key)
	return filepath.Join(k.baseDir, "secrets", safe+".bin")
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
