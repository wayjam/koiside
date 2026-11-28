package account

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestKeychainStorageRoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("requires macOS Keychain")
	}
	path := filepath.Join(t.TempDir(), "test.keychain-db")
	runSecurity := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "/usr/bin/security", args...).CombinedOutput(); err != nil {
			t.Fatalf("security %s: %v: %s", args[0], err, out)
		}
	}
	const password = "temporary-test-keychain"
	runSecurity("create-keychain", "-p", password, path)
	t.Cleanup(func() { runSecurity("delete-keychain", path) })
	runSecurity("unlock-keychain", "-p", password, path)
	store := &KeychainStorage{service: "me.koiside.test", keychainPath: path}
	key := "test_large_key"

	// 1. Initial get should fail
	if _, err := store.Get(key); err == nil {
		t.Fatal("expected error on nonexistent key")
	}

	// 2. Set 8KB data
	payload := bytes.Repeat([]byte("A1B2C3D4"), 1024)
	if err := store.Set(key, payload); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// 3. Get should return exact payload without prompts
	got, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Get mismatch: len %d vs %d", len(got), len(payload))
	}

	// 4. Update with smaller payload
	newPayload := []byte("hello-world-updated")
	if err := store.Set(key, newPayload); err != nil {
		t.Fatalf("Set update failed: %v", err)
	}
	got2, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get after update failed: %v", err)
	}
	if !bytes.Equal(got2, newPayload) {
		t.Fatalf("Get after update mismatch: %q", string(got2))
	}

	// 5. Delete key
	if err := store.DeleteKey(key); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}
	if _, err := store.Get(key); err == nil {
		t.Fatal("expected error after delete")
	}
}
