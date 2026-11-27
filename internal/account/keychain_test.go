package account

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestKeychainStorageRoundTrip(t *testing.T) {
	service := fmt.Sprintf("me.koiside.test.%d", time.Now().UnixNano())
	store := &KeychainStorage{service: service}
	key := "test_large_key"

	t.Cleanup(func() {
		_ = store.DeleteKey(key)
	})

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
