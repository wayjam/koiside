//go:build !darwin

package account

import "errors"

var errKeychainUnavailable = errors.New("macOS Keychain unavailable")

func readNativeKeychainItem(_, _ string) ([]byte, error)  { return nil, errKeychainUnavailable }
func writeNativeKeychainItem(_, _ string, _ []byte) error { return errKeychainUnavailable }
func deleteNativeKeychainItem(_, _ string) error          { return errKeychainUnavailable }
