// Package app is the UI-independent use-case layer.
// Views call it; it does not import mygo.
package app

import (
	"koiside/internal/account"
	"koiside/internal/signing"
)

// Services are the capabilities the window can use.
type Services struct {
	Accounts account.Manager
	Signing  signing.Service
}

// New returns the desktop services backed by macOS Keychain + Apple Developer Portal.
func New() Services {
	return Services{
		Accounts: account.NewLocalManager(nil),
	}
}
