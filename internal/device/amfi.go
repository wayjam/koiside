package device

import (
	"fmt"
)

const amfiLockdownService = "com.apple.amfi.lockdown"

// GetDeveloperModeStatus queries iOS AMFI over lockdown to check whether Developer Mode is enabled.
func (s *Session) GetDeveloperModeStatus() (bool, error) {
	conn, err := s.StartService(amfiLockdownService)
	if err != nil {
		return false, fmt.Errorf("device: start %s: %w", amfiLockdownService, err)
	}
	defer conn.Close()

	if err := writePlistFrame(conn, map[string]any{"action": 3}); err != nil {
		return false, err
	}
	reply, err := readPlistFrame(conn)
	if err != nil {
		return false, err
	}
	if ok, _ := reply["success"].(bool); !ok {
		return false, fmt.Errorf("device: amfi developer mode status failed: %v", reply["Error"])
	}
	enabled, has := reply["status"].(bool)
	if !has {
		return false, fmt.Errorf("device: amfi developer mode response missing status")
	}
	return enabled, nil
}

// RevealDeveloperMode reveals the Developer Mode toggle in iPhone Settings -> Privacy & Security.
func (s *Session) RevealDeveloperMode() error {
	conn, err := s.StartService(amfiLockdownService)
	if err != nil {
		return fmt.Errorf("device: start %s: %w", amfiLockdownService, err)
	}
	defer conn.Close()

	if err := writePlistFrame(conn, map[string]any{"action": 0}); err != nil {
		return err
	}
	reply, err := readPlistFrame(conn)
	if err != nil {
		return err
	}
	if ok, _ := reply["success"].(bool); !ok {
		return fmt.Errorf("device: reveal developer mode failed: %v", reply["Error"])
	}
	return nil
}

// EnableDeveloperMode requests enabling Developer Mode on iOS (usually prompts reboot on iPhone).
func (s *Session) EnableDeveloperMode() error {
	conn, err := s.StartService(amfiLockdownService)
	if err != nil {
		return fmt.Errorf("device: start %s: %w", amfiLockdownService, err)
	}
	defer conn.Close()

	if err := writePlistFrame(conn, map[string]any{"action": 1}); err != nil {
		return err
	}
	reply, err := readPlistFrame(conn)
	if err != nil {
		return err
	}
	if ok, _ := reply["success"].(bool); !ok {
		return fmt.Errorf("device: enable developer mode failed: %v", reply["Error"])
	}
	return nil
}

// TrustAppSigner asks AMFI to trust the provisioning profile UUID (best-effort; newer iOS may still require Settings confirmation).
func (s *Session) TrustAppSigner(profileUUID string) (bool, error) {
	if profileUUID == "" {
		return false, fmt.Errorf("device: empty provisioning profile UUID")
	}
	conn, err := s.StartService(amfiLockdownService)
	if err != nil {
		return false, fmt.Errorf("device: start %s: %w", amfiLockdownService, err)
	}
	defer conn.Close()

	if err := writePlistFrame(conn, map[string]any{
		"action":             4,
		"input_profile_uuid": profileUUID,
	}); err != nil {
		return false, err
	}
	reply, err := readPlistFrame(conn)
	if err != nil {
		return false, err
	}
	if ok, _ := reply["success"].(bool); !ok {
		return false, fmt.Errorf("device: trust app signer failed: %v", reply["Error"])
	}
	trusted, _ := reply["status"].(bool)
	return trusted, nil
}
